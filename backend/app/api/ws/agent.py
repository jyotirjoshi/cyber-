"""Live agent event stream over a websocket (FR-005, FR-011, SEC-002, SEC-003).

A client opens ``/ws/agent/{session_id}`` to watch a conversation unfold in real time -- thinking,
plan steps, tool calls, the approval-required interrupt (FR-011), findings updates, completion. The
socket carries events *out*; it is not a command channel. Posting a turn is the audited REST call
``POST /api/v1/agent/messages``; the only frames a client sends here are ``auth`` (the opening
handshake) and ``ping`` (application keepalive), per :class:`app.schemas.agent.ClientFrame`.

WHY authentication is a first-frame token rather than a dependency: a browser cannot set an
``Authorization`` header on a websocket handshake, so the bearer token arrives in the first frame.
It is verified against a *short-lived* database session opened only for the handshake -- holding a
pooled connection for the socket's whole lifetime would exhaust the pool under many concurrent
viewers. After the handshake the stream is served purely from Redis (:class:`EventBus`), which is
cheap to hold open. WHY a single writer: the outbound event pump and the ping/pong responder would
otherwise call ``send`` on one socket concurrently, interleaving frames; both instead enqueue to one
queue drained by a lone writer. WHY opaque close codes: a failed handshake closes with a bare code
and no reason string, so nothing about why (bad token, inactive user, wrong tenant, missing
permission) leaks to the caller (SEC-002). WHY the session is tenant-checked: the Redis stream is
keyed by ``session_id`` alone, so ownership must be proven before a single event is read (SEC-003).
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from app.api.deps import DenyListDep, EventBusDep, SettingsDep
from app.core.errors import CynuxError, PermissionDeniedError
from app.db.enums import Permission
from app.db.models.agent import AgentSession
from app.db.repository import TenantRepository
from app.db.session import session_scope
from app.schemas.agent import ClientFrame
from app.services.auth import authenticate_token, resolve_principal
from app.services.context import Principal
from app.services.events import EventBus, event_to_frame, pong_event

log = structlog.get_logger(__name__)

router = APIRouter()

# Application-defined websocket close codes (the 4000-4999 range is reserved for app use). All
# handshake failures are opaque by design (SEC-002): the code distinguishes the class of failure
# for a client's own retry logic without disclosing which credential check tripped.
_WS_UNAUTHENTICATED = 4401
_WS_FORBIDDEN = 4403
_WS_NOT_FOUND = 4404

_AUTH_DEADLINE_SECONDS = 10.0
_SEND_QUEUE_MAX = 256


@router.websocket("/ws/agent/{session_id}")
async def agent_stream(
    websocket: WebSocket,
    session_id: uuid.UUID,
    settings: SettingsDep,
    deny_list: DenyListDep,
    event_bus: EventBusDep,
) -> None:
    """Stream a conversation's events live until the client disconnects (FR-005, FR-011).

    The first frame must authenticate; thereafter events flow out and ``ping`` frames are answered
    with ``pong``. A ``?after_seq=`` query parameter lets a reconnecting client resume without a gap.
    """
    await websocket.accept()
    principal = await _authenticate(websocket, session_id, settings, deny_list)
    if principal is None:
        return  # _authenticate already closed the socket with a reason code.

    after_seq = _parse_after_seq(websocket)
    log.info("agent_ws_open", session_id=str(session_id), **principal.to_log_fields())

    outbound: asyncio.Queue[str] = asyncio.Queue(maxsize=_SEND_QUEUE_MAX)
    tasks: list[asyncio.Task[None]] = [
        asyncio.create_task(_writer(websocket, outbound)),
        asyncio.create_task(_pump_events(event_bus, session_id, outbound, after_seq)),
        asyncio.create_task(_pump_client(websocket, session_id, outbound)),
    ]
    try:
        # Whichever task finishes first ends the stream: the client disconnecting, the socket
        # erroring on a send, or the subscription closing. The rest are then cancelled -- which is
        # what runs EventBus.subscribe's finally and unsubscribes the pubsub channel.
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    log.info("agent_ws_closed", session_id=str(session_id))


async def _authenticate(
    websocket: WebSocket,
    session_id: uuid.UUID,
    settings: SettingsDep,
    deny_list: DenyListDep,
) -> Principal | None:
    """Verify the opening frame's token and the caller's right to this session, or close and return None.

    Uses a short-lived database session for the handshake only. Every failure path closes with an
    opaque code and no reason string (SEC-002); a cross-tenant session id closes as not-found, never
    as forbidden (SEC-003).
    """
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=_AUTH_DEADLINE_SECONDS)
    except (TimeoutError, WebSocketDisconnect):
        await _close(websocket, _WS_UNAUTHENTICATED)
        return None

    try:
        frame = ClientFrame.model_validate_json(raw)
    except ValidationError:
        await _close(websocket, _WS_UNAUTHENTICATED)
        return None
    if frame.type != "auth" or not frame.token:
        await _close(websocket, _WS_UNAUTHENTICATED)
        return None

    try:
        async with session_scope(settings) as db:
            user, claims = await authenticate_token(db, deny_list, frame.token, settings=settings)
            principal = await resolve_principal(db, user, claims)
            principal.require(Permission.AGENT_CHAT)
            owns = await TenantRepository(db, AgentSession, principal.organization_id).exists(
                session_id
            )
        if not owns:
            await _close(websocket, _WS_NOT_FOUND)
            return None
        return principal
    except PermissionDeniedError:
        await _close(websocket, _WS_FORBIDDEN)
        return None
    except CynuxError:
        # Bad/expired token, inactive account, no membership -- one opaque code, no detail (SEC-002).
        await _close(websocket, _WS_UNAUTHENTICATED)
        return None


async def _writer(websocket: WebSocket, outbound: asyncio.Queue[str]) -> None:
    """The sole task that calls ``send`` on the socket, so frames never interleave."""
    while True:
        frame = await outbound.get()
        await websocket.send_text(frame)


async def _pump_events(
    bus: EventBus, session_id: uuid.UUID, outbound: asyncio.Queue[str], after_seq: int
) -> None:
    """Backfill the missed backlog then stream live events onto the outbound queue."""
    async for event in bus.subscribe(session_id, after_seq=after_seq):
        await outbound.put(event_to_frame(event))


async def _pump_client(
    websocket: WebSocket, session_id: uuid.UUID, outbound: asyncio.Queue[str]
) -> None:
    """Read inbound frames; answer ``ping`` with ``pong``. A disconnect raises and ends the stream.

    Malformed frames are ignored rather than tearing down the socket -- a client that sends noise
    should not lose its event stream. ``auth`` frames after the handshake are ignored.
    """
    while True:
        raw = await websocket.receive_text()
        try:
            frame = ClientFrame.model_validate_json(raw)
        except ValidationError:
            continue
        if frame.type == "ping":
            await outbound.put(event_to_frame(pong_event(session_id)))


def _parse_after_seq(websocket: WebSocket) -> int:
    """The ``after_seq`` query parameter as a non-negative int, defaulting to 0 (whole backlog)."""
    raw = websocket.query_params.get("after_seq")
    if raw is None:
        return 0
    try:
        value = int(raw)
    except ValueError:
        return 0
    return value if value >= 0 else 0


async def _close(websocket: WebSocket, code: int) -> None:
    """Close the socket, tolerating a peer that has already gone away."""
    with contextlib.suppress(RuntimeError):
        await websocket.close(code=code)


__all__ = ["router"]
