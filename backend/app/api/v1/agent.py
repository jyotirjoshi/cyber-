"""Agent conversation endpoints: the read surface and the message-append (FR-005, FR-032, SEC-002, SEC-003).

The agent is driven from two places, and it matters which is which. *Scanning* work starts at
``POST /assessments`` -- that is where the FR-006 target attestation is supplied and where a worker
run is seeded (:mod:`app.api.v1.assessments`). The one human interaction *inside* a live run is the
approval gate (:mod:`app.api.v1.approvals`), whose row is authority, not notification (FR-011). This
module is neither: it is the conversation surface -- list and read sessions, read a run's step
timeline, replay the event backlog, and append a human turn to a conversation.

WHY ``POST /agent/messages`` does not start a run: the worker only drives assessment runs. Its
``_run_identity`` refuses any run whose ``assessment_id``/``session_id`` is null, there is no chat
graph, and creating a *scanning* assessment requires the FR-006 attestation this endpoint's payload
does not carry. So seeding a run here would enqueue something the worker rejects. Instead the turn is
persisted, its activity counters bumped, and an ``AGENT_MESSAGE`` event broadcast so every connected
client renders it from one source of truth -- the same shape the worker publishes for assistant turns.
This is honest (no fabricated execution), respects FR-006, and is forward-compatible with a chat graph.

WHY the append reloads before projecting: ``AgentMessage`` timestamps are ``server_default`` columns
with no client-side default (:class:`app.db.base.TimestampMixin`). A freshly-inserted row's
``created_at`` is *expired* after flush, so reading it on the async session during projection would
trigger implicit IO -- a ``MissingGreenlet`` crash. The row is re-read after the commit, which
repopulates every column. WHY the sequence retry: ``(session_id, seq)`` is unique, and the worker may
be appending assistant turns to the same conversation concurrently; on a collision we recompute the
next sequence and retry rather than surfacing a 500. WHY the event replay is tenant-gated first: the
Redis buffer is keyed only by ``session_id``, so a caller must be proven to own the session before we
read it (SEC-003). WHY the broadcast is guarded and best-effort: the turn is already committed and
returned; a Redis hiccup on fan-out must never turn a saved message into a 500 the client retries into
a duplicate. No endpoint here echoes untrusted content back into a prompt or a log (SEC-002).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Query, status
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    DbSession,
    EventBusDep,
    GatewayDep,
    PaginationDep,
    PrincipalDep,
    RedisDep,
    SettingsDep,
)
from app.core.errors import ConflictError, CynuxError, ModelUnavailableError
from app.db.enums import MessageRole, Permission
from app.db.models.agent import AgentAction, AgentMessage, AgentRun, AgentSession
from app.db.models.assessment import Assessment
from app.db.repository import TenantRepository, tenant_select
from app.schemas.agent import (
    AgentActionOut,
    AgentActionProposeIn,
    AgentActionResolveIn,
    AgentEvent,
    AgentMessageIn,
    AgentMessageOut,
    AgentRunOut,
    AgentSessionDetailOut,
    AgentSessionOut,
    AssessmentWorkOut,
)
from app.schemas.common import Page
from app.services import agent_action as agent_action_service
from app.services import audit as audit_service
from app.services.agent_chat import create_reply, load_assessment_run_details
from app.services.agent_chat_actions import propose_chat_actions
from app.services.context import Principal
from app.services.events import EventEmitter

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

_TITLE_MAX_CHARS = 80
_MAX_SEQ_RETRIES = 3


@router.get("/actions", response_model=list[AgentActionOut])
async def list_agent_actions(
    principal: PrincipalDep,
    session: DbSession,
    session_id: uuid.UUID | None = None,
) -> list[AgentActionOut]:
    """Pending and resolved agent actions for one organization; no provider call is made."""
    principal.require(Permission.AGENT_CHAT)
    stmt = (
        tenant_select(AgentAction, principal.organization_id)
        .order_by(AgentAction.created_at.desc(), AgentAction.id.desc())
        .limit(100)
    )
    if session_id is not None:
        await TenantRepository(session, AgentSession, principal.organization_id).get_or_404(
            session_id
        )
        stmt = stmt.where(AgentAction.session_id == session_id)
    rows = (await session.execute(stmt)).scalars().all()
    details = await load_assessment_run_details(
        session,
        principal,
        [row.run_id for row in rows if row.action == "start_assessment" and row.run_id],
    )
    output = []
    for row in rows:
        action = AgentActionOut.model_validate(row)
        if row.action == "start_assessment" and row.run_id in details:
            detail = details[row.run_id]
            assessment = detail.get("assessment")
            action = action.model_copy(
                update={
                    "run_status": detail.get("run_status"),
                    "assessment": (
                        AssessmentWorkOut.model_validate(assessment)
                        if isinstance(assessment, dict)
                        else None
                    ),
                }
            )
        output.append(action)
    return output


@router.post("/actions", response_model=AgentActionOut, status_code=status.HTTP_201_CREATED)
async def propose_agent_action(
    payload: AgentActionProposeIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AgentActionOut:
    """Queue exactly one external operation for a human decision; it does not execute it."""
    action = await agent_action_service.propose_action(
        session,
        principal,
        session_id=payload.session_id,
        action=payload.action,
        label=payload.label,
        rationale=payload.rationale,
        payload=payload.payload,
    )
    await session.commit()
    return AgentActionOut.model_validate(action)


@router.post("/actions/{action_id}/resolve", response_model=AgentActionOut)
async def resolve_agent_action(
    action_id: uuid.UUID,
    payload: AgentActionResolveIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AgentActionOut:
    """Approve or reject one exact action. Approval is not reusable for another action."""
    action = await agent_action_service.resolve_action(
        session, principal, action_id, approve=payload.approve, note=payload.note
    )
    await session.commit()
    return AgentActionOut.model_validate(action)


@router.post("/actions/{action_id}/execute", response_model=AgentActionOut)
async def execute_agent_action(
    action_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> AgentActionOut:
    """Run one approved action once, with a tenant-scoped row lock and exact-payload check."""
    principal.require(Permission.AGENT_CHAT)
    action = (
        await session.execute(
            tenant_select(AgentAction, principal.organization_id)
            .where(AgentAction.id == action_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if action is None:
        action = await TenantRepository(session, AgentAction, principal.organization_id).get_or_404(
            action_id
        )
    if action.status in {"executed", "failed"}:
        # A background worker can settle the row while the approving browser waits
        # for this lock. Return its result without invoking the provider twice.
        agent_action_service.require_action_permission(principal, action.action)
        return AgentActionOut.model_validate(action)
    result = await agent_action_service.execute_and_settle_action(
        session, principal, action, settings=settings, redis=redis
    )
    await session.commit()
    return AgentActionOut.model_validate(result)


@router.get("/sessions", response_model=Page[AgentSessionOut])
async def list_sessions(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    include_archived: Annotated[bool, Query()] = False,
) -> Page[AgentSessionOut]:
    """A page of the organization's conversations, most recently active first (FR-005).

    Archived conversations are hidden unless ``include_archived`` is set. The projection reads only
    scalar columns, so no relationship is loaded for the list view.
    """
    principal.require(Permission.AGENT_CHAT)
    rows_stmt = tenant_select(AgentSession, principal.organization_id)
    count_stmt = (
        select(func.count())
        .select_from(AgentSession)
        .where(AgentSession.organization_id == principal.organization_id)
    )
    if not include_archived:
        rows_stmt = rows_stmt.where(AgentSession.is_archived.is_(False))
        count_stmt = count_stmt.where(AgentSession.is_archived.is_(False))

    total = int((await session.execute(count_stmt)).scalar_one())
    rows_stmt = (
        rows_stmt.order_by(
            AgentSession.last_activity_at.desc().nulls_last(),
            AgentSession.created_at.desc(),
        )
        .limit(pagination.limit)
        .offset(pagination.offset)
    )
    rows = (await session.execute(rows_stmt)).scalars().all()
    items = [AgentSessionOut.model_validate(row) for row in rows]
    return Page.build(items, total=total, limit=pagination.limit, offset=pagination.offset)


@router.get("/sessions/{session_id}", response_model=AgentSessionDetailOut)
async def get_session(
    session_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AgentSessionDetailOut:
    """One conversation with its full transcript and run timelines (FR-005).

    Messages, runs and each run's steps are eager-loaded because the projection walks all three;
    a ``raise_on_sql`` relationship left unloaded would raise inside the synchronous serializer.
    A session id from another organization is a 404 (tenant isolation), never a 403 (SEC-003).
    """
    principal.require(Permission.AGENT_CHAT)
    repo = TenantRepository(session, AgentSession, principal.organization_id)
    convo = await repo.get_or_404(
        session_id,
        selectinload(AgentSession.messages),
        selectinload(AgentSession.runs).selectinload(AgentRun.steps),
    )
    return AgentSessionDetailOut.model_validate(convo)


@router.get("/sessions/{session_id}/events", response_model=list[AgentEvent])
async def list_session_events(
    session_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    event_bus: EventBusDep,
    after_seq: Annotated[int, Query(ge=0)] = 0,
) -> list[AgentEvent]:
    """Replay the recent event backlog for a session, oldest first (FR-005).

    This is the HTTP counterpart to the websocket at ``/ws/agent/{session_id}``: a client that
    cannot hold a socket, or one reconnecting, passes the highest ``seq`` it has rendered and gets
    back only what it missed. The session is tenant-checked *before* Redis is touched, because the
    replay buffer is keyed by session id alone (SEC-003).
    """
    principal.require(Permission.AGENT_CHAT)
    repo = TenantRepository(session, AgentSession, principal.organization_id)
    await repo.get_or_404(session_id)
    return await event_bus.replay(session_id, after_seq=after_seq)


@router.get("/runs/{run_id}", response_model=AgentRunOut)
async def get_run(
    run_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AgentRunOut:
    """One run with its ordered step timeline (FR-005).

    Steps are eager-loaded for the projection. A run id from another organization is a 404.
    """
    principal.require(Permission.AGENT_CHAT)
    repo = TenantRepository(session, AgentRun, principal.organization_id)
    run = await repo.get_or_404(run_id, selectinload(AgentRun.steps))
    return AgentRunOut.model_validate(run)


@router.post(
    "/messages",
    response_model=AgentMessageOut,
    status_code=status.HTTP_201_CREATED,
)
async def post_message(
    payload: AgentMessageIn,
    principal: PrincipalDep,
    session: DbSession,
    event_bus: EventBusDep,
    gateway: GatewayDep,
    settings: SettingsDep,
) -> AgentMessageOut:
    """Append a human turn to a conversation and broadcast it (FR-005, FR-032).

    Creates the conversation when ``session_id`` is omitted. This does **not** start a scanning run
    -- see the module docstring for why -- it persists the turn, audits it, and fans it out as an
    ``AGENT_MESSAGE`` event. The optional ``assessment_id`` is tenant-checked so a broadcast can
    never reference another organization's assessment; it is not stored on the message row.
    """
    principal.require(Permission.AGENT_CHAT)
    org_id = principal.organization_id
    now = datetime.now(UTC)

    if payload.assessment_id is not None:
        await TenantRepository(session, Assessment, org_id).get_or_404(payload.assessment_id)

    message_id: uuid.UUID | None = None
    convo_id: uuid.UUID | None = None
    for attempt in range(_MAX_SEQ_RETRIES):
        convo, created = await _resolve_conversation(session, principal, payload)
        seq = await _next_message_seq(session, convo.id)
        message = AgentMessage(
            id=uuid.uuid4(),
            organization_id=org_id,
            session_id=convo.id,
            seq=seq,
            role=MessageRole.USER.value,
            content=payload.content,
        )
        session.add(message)
        try:
            await session.flush()
        except IntegrityError:
            # A concurrent writer (the worker appending an assistant turn) took this seq.
            # Recompute and retry rather than surfacing a 500; nothing is committed yet.
            await session.rollback()
            log.warning("agent_message_seq_conflict", attempt=attempt)
            continue

        convo.message_count = 1 if created else convo.message_count + 1
        convo.last_activity_at = now
        if created:
            await audit_service.record(
                session,
                action=audit_service.AuditAction.AGENT_SESSION_CREATE,
                principal=principal,
                resource_type="agent_session",
                resource_id=convo.id,
            )
        await audit_service.record(
            session,
            action=audit_service.AuditAction.AGENT_MESSAGE,
            principal=principal,
            resource_type="agent_session",
            resource_id=convo.id,
            detail={"seq": seq},
        )
        await session.commit()
        message_id, convo_id = message.id, convo.id
        break

    if message_id is None or convo_id is None:
        raise ConflictError(
            "The conversation was updated concurrently. Please resend your message."
        )

    # Reload after commit: the server_default timestamps are expired on the just-inserted row,
    # and projecting them on the async session would trigger implicit IO (see module docstring).
    reloaded = (
        await session.execute(
            tenant_select(AgentMessage, org_id).where(AgentMessage.id == message_id)
        )
    ).scalar_one()
    message_out = AgentMessageOut.model_validate(reloaded)

    # Fan-out is best-effort: the turn is committed and about to be returned. ``next_seq`` is not
    # guarded against a Redis outage, so a hiccup here must not become a post-commit 500 the client
    # would retry into a duplicate turn. A reconnecting client recovers the turn via replay.
    emitter = EventEmitter(event_bus, session_id=convo_id, assessment_id=payload.assessment_id)
    try:
        await emitter.message(message_out)
    except RedisError:
        log.warning("agent_message_broadcast_failed", session_id=str(convo_id))

    # Chat is intentionally synchronous: it is a short model completion, not an assessment run.
    # The reply is committed before this request resolves, so a reload cannot lose it and normal
    # guidance does not depend on the assessment worker.
    try:
        try:
            await emitter.thinking("Checking the request and preparing a response…", node="chat")
        except RedisError:
            log.warning("agent_chat_thinking_broadcast_failed", session_id=str(convo_id))

        action_outcomes = await propose_chat_actions(
            session,
            principal,
            session_id=convo_id,
            question=payload.content,
            gateway=gateway,
            settings=settings,
        )
        if action_outcomes:
            await session.commit()

        assistant = await create_reply(
            session,
            organization_id=org_id,
            conversation_id=convo_id,
            gateway=gateway,
            principal=principal,
            action_result=json.dumps(action_outcomes, separators=(",", ":"))
            if action_outcomes
            else None,
        )
        assistant_out = AgentMessageOut.model_validate(assistant)
        try:
            await emitter.message(assistant_out)
            await emitter.complete()
        except RedisError:
            log.warning("agent_chat_reply_broadcast_failed", session_id=str(convo_id))
    except CynuxError as exc:
        log.info("agent_chat_reply_unavailable", session_id=str(convo_id), error_code=exc.code)
        try:
            await emitter.error(exc)
        except RedisError:
            log.warning("agent_chat_error_broadcast_failed", session_id=str(convo_id))
    except Exception as exc:  # pragma: no cover - defensive boundary around third-party SDKs
        log.exception("agent_chat_reply_failed", session_id=str(convo_id))
        try:
            await emitter.error(ModelUnavailableError("Chat completion failed", cause=exc))
        except RedisError:
            log.warning("agent_chat_error_broadcast_failed", session_id=str(convo_id))

    return message_out


async def _resolve_conversation(
    session: AsyncSession, principal: Principal, payload: AgentMessageIn
) -> tuple[AgentSession, bool]:
    """Return the target conversation and whether it was created for this turn.

    A new conversation is flushed so its id is available for the message's foreign key. An existing
    one is loaded tenant-scoped -- a session id from another organization is a 404, not a 403.
    """
    if payload.session_id is None:
        convo = AgentSession(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            user_id=principal.user_id,
            title=_derive_title(payload.content),
        )
        session.add(convo)
        await session.flush()
        return convo, True
    repo = TenantRepository(session, AgentSession, principal.organization_id)
    convo = await repo.get_or_404(payload.session_id)
    return convo, False


async def _next_message_seq(session: AsyncSession, session_id: uuid.UUID) -> int:
    """The next per-conversation message sequence: ``max(seq) + 1`` (``0`` for an empty conversation).

    Whatever the concurrent worker's strategy, ``max + 1`` always yields an unused sequence at query
    time; a lost race surfaces as the unique-constraint violation the caller retries on.
    """
    stmt = select(func.coalesce(func.max(AgentMessage.seq), -1) + 1).where(
        AgentMessage.session_id == session_id
    )
    return int((await session.execute(stmt)).scalar_one())


def _derive_title(content: str) -> str:
    """A short conversation title from the first line of the opening message."""
    stripped = content.strip()
    if not stripped:
        return "New conversation"
    first_line = stripped.splitlines()[0].strip()
    return first_line[:_TITLE_MAX_CHARS] or "New conversation"


__all__ = ["router"]
