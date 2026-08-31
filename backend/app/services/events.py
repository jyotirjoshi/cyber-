"""Agent event fan-out over Redis (FR-038, PRD §8, §53).

The graph runs in a **worker** process; the WebSocket is held by an **API** process.
Nothing in that arrangement lets the two share memory, so every server-to-client push
goes through Redis pub/sub keyed on the session.  Any API replica can then serve any
socket, and a worker publishing an event does not need to know which replica is
listening -- or whether one is at all.

Three properties are load-bearing.

**``seq`` is monotonic per session**, allocated by ``INCR`` rather than by the publisher.
Two nodes emitting concurrently would otherwise both compute "the next one" and produce
a duplicate, and a client that de-duplicates on ``seq`` would silently drop the second
event.

**Recent events are replayed on subscribe.**  Pub/sub has no history: an event published
in the millisecond between a page load and the socket handshake is gone forever.  For
``agent_thinking`` that is cosmetic.  For ``agent_approval_required`` it is not -- that
event is the *only* thing telling the operator a run is paused waiting on them, and
losing it strands the assessment at the approval interrupt (FR-011) with a UI showing
nothing to do.  So :meth:`EventBus.publish` also appends to a capped list, and
:meth:`EventBus.subscribe` drains it before relaying live traffic.

**Publishing never fails a run.**  Emitting progress is observability, not work; a Redis
blip must not abort an assessment that is otherwise proceeding.  :meth:`EventBus.publish`
logs and returns.  The one thing it does *not* do is swallow the error silently, because
a socket that has stopped delivering looks identical to an agent that has stopped
working.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import Any, Literal, cast

import structlog
from pydantic import BaseModel, ValidationError
from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.core.config import Settings
from app.core.errors import CynuxError
from app.db.enums import AssessmentStage, AssessmentStatus, RiskLevel, StepStatus
from app.schemas.agent import (
    AgentEvent,
    AgentEventType,
    AgentMessageOut,
    CompleteData,
    ErrorData,
    FindingsUpdateData,
    PlanStepData,
    ProgressData,
    ThinkingData,
    ToolCallData,
)
from app.schemas.assessment import ApprovalOut, StageOut

log = structlog.get_logger(__name__)

#: How many recent events stay replayable per session. Twenty is a full run's worth of
#: stage transitions -- enough that a reconnect inside one node's execution recovers
#: everything it missed -- without turning Redis into the event store.
REPLAY_LIMIT = 20

#: Replay buffers outlive a disconnect but not an engagement. A run can sit at the
#: approval interrupt for ``agent.approval_ttl_hours`` (72 by default), so this must
#: exceed that: the buffer is what lets a reconnected browser rediscover the pending
#: approval rather than show an idle-looking run.
REPLAY_TTL_SECONDS = 4 * 24 * 3600

#: Sequence counters expire on the same clock. A session whose counter has expired
#: restarts at 1, which a client reads as a gap and refetches -- the correct outcome for
#: a session nobody has touched in four days.
SEQ_TTL_SECONDS = REPLAY_TTL_SECONDS

#: Guard on a single event's serialized size. ``data`` is built from typed payloads, so
#: this is a backstop against a caller inlining a tool result rather than a summary
#: (SEC-006). Exceeding it drops the *payload*, not the event: the client still learns
#: that something happened at that ``seq``.
MAX_EVENT_BYTES = 64 * 1024

#: Bounded so :meth:`EventBus.subscribe` stays promptly cancellable. An ``await`` with no
#: timeout is not interrupted quickly when the client disconnects, and the task would
#: linger holding a pooled connection.
_POLL_TIMEOUT_SECONDS = 1.0


def channel_for(settings: Settings, session_id: uuid.UUID) -> str:
    """The pub/sub channel one agent session's events travel on."""
    return f"{settings.redis.event_channel_prefix}:session:{session_id}"


def _replay_key(settings: Settings, session_id: uuid.UUID) -> str:
    return f"{settings.redis.event_channel_prefix}:replay:{session_id}"


def _seq_key(settings: Settings, session_id: uuid.UUID) -> str:
    return f"{settings.redis.event_channel_prefix}:seq:{session_id}"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class EventBus:
    """Publish/subscribe for :class:`~app.schemas.agent.AgentEvent`."""

    def __init__(self, redis: Redis, settings: Settings) -> None:
        self._r = redis
        self._settings = settings

    # -- sequencing ----------------------------------------------------------

    async def next_seq(self, session_id: uuid.UUID) -> int:
        """Allocate the next per-session sequence number.

        ``INCR`` rather than "read the last one and add one": the graph publishes from
        several places, and a read-modify-write would hand the same number to two events
        under concurrency.  A client de-duplicating on ``seq`` would then drop one of
        them -- and the one it drops could be the approval request.

        Best-effort for the same reason :meth:`publish` is (see the module docstring): this
        runs on the emit path, so a Redis blip while allocating a sequence must not abort an
        otherwise-healthy run (FR-040).  On failure it logs and returns ``0`` -- the same
        "not part of the stream" sentinel :func:`pong_event` uses -- and the ``publish`` that
        follows best-effort-fails too, so nothing is delivered and the run carries on.
        """
        key = _seq_key(self._settings, session_id)
        try:
            pipe = self._r.pipeline()
            pipe.incr(key)
            pipe.expire(key, SEQ_TTL_SECONDS)
            seq, _ = await pipe.execute()
        except RedisError as exc:
            log.warning("event.seq_failed", session_id=str(session_id), error=type(exc).__name__)
            return 0
        return int(seq)

    # -- publish -------------------------------------------------------------

    async def publish(self, event: AgentEvent) -> None:
        """Fan an event out to subscribers and add it to the replay buffer.

        Best-effort by design: see the module docstring.  A failure is logged at WARNING
        with the event type and session, which is what makes "the socket went quiet"
        diagnosable rather than mysterious.
        """
        payload = event.model_dump_json()
        if len(payload) > MAX_EVENT_BYTES:
            # Almost certainly a caller that inlined a tool result instead of summarizing
            # it. Stripping ``data`` keeps the sequence intact so the client does not read
            # a gap, and logs loudly enough that the offending emitter gets fixed.
            log.warning(
                "event.oversized",
                event_type=event.type.value,
                session_id=str(event.session_id),
                size_bytes=len(payload),
            )
            event = event.model_copy(update={"data": {"_omitted": "payload too large"}})
            payload = event.model_dump_json()

        channel = channel_for(self._settings, event.session_id)
        replay = _replay_key(self._settings, event.session_id)
        try:
            pipe = self._r.pipeline()
            pipe.publish(channel, payload)
            # Appended *and* published in one round trip. Doing the two separately opens a
            # window where a subscriber sees a live event that is not yet replayable, so a
            # reconnect a moment later would miss it.
            pipe.rpush(replay, payload)
            pipe.ltrim(replay, -REPLAY_LIMIT, -1)
            pipe.expire(replay, REPLAY_TTL_SECONDS)
            await pipe.execute()
        except RedisError as exc:
            log.warning(
                "event.publish_failed",
                event_type=event.type.value,
                session_id=str(event.session_id),
                seq=event.seq,
                error=type(exc).__name__,
            )

    # -- subscribe -----------------------------------------------------------

    async def replay(self, session_id: uuid.UUID, *, after_seq: int = 0) -> list[AgentEvent]:
        """Recent events for a session, oldest first, excluding those already seen.

        A reconnecting client passes the highest ``seq`` it rendered and gets back only
        what it missed.  A client with no state passes ``0`` and gets the whole buffer,
        which is how a freshly opened tab discovers a run that is already mid-flight.
        """
        try:
            # ``cast`` because redis-py annotates each command once for both clients, as
            # ``Awaitable[T] | T`` -- mypy rightly refuses to ``await`` that union. On
            # ``redis.asyncio`` the runtime value is always the awaitable half, and the pool
            # is built with ``decode_responses=True``, so these come back as ``str``.
            raw = await cast(
                Awaitable[list[str]], self._r.lrange(_replay_key(self._settings, session_id), 0, -1)
            )
        except RedisError as exc:
            log.warning("event.replay_failed", session_id=str(session_id), error=type(exc).__name__)
            return []
        events = [e for e in (_parse(item) for item in raw) if e is not None]
        return [e for e in events if e.seq > after_seq]

    async def subscribe(
        self, session_id: uuid.UUID, *, after_seq: int = 0
    ) -> AsyncIterator[AgentEvent]:
        """Yield the missed backlog, then live events, until the caller stops iterating.

        The subscription is established *before* the backlog is read, which is the only
        ordering that cannot lose an event: the reverse leaves a gap between "finished
        reading history" and "started listening".  The cost is that an event may arrive
        both ways, so ``seq`` is tracked and repeats are dropped -- de-duplicating is
        cheap, and losing the approval request is not.
        """
        pubsub = self._r.pubsub(ignore_subscribe_messages=True)
        await pubsub.subscribe(channel_for(self._settings, session_id))
        highest = after_seq
        try:
            for event in await self.replay(session_id, after_seq=after_seq):
                highest = max(highest, event.seq)
                yield event

            while True:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=_POLL_TIMEOUT_SECONDS
                )
                if message is None:
                    continue
                live = _parse(message.get("data"))
                if live is None or live.seq <= highest:
                    continue
                highest = live.seq
                yield live
        finally:
            # Runs on cancellation too -- which is the normal exit, since the caller is a
            # WebSocket handler whose task is cancelled when the client disconnects.
            # Without it the connection leaks back to a pool with a hard cap.
            try:
                await pubsub.aclose()
            except RedisError as exc:
                # Worth a line rather than a bare suppress: a consistently failing close
                # means connections are reclaimed by timeout instead of returned, which
                # surfaces much later as pool exhaustion.
                log.debug("event.unsubscribe_failed", error=type(exc).__name__)


def _parse(raw: object) -> AgentEvent | None:
    """Decode one channel payload, tolerating anything that is not a valid event.

    A malformed frame must not end the subscription: the channel carries every event for
    a session, so one bad payload would otherwise take down a live run's whole stream.
    It is logged and skipped.
    """
    if not isinstance(raw, str | bytes | bytearray):
        return None
    try:
        return AgentEvent.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        log.warning("event.undecodable", error=type(exc).__name__)
        return None


# ---------------------------------------------------------------------------
# Typed emitters
# ---------------------------------------------------------------------------


def _as_data(payload: BaseModel) -> dict[str, Any]:
    """Payload model to JSON-safe dict.

    ``mode="json"`` is required, not stylistic: ``data`` is serialized as part of the
    envelope, and a raw ``UUID`` or ``datetime`` nested inside a plain dict makes
    ``model_dump_json`` fail at publish time -- inside the emitter of an event nobody is
    waiting on, so the failure surfaces as silence.
    """
    return payload.model_dump(mode="json")


class EventEmitter:
    """An :class:`EventBus` bound to one session, run and assessment.

    Graph nodes hold this rather than the bus.  Three reasons, in order of how much they
    matter: a node cannot mislabel an event with another session's id; ``seq`` allocation
    and envelope construction happen in one place; and the methods below are *typed*, so
    the SEC-002 rule that a tool call publishes a summary and never its arguments is
    enforced by the signature instead of by everyone remembering it.
    """

    def __init__(
        self,
        bus: EventBus,
        *,
        session_id: uuid.UUID,
        assessment_id: uuid.UUID | None = None,
        run_id: uuid.UUID | None = None,
    ) -> None:
        self._bus = bus
        self.session_id = session_id
        self.assessment_id = assessment_id
        self.run_id = run_id

    def bind(
        self,
        *,
        assessment_id: uuid.UUID | None = None,
        run_id: uuid.UUID | None = None,
    ) -> EventEmitter:
        """A copy with the assessment or run attached.

        The session exists before the assessment does -- the operator is chatting first --
        so the emitter starts without one and gains it when the create node runs.
        """
        return EventEmitter(
            self._bus,
            session_id=self.session_id,
            assessment_id=assessment_id if assessment_id is not None else self.assessment_id,
            run_id=run_id if run_id is not None else self.run_id,
        )

    async def emit(self, event_type: AgentEventType, payload: BaseModel | None = None) -> None:
        event = AgentEvent(
            type=event_type,
            session_id=self.session_id,
            assessment_id=self.assessment_id,
            run_id=self.run_id,
            seq=await self._bus.next_seq(self.session_id),
            at=_now(),
            data=_as_data(payload) if payload is not None else {},
        )
        await self._bus.publish(event)

    # -- one method per event type -------------------------------------------

    async def thinking(self, text: str, *, node: str | None = None) -> None:
        """Narration of what the agent is doing.

        Deliberately not raw chain-of-thought: the text is composed by the node, not
        lifted from the model's reasoning, so it cannot echo back a prompt that included
        untrusted scanner output (SEC-005).
        """
        await self.emit(AgentEventType.AGENT_THINKING, ThinkingData(text=text, node=node))

    async def plan_step(
        self,
        *,
        step_index: int,
        total_steps: int,
        title: str,
        status: StepStatus,
        stage: AssessmentStage | None = None,
        detail: str | None = None,
    ) -> None:
        await self.emit(
            AgentEventType.AGENT_PLAN_STEP,
            PlanStepData(
                step_index=step_index,
                total_steps=total_steps,
                stage=stage,
                title=title,
                status=status,
                detail=detail,
            ),
        )

    async def tool_call(
        self,
        *,
        tool: str,
        status: Literal["started", "succeeded", "failed"],
        summary: str | None = None,
        risk_level: RiskLevel | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """Report a tool invocation as a *summary*.

        There is no parameter for arguments, and that is the point.  Scanner argv carries
        target hostnames; integration calls carry tokens.  A signature with nowhere to put
        them cannot be misused into putting them on a socket (SEC-002, SEC-006).
        """
        await self.emit(
            AgentEventType.AGENT_TOOL_CALL,
            ToolCallData(
                tool=tool,
                status=status,
                risk_level=risk_level,
                summary=summary,
                duration_ms=duration_ms,
            ),
        )

    async def approval_required(self, approval: ApprovalOut) -> None:
        """The one event whose loss blocks a run.

        Takes the wire type rather than the ORM row: an ORM object here would either lazy
        -load under ``raise_on_sql`` or publish columns ``ApprovalOut`` deliberately omits.
        """
        await self.emit(AgentEventType.AGENT_APPROVAL_REQUIRED, approval)

    async def findings_update(
        self,
        *,
        assessment_id: uuid.UUID,
        total: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        info: int = 0,
        new_since_last: int = 0,
    ) -> None:
        await self.emit(
            AgentEventType.AGENT_FINDINGS_UPDATE,
            FindingsUpdateData(
                assessment_id=assessment_id,
                total=total,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                info=info,
                new_since_last=new_since_last,
            ),
        )

    async def error(self, error: CynuxError, *, stage: AssessmentStage | None = None) -> None:
        """Publish a failure from the error taxonomy.

        Built from :attr:`CynuxError.user_message`, never ``str(error)``.  The internal
        message may quote a provider response or name an internal host, and this envelope
        goes straight to a browser (SEC-002).
        """
        await self.emit(
            AgentEventType.AGENT_ERROR,
            ErrorData(
                code=error.code,
                category=error.category.value,
                user_message=error.user_message,
                retryable=error.retryable,
                degradable=error.degradable,
                stage=stage,
            ),
        )

    async def complete(
        self,
        *,
        assessment_id: uuid.UUID | None = None,
        status: AssessmentStatus | None = None,
        findings_total: int = 0,
        report_id: uuid.UUID | None = None,
        duration_seconds: int | None = None,
    ) -> None:
        await self.emit(
            AgentEventType.AGENT_COMPLETE,
            CompleteData(
                assessment_id=assessment_id,
                status=status,
                findings_total=findings_total,
                report_id=report_id,
                duration_seconds=duration_seconds,
            ),
        )

    async def message(self, message: AgentMessageOut) -> None:
        """An assistant turn, as it will appear in the conversation history."""
        await self.emit(AgentEventType.AGENT_MESSAGE, message)

    async def progress(
        self,
        *,
        stage: AssessmentStage,
        progress_percent: int,
        stages: list[StageOut] | None = None,
    ) -> None:
        await self.emit(
            AgentEventType.AGENT_PROGRESS,
            ProgressData(stage=stage, progress_percent=progress_percent, stages=stages or []),
        )


def pong_event(session_id: uuid.UUID) -> AgentEvent:
    """Keepalive reply, built without touching Redis.

    ``seq`` is ``0`` because a pong is not part of the session's event stream: allocating
    a real sequence number would make every idle client's keepalives advance the counter
    and manufacture apparent gaps for everyone else watching the session.
    """
    return AgentEvent(type=AgentEventType.PONG, session_id=session_id, seq=0, at=_now())


def event_to_frame(event: AgentEvent) -> str:
    """Serialize for the WebSocket. One place, so the wire format has one definition."""
    return event.model_dump_json()


def frame_to_event(raw: str) -> AgentEvent | None:
    """Parse a frame back into an event. Used by tests and by the worker's own relay."""
    return _parse(raw)


__all__ = [
    "MAX_EVENT_BYTES",
    "REPLAY_LIMIT",
    "REPLAY_TTL_SECONDS",
    "SEQ_TTL_SECONDS",
    "EventBus",
    "EventEmitter",
    "channel_for",
    "event_to_frame",
    "frame_to_event",
    "pong_event",
]
