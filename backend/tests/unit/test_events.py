"""Agent event fan-out (``app/services/events.py``).

The bus sits between two processes -- a worker publishing, an API replica relaying to a
browser -- so almost none of its behaviour is observable from either side alone.  What is
tested here is what each side has to be able to assume.

**No event is lost across a reconnect.**  ``agent_approval_required`` is the one event
whose loss strands an assessment at the FR-011 interrupt with a UI showing nothing to do.
The tests exercise the backlog, the ordering of subscribe-then-drain, and the de-duplication
that ordering makes necessary.

**No sequence number is issued twice.**  A client de-duplicates on ``seq``; a duplicate
means it silently drops an event, and the one it drops could be the approval request.

**Nothing sensitive reaches the socket.**  ``tool_call`` has nowhere to put arguments and
``error`` carries ``user_message`` only (SEC-002, SEC-006).  Both are asserted against the
published frame, not against the source.

The fake Redis below implements list, counter and pub/sub semantics rather than mocking
method calls, because the properties above are about what a *subscriber* sees.  A mock
asserting "rpush was called" would pass while the buffer was empty.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import inspect
import json
import uuid
from typing import Any

import pytest
import structlog
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.db.enums import (
    ApprovalDecision,
    ApprovalKind,
    AssessmentStage,
    AssessmentStatus,
    MessageRole,
    RiskLevel,
    ScannerName,
    StepStatus,
)
from app.schemas.agent import (
    EVENT_PAYLOADS,
    AgentEvent,
    AgentEventType,
    AgentMessageOut,
)
from app.schemas.assessment import ApprovalOut, StageOut
from app.services.events import (
    MAX_EVENT_BYTES,
    REPLAY_LIMIT,
    REPLAY_TTL_SECONDS,
    SEQ_TTL_SECONDS,
    EventBus,
    EventEmitter,
    channel_for,
    event_to_frame,
    frame_to_event,
    pong_event,
)
from app.services.progress import STAGE_LABELS

NOW = dt.datetime(2026, 3, 1, 12, 0, tzinfo=dt.UTC)


# ---------------------------------------------------------------------------
# A Redis with real list, counter and pub/sub semantics
# ---------------------------------------------------------------------------


def _resolve(length: int, start: int, end: int) -> tuple[int, int]:
    """Redis range semantics: negative indices count back, ``end`` is inclusive."""
    if start < 0:
        start = max(length + start, 0)
    if end < 0:
        end = length + end
    return start, end


class FakePubSub:
    """One subscriber's mailbox. Messages are queued at publish time, as Redis does."""

    def __init__(self, redis: FakeRedis) -> None:
        self._redis = redis
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.channels: list[str] = []
        self.closed = False

    async def subscribe(self, channel: str) -> None:
        self._redis.subscribers.setdefault(channel, []).append(self)
        self.channels.append(channel)

    async def get_message(
        self, ignore_subscribe_messages: bool = False, timeout: float | None = None
    ) -> dict[str, Any] | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout)
        except TimeoutError:
            return None

    async def aclose(self) -> None:
        if self._redis.fail_on_close:
            raise RedisConnectionError("connection reset")
        self.closed = True
        for channel in self.channels:
            self._redis.subscribers.get(channel, []).remove(self)

    def deliver(self, channel: str, data: str) -> None:
        self._queue.put_nowait({"type": "message", "channel": channel, "data": data})


class FakePipeline:
    """Buffers commands and applies them on ``execute``, so a failure is all-or-nothing."""

    def __init__(self, redis: FakeRedis) -> None:
        self._redis = redis
        self.commands: list[tuple[str, tuple[Any, ...]]] = []

    def incr(self, key: str) -> FakePipeline:
        self.commands.append(("incr", (key,)))
        return self

    def expire(self, key: str, ttl: int) -> FakePipeline:
        self.commands.append(("expire", (key, ttl)))
        return self

    def publish(self, channel: str, payload: str) -> FakePipeline:
        self.commands.append(("publish", (channel, payload)))
        return self

    def rpush(self, key: str, value: str) -> FakePipeline:
        self.commands.append(("rpush", (key, value)))
        return self

    def ltrim(self, key: str, start: int, end: int) -> FakePipeline:
        self.commands.append(("ltrim", (key, start, end)))
        return self

    async def execute(self) -> list[Any]:
        self._redis.executed.append([name for name, _ in self.commands])
        if self._redis.fail_on_execute:
            raise RedisConnectionError("connection refused")
        return [getattr(self._redis, f"_do_{name}")(*args) for name, args in self.commands]


class FakeRedis:
    """Enough of Redis for :class:`EventBus`, with switches for the failure paths."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.lists: dict[str, list[str]] = {}
        self.ttls: dict[str, int] = {}
        self.subscribers: dict[str, list[FakePubSub]] = {}
        self.executed: list[list[str]] = []
        self.fail_on_execute = False
        self.fail_on_lrange = False
        self.fail_on_close = False

    # -- command implementations --------------------------------------------

    def _do_incr(self, key: str) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    def _do_expire(self, key: str, ttl: int) -> bool:
        self.ttls[key] = ttl
        return True

    def _do_publish(self, channel: str, payload: str) -> int:
        for sub in list(self.subscribers.get(channel, [])):
            sub.deliver(channel, payload)
        return len(self.subscribers.get(channel, []))

    def _do_rpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    def _do_ltrim(self, key: str, start: int, end: int) -> bool:
        items = self.lists.get(key, [])
        lo, hi = _resolve(len(items), start, end)
        self.lists[key] = items[lo : hi + 1]
        return True

    # -- client surface ------------------------------------------------------

    def pipeline(self, *_args: Any, **_kw: Any) -> FakePipeline:
        return FakePipeline(self)

    async def lrange(self, key: str, start: int, end: int) -> list[str]:
        if self.fail_on_lrange:
            raise RedisConnectionError("connection refused")
        items = self.lists.get(key, [])
        lo, hi = _resolve(len(items), start, end)
        return items[lo : hi + 1]

    def pubsub(self, **_kw: Any) -> FakePubSub:
        return FakePubSub(self)


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture
def bus(redis: FakeRedis, settings: Settings) -> EventBus:
    return EventBus(redis, settings)  # type: ignore[arg-type]


@pytest.fixture
def session_id() -> uuid.UUID:
    return uuid.UUID("11111111-1111-4111-8111-111111111111")


@pytest.fixture
def emitter(bus: EventBus, session_id: uuid.UUID) -> EventEmitter:
    return EventEmitter(
        bus,
        session_id=session_id,
        assessment_id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
        run_id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )


def _event(session_id: uuid.UUID, seq: int, **kw: Any) -> AgentEvent:
    return AgentEvent(
        type=kw.pop("type", AgentEventType.AGENT_THINKING),
        session_id=session_id,
        seq=seq,
        at=NOW,
        **kw,
    )


def _buffered(redis: FakeRedis, settings: Settings, session_id: uuid.UUID) -> list[AgentEvent]:
    key = f"{settings.redis.event_channel_prefix}:replay:{session_id}"
    return [AgentEvent.model_validate_json(raw) for raw in redis.lists.get(key, [])]


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def test_the_channel_is_namespaced_per_session(settings: Settings) -> None:
    one, two = uuid.uuid4(), uuid.uuid4()
    assert channel_for(settings, one) != channel_for(settings, two)
    assert channel_for(settings, one).startswith(settings.redis.event_channel_prefix)


async def test_seq_and_replay_keys_are_distinct(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID
) -> None:
    """A shared key would be a hard failure: ``INCR`` against a list raises WRONGTYPE."""
    await bus.publish(_event(session_id, await bus.next_seq(session_id)))
    assert len(redis.counters) == 1
    assert len(redis.lists) == 1
    assert set(redis.counters).isdisjoint(redis.lists)


# ---------------------------------------------------------------------------
# Sequencing
# ---------------------------------------------------------------------------


async def test_seq_starts_at_one_and_increments(bus: EventBus, session_id: uuid.UUID) -> None:
    assert [await bus.next_seq(session_id) for _ in range(3)] == [1, 2, 3]


async def test_seq_is_independent_per_session(bus: EventBus) -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    assert await bus.next_seq(a) == 1
    assert await bus.next_seq(a) == 2
    assert await bus.next_seq(b) == 1


async def test_concurrent_allocation_never_repeats_a_seq(
    bus: EventBus, session_id: uuid.UUID
) -> None:
    """The reason allocation is ``INCR`` and not read-modify-write.

    Several nodes emit at once; a duplicate here means a client de-duplicating on ``seq``
    drops a real event.
    """
    seqs = await asyncio.gather(*(bus.next_seq(session_id) for _ in range(25)))
    assert sorted(seqs) == list(range(1, 26))


async def test_the_counter_gets_a_ttl(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    await bus.next_seq(session_id)
    key = f"{settings.redis.event_channel_prefix}:seq:{session_id}"
    assert redis.ttls[key] == SEQ_TTL_SECONDS


def test_retention_outlives_the_approval_window(settings: Settings) -> None:
    """A run can sit at the interrupt for ``agent.approval_ttl_hours``.

    If the buffer expired first, a browser opened on the second day of a pending approval
    would rediscover nothing and the run would look idle rather than blocked -- so the
    relationship between these two settings is asserted, not just commented.
    """
    approval_window = settings.agent.approval_ttl_hours * 3600
    assert approval_window < REPLAY_TTL_SECONDS
    assert SEQ_TTL_SECONDS >= REPLAY_TTL_SECONDS


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------


async def test_publish_reaches_a_subscriber(bus: EventBus, session_id: uuid.UUID) -> None:
    agen = bus.subscribe(session_id)
    await bus.publish(_event(session_id, 1))
    received = await anext(agen)
    assert received.seq == 1
    await agen.aclose()


async def test_publish_appends_to_the_replay_buffer(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    await bus.publish(_event(session_id, 1))
    await bus.publish(_event(session_id, 2))
    assert [e.seq for e in _buffered(redis, settings, session_id)] == [1, 2]


async def test_publish_and_buffer_happen_in_one_round_trip(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID
) -> None:
    """Doing them separately opens a window where a live event is not yet replayable.

    A subscriber that reconnects inside that window misses an event that was, from its
    point of view, already delivered.
    """
    await bus.publish(_event(session_id, 1))
    assert redis.executed == [["publish", "rpush", "ltrim", "expire"]]


async def test_the_buffer_is_capped(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """Redis is the transport, not the event store."""
    for seq in range(1, REPLAY_LIMIT + 6):
        await bus.publish(_event(session_id, seq))
    buffered = _buffered(redis, settings, session_id)
    assert len(buffered) == REPLAY_LIMIT
    assert buffered[-1].seq == REPLAY_LIMIT + 5


async def test_publishing_survives_a_redis_outage(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID
) -> None:
    """Emitting progress is observability, not work: a Redis blip must not abort a run."""
    redis.fail_on_execute = True
    await bus.publish(_event(session_id, 1))  # must not raise


async def test_a_failed_publish_is_logged(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID
) -> None:
    """Swallowed silently, "the socket went quiet" is indistinguishable from a stalled agent."""
    redis.fail_on_execute = True
    with structlog.testing.capture_logs() as logs:
        await bus.publish(_event(session_id, 7))
    assert [entry["event"] for entry in logs] == ["event.publish_failed"]
    assert logs[0]["seq"] == 7


async def test_an_oversized_event_keeps_its_sequence_and_loses_its_payload(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """SEC-006 backstop: a caller that inlines a tool result instead of summarizing it.

    The event survives so the client does not read a gap in ``seq`` and refetch the whole
    session; only the payload is dropped.
    """
    huge = _event(session_id, 4, data={"stdout": "A" * (MAX_EVENT_BYTES + 1)})
    with structlog.testing.capture_logs() as logs:
        await bus.publish(huge)
    stored = _buffered(redis, settings, session_id)[0]
    assert stored.seq == 4
    assert stored.data == {"_omitted": "payload too large"}
    assert len(event_to_frame(stored)) < MAX_EVENT_BYTES
    assert [entry["event"] for entry in logs] == ["event.oversized"]


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


async def test_replay_returns_the_buffer_oldest_first(bus: EventBus, session_id: uuid.UUID) -> None:
    for seq in (1, 2, 3):
        await bus.publish(_event(session_id, seq))
    assert [e.seq for e in await bus.replay(session_id)] == [1, 2, 3]


async def test_replay_excludes_what_the_client_already_rendered(
    bus: EventBus, session_id: uuid.UUID
) -> None:
    for seq in (1, 2, 3):
        await bus.publish(_event(session_id, seq))
    assert [e.seq for e in await bus.replay(session_id, after_seq=2)] == [3]


async def test_replay_of_an_unknown_session_is_empty(bus: EventBus) -> None:
    assert await bus.replay(uuid.uuid4()) == []


async def test_replay_survives_a_redis_outage(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID
) -> None:
    """A socket that opens with no history is degraded; one that 500s is broken."""
    redis.fail_on_lrange = True
    assert await bus.replay(session_id) == []


async def test_replay_skips_an_undecodable_frame(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """One bad frame must not take down a live run's whole stream."""
    await bus.publish(_event(session_id, 1))
    key = f"{settings.redis.event_channel_prefix}:replay:{session_id}"
    redis.lists[key].append("{not json")
    await bus.publish(_event(session_id, 2))
    assert [e.seq for e in await bus.replay(session_id)] == [1, 2]


# ---------------------------------------------------------------------------
# Subscribe
# ---------------------------------------------------------------------------


async def test_subscribe_delivers_the_backlog_before_live_traffic(
    bus: EventBus, session_id: uuid.UUID
) -> None:
    """A tab opened mid-run has to discover what already happened.

    Without the backlog it renders an idle-looking assessment until the next event, which
    for a run paused at the approval interrupt is forever.
    """
    await bus.publish(_event(session_id, 1, type=AgentEventType.AGENT_APPROVAL_REQUIRED))
    agen = bus.subscribe(session_id)
    backlog = await anext(agen)
    assert backlog.type is AgentEventType.AGENT_APPROVAL_REQUIRED

    await bus.publish(_event(session_id, 2, type=AgentEventType.AGENT_COMPLETE))
    live = await anext(agen)
    assert live.type is AgentEventType.AGENT_COMPLETE
    await agen.aclose()


async def test_subscribe_honours_the_clients_position(bus: EventBus, session_id: uuid.UUID) -> None:
    for seq in (1, 2):
        await bus.publish(_event(session_id, seq))
    agen = bus.subscribe(session_id, after_seq=1)
    assert (await anext(agen)).seq == 2
    await agen.aclose()


async def test_subscribe_delivers_an_event_once_even_if_it_arrives_twice(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """The cost of subscribing before draining the backlog, and why ``seq`` is tracked.

    An event published between the subscribe and the ``LRANGE`` arrives by both routes.
    Delivering it twice would render a duplicate message in the conversation.
    """
    await bus.publish(_event(session_id, 1))
    agen = bus.subscribe(session_id)
    assert (await anext(agen)).seq == 1

    channel = channel_for(settings, session_id)
    key = f"{settings.redis.event_channel_prefix}:replay:{session_id}"
    redis._do_publish(channel, redis.lists[key][0])  # the same frame, again
    await bus.publish(_event(session_id, 2))

    assert (await anext(agen)).seq == 2
    await agen.aclose()


async def test_subscribe_ignores_a_malformed_live_frame(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    await bus.publish(_event(session_id, 1))
    agen = bus.subscribe(session_id)
    assert (await anext(agen)).seq == 1

    redis._do_publish(channel_for(settings, session_id), "<html>502 Bad Gateway</html>")
    await bus.publish(_event(session_id, 2))
    assert (await anext(agen)).seq == 2
    await agen.aclose()


async def test_subscribe_releases_its_connection_when_the_consumer_stops(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """The normal exit is cancellation, when the browser disconnects.

    A pubsub left open is a pooled connection reclaimed only by timeout, which surfaces
    much later as pool exhaustion on an unrelated request.
    """
    await bus.publish(_event(session_id, 1))
    agen = bus.subscribe(session_id)
    await anext(agen)
    channel = channel_for(settings, session_id)
    assert len(redis.subscribers[channel]) == 1

    await agen.aclose()
    assert redis.subscribers[channel] == []


async def test_subscribe_does_not_raise_when_the_close_fails(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID
) -> None:
    """A disconnect is already the unhappy path; a second failure must not mask it."""
    await bus.publish(_event(session_id, 1))
    agen = bus.subscribe(session_id)
    await anext(agen)
    redis.fail_on_close = True
    await agen.aclose()  # must not raise


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------


def test_a_frame_round_trips(session_id: uuid.UUID) -> None:
    event = _event(session_id, 5, data={"text": "hello"})
    assert frame_to_event(event_to_frame(event)) == event


def test_frame_to_event_returns_none_for_garbage() -> None:
    assert frame_to_event("not an event") is None
    assert frame_to_event(json.dumps({"type": "agent_thinking"})) is None


def test_pong_carries_seq_zero(session_id: uuid.UUID) -> None:
    """A keepalive is not part of the session's stream.

    Allocating a real sequence number would make every idle client's pings advance the
    counter and manufacture apparent gaps for everyone else watching the session.
    """
    pong = pong_event(session_id)
    assert (pong.type, pong.seq, pong.session_id) == (AgentEventType.PONG, 0, session_id)


# ---------------------------------------------------------------------------
# EventEmitter
# ---------------------------------------------------------------------------


def _approval(assessment_id: uuid.UUID) -> ApprovalOut:
    return ApprovalOut(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        kind=ApprovalKind.SCAN_SCOPE,
        decision=ApprovalDecision.PENDING,
        prompt="Scan 12 assets with nmap and nuclei?",
        risk_level=RiskLevel.MEDIUM,
        proposed_scanners=[ScannerName.NMAP, ScannerName.NUCLEI],
        created_at=NOW,
    )


def _message(session_id: uuid.UUID) -> AgentMessageOut:
    return AgentMessageOut(
        id=uuid.uuid4(),
        session_id=session_id,
        seq=1,
        role=MessageRole.ASSISTANT,
        content="Recon finished. 12 assets found.",
        created_at=NOW,
    )


async def _emit_one_of_each(emitter: EventEmitter) -> None:
    """Drive every emitter method once, with a valid payload for each."""
    assessment_id = emitter.assessment_id
    assert assessment_id is not None
    await emitter.thinking("Reading the objective.", node="understand")
    await emitter.plan_step(
        step_index=0,
        total_steps=5,
        title="Passive reconnaissance",
        status=StepStatus.RUNNING,
        stage=AssessmentStage.RECON,
    )
    await emitter.tool_call(tool="nmap", status="started", risk_level=RiskLevel.MEDIUM)
    await emitter.approval_required(_approval(assessment_id))
    await emitter.findings_update(assessment_id=assessment_id, total=3, high=1)
    await emitter.error(IntegrationError(provider="nvd"), stage=AssessmentStage.ENRICH)
    await emitter.complete(assessment_id=assessment_id, status=AssessmentStatus.COMPLETED)
    await emitter.message(_message(emitter.session_id))
    await emitter.progress(
        stage=AssessmentStage.REPORT,
        progress_percent=94,
        stages=[
            StageOut(
                stage=AssessmentStage.REPORT,
                label=STAGE_LABELS[AssessmentStage.REPORT],
                status=StepStatus.RUNNING,
            )
        ],
    )


async def test_every_declared_event_type_has_an_emitter(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """A new member of ``AgentEventType`` needs a typed method, not a raw ``emit`` call.

    ``PONG`` is excluded because it is built without Redis -- see :func:`pong_event`.
    """
    await _emit_one_of_each(emitter)
    published = {e.type for e in _buffered(redis, settings, session_id)}
    assert published == set(EVENT_PAYLOADS)


async def test_published_data_matches_the_declared_payload_model(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """``EVENT_PAYLOADS`` is what the frontend generator reads.

    If ``data`` does not validate against it, the contract is a comment rather than a
    contract -- and the client's decoder is the thing that breaks.
    """
    await _emit_one_of_each(emitter)
    for event in _buffered(redis, settings, session_id):
        EVENT_PAYLOADS[event.type].model_validate(event.data)


async def test_payloads_are_json_ready(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """``data`` is dumped in ``mode="json"``.

    A raw ``UUID`` or ``datetime`` nested in a plain dict makes the envelope's own
    serialization fail *inside the emitter*, so the failure surfaces as silence on a socket
    nobody is watching yet.
    """
    await _emit_one_of_each(emitter)
    for event in _buffered(redis, settings, session_id):
        json.dumps(event.data)


async def test_the_emitter_stamps_its_bound_ids(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """A node holds an emitter, not the bus, so it cannot label an event with another
    session's id."""
    await emitter.thinking("hello")
    event = _buffered(redis, settings, session_id)[0]
    assert event.session_id == emitter.session_id
    assert event.assessment_id == emitter.assessment_id
    assert event.run_id == emitter.run_id


async def test_the_emitter_allocates_one_seq_per_event(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    await _emit_one_of_each(emitter)
    seqs = [e.seq for e in _buffered(redis, settings, session_id)]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


async def test_two_emitters_on_one_session_share_the_sequence(
    bus: EventBus, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """Two nodes emitting concurrently is the normal case, not an edge one."""
    a = EventEmitter(bus, session_id=session_id)
    b = EventEmitter(bus, session_id=session_id)
    await asyncio.gather(a.thinking("a"), b.thinking("b"), a.thinking("c"))
    seqs = sorted(e.seq for e in _buffered(redis, settings, session_id))
    assert seqs == [1, 2, 3]


def test_bind_returns_a_copy(bus: EventBus, session_id: uuid.UUID) -> None:
    """The session exists before the assessment does -- the operator is chatting first."""
    base = EventEmitter(bus, session_id=session_id)
    assessment_id = uuid.uuid4()
    bound = base.bind(assessment_id=assessment_id)
    assert bound is not base
    assert base.assessment_id is None
    assert bound.assessment_id == assessment_id
    assert bound.session_id == session_id


def test_bind_keeps_what_it_was_not_given(bus: EventBus, session_id: uuid.UUID) -> None:
    run_id = uuid.uuid4()
    bound = EventEmitter(bus, session_id=session_id, run_id=run_id).bind(assessment_id=uuid.uuid4())
    assert bound.run_id == run_id


# ---------------------------------------------------------------------------
# SEC-002 / SEC-006 on the wire
# ---------------------------------------------------------------------------


def test_tool_call_has_nowhere_to_put_arguments() -> None:
    """The SEC-002 rule is enforced by the signature, so the signature is the test.

    Scanner argv carries target hostnames and integration calls carry tokens. A method
    with no parameter for them cannot be misused into putting them on a socket.
    """
    parameters = set(inspect.signature(EventEmitter.tool_call).parameters)
    forbidden = {"args", "arguments", "argv", "params", "input", "command", "cmd", "payload"}
    assert parameters & forbidden == set()
    assert "summary" in parameters


async def test_error_publishes_the_user_safe_message_only(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """The internal message may quote a provider response; this envelope goes to a browser."""
    error = IntegrationError("401 from https://jira.internal?token=s3cr3t", provider="jira")
    assert "s3cr3t" in str(error), "fixture no longer carries a secret; the test is vacuous"

    await emitter.error(error, stage=AssessmentStage.ACTIONS)
    frame = event_to_frame(_buffered(redis, settings, session_id)[0])
    assert "s3cr3t" not in frame
    assert "jira.internal" not in frame
    assert error.user_message in frame


async def test_error_carries_the_taxonomy_fields_the_ui_needs(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    """``retryable`` and ``degradable`` decide whether the UI offers "retry" or explains
    a partial result, so they must survive the trip (FR-039, FR-040)."""
    error = IntegrationError(provider="nvd")
    await emitter.error(error, stage=AssessmentStage.ENRICH)
    data = _buffered(redis, settings, session_id)[0].data
    assert data["code"] == error.code
    assert data["category"] == error.category.value
    assert data["retryable"] is True
    assert data["degradable"] is True
    assert data["stage"] == AssessmentStage.ENRICH.value


async def test_tool_call_publishes_only_the_summary(
    emitter: EventEmitter, redis: FakeRedis, session_id: uuid.UUID, settings: Settings
) -> None:
    await emitter.tool_call(
        tool="nuclei",
        status="succeeded",
        summary="nuclei against 12 selected assets",
        duration_ms=41_000,
    )
    data = _buffered(redis, settings, session_id)[0].data
    assert data == {
        "tool": "nuclei",
        "status": "succeeded",
        "risk_level": None,
        "summary": "nuclei against 12 selected assets",
        "duration_ms": 41_000,
    }
