"""A worker must not reserve more long-running assessments than it can drive."""

from __future__ import annotations

import uuid

import pytest


@pytest.mark.asyncio
async def test_idle_worker_claims_only_one_new_run_at_a_time(monkeypatch) -> None:
    from app.worker.worker import AgentWorker

    class _Redis:
        def __init__(self):
            self.counts: list[int] = []

        async def xreadgroup(self, group, consumer, streams, *, count, block):
            self.counts.append(count)
            return []

    async def no_reclaim(self):
        return None

    monkeypatch.setattr(AgentWorker, "_reclaim_pending", no_reclaim)
    worker = object.__new__(AgentWorker)
    redis = _Redis()
    worker._redis = redis
    worker._group = "workers"
    worker._consumer = "worker-1"
    worker._stream = "runs"
    worker._stopping = False

    await worker._consume_once()

    assert redis.counts == [1]


@pytest.mark.asyncio
async def test_idle_worker_reclaims_only_one_orphaned_run_at_a_time() -> None:
    from types import SimpleNamespace

    from app.worker.worker import AgentWorker

    class _Redis:
        def __init__(self):
            self.counts: list[int] = []

        async def xautoclaim(self, stream, group, consumer, *, min_idle_time, start_id, count):
            self.counts.append(count)
            return ["0-0", []]

    worker = object.__new__(AgentWorker)
    redis = _Redis()
    worker._redis = redis
    worker._group = "workers"
    worker._consumer = "worker-1"
    worker._stream = "runs"
    worker._stopping = False
    worker._settings = SimpleNamespace(redis=SimpleNamespace(claim_idle_ms=120_000))

    await worker._reclaim_pending()

    assert redis.counts == [1]


@pytest.mark.asyncio
async def test_publishing_does_not_trim_unacknowledged_run_requests() -> None:
    from types import SimpleNamespace

    from app.worker.protocol import RunAction, RunRequest, publish_run_request

    class _Redis:
        def __init__(self):
            self.kwargs = None

        async def xadd(self, stream, fields, **kwargs):
            self.kwargs = kwargs
            return "1-0"

    redis = _Redis()
    settings = SimpleNamespace(redis=SimpleNamespace(stream="runs", max_stream_length=1))
    request = RunRequest.new(uuid.uuid4(), RunAction.START)
    assert await publish_run_request(redis, settings, request) == "1-0"
    assert redis.kwargs == {}


@pytest.mark.asyncio
async def test_settled_run_is_deleted_only_after_acknowledgement() -> None:
    from app.worker.worker import AgentWorker

    class _Redis:
        def __init__(self):
            self.calls = []

        async def xack(self, stream, group, message_id):
            self.calls.append(("ack", message_id))
            return 1

        async def xdel(self, stream, message_id):
            self.calls.append(("delete", message_id))
            return 1

    worker = object.__new__(AgentWorker)
    redis = _Redis()
    worker._redis = redis
    worker._stream = "runs"
    worker._group = "workers"
    await worker._ack("1-0")
    assert redis.calls == [("ack", "1-0"), ("delete", "1-0")]


@pytest.mark.asyncio
async def test_poison_message_is_dead_lettered_before_acknowledgement() -> None:
    from app.worker.worker import AgentWorker

    class _Redis:
        def __init__(self):
            self.calls = []

        async def xadd(self, stream, fields):
            self.calls.append(("dead_letter", stream, fields))
            return "2-0"

        async def xack(self, stream, group, message_id):
            self.calls.append(("ack", message_id))
            return 1

        async def xdel(self, stream, message_id):
            self.calls.append(("delete", message_id))
            return 1

    worker = object.__new__(AgentWorker)
    redis = _Redis()
    worker._redis = redis
    worker._stream = "runs"
    worker._group = "workers"
    await worker._dispatch("1-0", {"invalid": "potential secret"}, reclaimed=False)

    assert redis.calls == [
        ("dead_letter", "runs:dead", {
            "source_message_id": "1-0", "reason": "invalid_request",
        }),
        ("ack", "1-0"),
        ("delete", "1-0"),
    ]
    assert "potential secret" not in str(redis.calls)


@pytest.mark.asyncio
async def test_dead_letter_failure_keeps_poison_message_pending() -> None:
    from redis.exceptions import RedisError

    from app.worker.worker import AgentWorker

    class _Redis:
        def __init__(self):
            self.acked = False

        async def xadd(self, stream, fields):
            raise RedisError("offline")

        async def xack(self, stream, group, message_id):
            self.acked = True
            return 1

    worker = object.__new__(AgentWorker)
    redis = _Redis()
    worker._redis = redis
    worker._stream = "runs"
    worker._group = "workers"
    await worker._dispatch("1-0", {"invalid": "potential secret"}, reclaimed=False)

    assert redis.acked is False


@pytest.mark.asyncio
async def test_duplicate_delivery_does_not_drive_a_live_run(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.db.enums import AgentRunStatus
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker, _RunContext

    run_id = uuid.uuid4()
    org_id = uuid.uuid4()
    driven = []
    acknowledged = []

    async def load_context(self, current_run_id, message_id):
        assert current_run_id == run_id
        return _RunContext(
            run_status=AgentRunStatus.RUNNING,
            organization_id=org_id,
            assessment_id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            heartbeat_at=dt.datetime.now(dt.UTC),
            assessment_status=None,
        )

    async def drive(self, *args):
        driven.append(args)

    async def ack(self, message_id):
        acknowledged.append(message_id)

    monkeypatch.setattr(AgentWorker, "_load_context", load_context)
    monkeypatch.setattr(AgentWorker, "_run", drive)
    monkeypatch.setattr(AgentWorker, "_ack", ack)
    worker = object.__new__(AgentWorker)
    worker._settings = SimpleNamespace(redis=SimpleNamespace(claim_idle_ms=120_000))
    request = RunRequest.new(run_id, RunAction.START)

    await worker._dispatch("2-0", request.to_fields(), reclaimed=False)
    assert driven == []
    assert acknowledged == ["2-0"]

    await worker._dispatch("1-0", request.to_fields(), reclaimed=True)
    assert driven == []
    assert acknowledged == ["2-0"]


@pytest.mark.asyncio
async def test_duplicate_delivery_keeps_original_queue_trace(monkeypatch) -> None:
    import datetime as dt
    from contextlib import asynccontextmanager

    from app.db.enums import AgentRunStatus
    from app.worker import worker as worker_module

    run_id = uuid.uuid4()
    run = type("Run", (), {})()
    run.status_enum = AgentRunStatus.RUNNING
    run.queue_message_id = "1-0"
    run.organization_id = uuid.uuid4()
    run.assessment_id = None
    run.session_id = uuid.uuid4()
    run.heartbeat_at = dt.datetime.now(dt.UTC)

    class _Session:
        async def get(self, model, key):
            assert key == run_id
            return run

    @asynccontextmanager
    async def scoped(settings):
        yield _Session()

    monkeypatch.setattr(worker_module, "session_scope", scoped)
    worker = object.__new__(worker_module.AgentWorker)
    worker._settings = object()
    await worker._load_context(run_id, "2-0")
    assert run.queue_message_id == "1-0"


@pytest.mark.asyncio
async def test_missing_run_is_recorded_for_recovery_before_ack(monkeypatch) -> None:
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker

    events = []

    async def missing(self, run_id, message_id):
        return None

    async def dead_letter(self, message_id, reason):
        events.append(("dead", message_id, reason))
        return True

    async def ack(self, message_id):
        events.append(("ack", message_id))

    monkeypatch.setattr(AgentWorker, "_load_context", missing)
    monkeypatch.setattr(AgentWorker, "_dead_letter", dead_letter)
    monkeypatch.setattr(AgentWorker, "_ack", ack)
    worker = object.__new__(AgentWorker)
    request = RunRequest.new(uuid.uuid4(), RunAction.START)
    await worker._dispatch("1-0", request.to_fields(), reclaimed=False)
    assert events == [("dead", "1-0", "run_missing"), ("ack", "1-0")]


@pytest.mark.asyncio
async def test_unprocessable_run_is_dead_lettered_before_ack(monkeypatch) -> None:
    import datetime as dt

    from app.db.enums import AgentRunStatus
    from app.worker.worker import AgentWorker, _RunContext

    events = []
    run_id = uuid.uuid4()
    context = _RunContext(
        run_status=AgentRunStatus.QUEUED,
        organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        heartbeat_at=dt.datetime.now(dt.UTC),
        assessment_status=None,
    )

    class _Runner:
        async def advance(self, run_id, *, principal):
            from app.core.errors import InvalidConfigurationError
            raise InvalidConfigurationError("not runnable")

    async def dead_letter(self, message_id, reason):
        events.append(("dead", message_id, reason))
        return True

    async def ack(self, message_id):
        events.append(("ack", message_id))

    async def monitor(self, *args):
        await args[-1].stop.wait()

    async def settle(self, current_run_id, current_context):
        events.append(("settled", current_run_id))

    monkeypatch.setattr(AgentWorker, "_dead_letter", dead_letter)
    monkeypatch.setattr(AgentWorker, "_ack", ack)
    monkeypatch.setattr(AgentWorker, "_settle_retry_exhausted", settle)
    monkeypatch.setattr(AgentWorker, "_monitor", monitor)
    worker = object.__new__(AgentWorker)
    worker._runner = _Runner()
    worker._stopping = False
    await worker._run("1-0", run_id, context, None)
    assert events == [
        ("dead", "1-0", "unprocessable_run"), ("settled", run_id), ("ack", "1-0"),
    ]


@pytest.mark.asyncio
async def test_failed_run_attempts_have_persisted_exponential_backoff(monkeypatch) -> None:
    import datetime as dt

    from app.worker import worker as worker_module

    class _Redis:
        def __init__(self):
            self.hashes = {}

        async def hincrby(self, key, field, amount):
            data = self.hashes.setdefault(key, {})
            data[field] = int(data.get(field, 0)) + amount
            return data[field]

        async def hset(self, key, field, value):
            self.hashes.setdefault(key, {})[field] = value
            return 1

        async def hget(self, key, field):
            return self.hashes.get(key, {}).get(field)

        async def expire(self, key, seconds):
            return True

    current = dt.datetime(2026, 10, 5, tzinfo=dt.UTC)
    monkeypatch.setattr(worker_module, "_now", lambda: current)
    worker = object.__new__(worker_module.AgentWorker)
    worker._redis = _Redis()
    worker._stream = "runs"
    assert await worker._begin_attempt("1-0") == 1
    await worker._schedule_retry("1-0", 1)
    assert await worker._retry_due("1-0") is False
    current += dt.timedelta(seconds=120)
    assert await worker._retry_due("1-0") is True
    assert await worker._begin_attempt("1-0") == 2
    await worker._schedule_retry("1-0", 2)
    current += dt.timedelta(seconds=120)
    assert await worker._retry_due("1-0") is False
    current += dt.timedelta(seconds=120)
    assert await worker._retry_due("1-0") is True


@pytest.mark.asyncio
async def test_retry_is_not_driven_before_due_and_counts_real_attempt(monkeypatch) -> None:
    from app.db.enums import AgentRunStatus
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker, _RunContext

    run_id = uuid.uuid4()
    context = _RunContext(
        run_status=AgentRunStatus.RUNNING, organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )
    due = False
    driven = []

    async def load(self, current_run_id, message_id):
        return context

    async def is_due(self, message_id):
        return due

    async def begin(self, message_id):
        return 2

    async def drive(self, message_id, current_run_id, current_context, principal, attempts):
        driven.append(attempts)

    async def claim(self, organization_id, current_run_id):
        return True

    async def release(self, organization_id, current_run_id):
        return None

    monkeypatch.setattr(AgentWorker, "_load_context", load)
    monkeypatch.setattr(AgentWorker, "_retry_due", is_due)
    monkeypatch.setattr(AgentWorker, "_begin_attempt", begin)
    monkeypatch.setattr(AgentWorker, "_run", drive)
    monkeypatch.setattr(AgentWorker, "_claim_run_slot", claim)
    monkeypatch.setattr(AgentWorker, "_release_run_slot", release)
    worker = object.__new__(AgentWorker)
    request = RunRequest.new(run_id, RunAction.START)
    await worker._dispatch("1-0", request.to_fields(), reclaimed=True)
    assert driven == []
    due = True
    await worker._dispatch("1-0", request.to_fields(), reclaimed=True)
    assert driven == [2]


@pytest.mark.asyncio
async def test_tenant_run_slot_refusal_never_spends_an_attempt(monkeypatch) -> None:
    from app.db.enums import AgentRunStatus
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker, _RunContext

    run_id = uuid.uuid4()
    org_id = uuid.uuid4()
    context = _RunContext(
        run_status=AgentRunStatus.QUEUED, organization_id=org_id,
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )

    async def load(self, current_run_id, message_id):
        return context

    async def due(self, message_id):
        return True

    async def refuse(self, organization_id, current_run_id):
        assert organization_id == org_id
        assert current_run_id == run_id
        return False

    async def forbidden(self, *args):
        raise AssertionError("refused run must not be counted or driven")

    monkeypatch.setattr(AgentWorker, "_load_context", load)
    monkeypatch.setattr(AgentWorker, "_retry_due", due)
    monkeypatch.setattr(AgentWorker, "_claim_run_slot", refuse, raising=False)
    monkeypatch.setattr(AgentWorker, "_begin_attempt", forbidden)
    monkeypatch.setattr(AgentWorker, "_run", forbidden)
    worker = object.__new__(AgentWorker)
    request = RunRequest.new(run_id, RunAction.START)
    await worker._dispatch("3-0", request.to_fields(), reclaimed=False)


@pytest.mark.asyncio
async def test_tenant_run_slot_released_after_graph_settles(monkeypatch) -> None:
    from app.db.enums import AgentRunStatus
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker, _RunContext

    run_id = uuid.uuid4()
    org_id = uuid.uuid4()
    context = _RunContext(
        run_status=AgentRunStatus.QUEUED, organization_id=org_id,
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )
    events = []

    async def load(self, current_run_id, message_id):
        return context

    async def due(self, message_id):
        return True

    async def claim(self, organization_id, current_run_id):
        events.append("claimed")
        return True

    async def begin(self, message_id):
        events.append("attempt")
        return 1

    async def drive(self, message_id, current_run_id, current_context, principal, attempts):
        events.append("driven")

    async def release(self, organization_id, current_run_id):
        events.append("released")

    monkeypatch.setattr(AgentWorker, "_load_context", load)
    monkeypatch.setattr(AgentWorker, "_retry_due", due)
    monkeypatch.setattr(AgentWorker, "_claim_run_slot", claim, raising=False)
    monkeypatch.setattr(AgentWorker, "_release_run_slot", release, raising=False)
    monkeypatch.setattr(AgentWorker, "_begin_attempt", begin)
    monkeypatch.setattr(AgentWorker, "_run", drive)
    worker = object.__new__(AgentWorker)
    request = RunRequest.new(run_id, RunAction.START)
    await worker._dispatch("3-0", request.to_fields(), reclaimed=False)
    assert events == ["claimed", "attempt", "driven", "released"]


@pytest.mark.asyncio
async def test_worker_cancels_graph_when_tenant_lease_cannot_be_renewed(monkeypatch) -> None:
    import asyncio

    from app.db.enums import AgentRunStatus
    from app.worker import worker as module

    context = module._RunContext(
        run_status=AgentRunStatus.RUNNING, organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )
    worker = object.__new__(module.AgentWorker)
    async def lost(self, organization_id, run_id):
        return False

    async def no_cancel(self, run_id, ctx):
        return False

    monkeypatch.setattr(module, "_MONITOR_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(module.AgentWorker, "_renew_run_slot", lost, raising=False)
    monkeypatch.setattr(module.AgentWorker, "_heartbeat_and_check_cancel", no_cancel)
    run_id = uuid.uuid4()
    advance = asyncio.create_task(asyncio.sleep(10))
    canceller = module._CancelState()
    try:
        await asyncio.wait_for(worker._monitor(run_id, context, advance, canceller), 0.2)
        assert canceller.lease_lost is True
        assert advance.cancelled() or advance.cancelling()
    finally:
        advance.cancel()
        await asyncio.gather(advance, return_exceptions=True)


@pytest.mark.asyncio
async def test_tenant_run_slot_claim_is_atomic_in_redis(monkeypatch) -> None:
    import asyncio
    import datetime as dt
    import shutil
    import socket
    import subprocess
    from types import SimpleNamespace

    import redis.asyncio

    from app.worker import worker as module

    executable = shutil.which("redis-server")
    if executable is None:
        pytest.skip("redis-server unavailable")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    def start_local_redis():
        return subprocess.Popen(
            [executable, "--bind", "127.0.0.1", "--port", str(port),  # noqa: S603 - resolved executable
             "--save", "", "--appendonly", "no"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

    process = start_local_redis()
    redis_client = redis.asyncio.Redis(host="127.0.0.1", port=port)
    try:
        for _ in range(40):
            try:
                await redis_client.ping()
                break
            except redis.exceptions.RedisError:
                await asyncio.sleep(0.05)
        else:
            pytest.fail("temporary redis-server did not start")

        org_id = uuid.uuid4()
        first_run, second_run = uuid.uuid4(), uuid.uuid4()
        base = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
        monkeypatch.setattr(module, "_now", lambda: base)
        workers = []
        for worker_id in ("worker-one", "worker-two"):
            worker = object.__new__(module.AgentWorker)
            worker._worker_id = worker_id
            worker._redis = redis_client
            worker._stream = f"test-runs:{org_id}"
            worker._settings = SimpleNamespace(
                agent=SimpleNamespace(max_concurrent_runs_per_org=1)
            )
            workers.append(worker)
        accepted = await asyncio.gather(
            workers[0]._claim_run_slot(org_id, first_run),
            workers[1]._claim_run_slot(org_id, second_run),
        )
        assert sum(accepted) == 1
        winning_index = accepted.index(True)
        winning_run = (first_run, second_run)[winning_index]
        assert await workers[winning_index]._renew_run_slot(org_id, winning_run) is True
        monkeypatch.setattr(module, "_now", lambda: base + dt.timedelta(seconds=91))
        losing_index = accepted.index(False)
        losing_run = (first_run, second_run)[losing_index]
        assert await workers[losing_index]._claim_run_slot(org_id, losing_run) is True
        await workers[0]._release_run_slot(org_id, first_run)
        await workers[1]._release_run_slot(org_id, second_run)
        for worker in workers:
            worker._settings.agent.max_concurrent_runs_per_org = 2
        duplicate_claims = await asyncio.gather(
            workers[0]._claim_run_slot(org_id, first_run),
            workers[1]._claim_run_slot(org_id, first_run),
        )
        assert sum(duplicate_claims) == 1
        duplicate_winner = duplicate_claims.index(True)
        duplicate_loser = duplicate_claims.index(False)
        await workers[duplicate_loser]._release_run_slot(org_id, first_run)
        assert await workers[duplicate_loser]._claim_run_slot(org_id, first_run) is False
        await workers[duplicate_winner]._release_run_slot(org_id, first_run)
        assert await workers[duplicate_loser]._claim_run_slot(org_id, first_run) is True
        await workers[duplicate_loser]._release_run_slot(org_id, first_run)
    finally:
        await redis_client.aclose()
        process.terminate()
        process.wait(timeout=3)


@pytest.mark.asyncio
async def test_unexpected_run_error_schedules_retry_without_ack(monkeypatch) -> None:
    from app.db.enums import AgentRunStatus
    from app.worker.worker import AgentWorker, _RunContext

    events = []

    class _Runner:
        async def advance(self, run_id, *, principal):
            raise RuntimeError("internal failure")

    async def monitor(self, *args):
        await args[-1].stop.wait()

    async def schedule(self, message_id, attempts):
        events.append(("retry", message_id, attempts))

    async def ack(self, message_id):
        events.append(("ack", message_id))

    monkeypatch.setattr(AgentWorker, "_monitor", monitor)
    monkeypatch.setattr(AgentWorker, "_schedule_retry", schedule)
    monkeypatch.setattr(AgentWorker, "_ack", ack)
    worker = object.__new__(AgentWorker)
    worker._runner = _Runner()
    worker._stopping = False
    context = _RunContext(
        run_status=AgentRunStatus.RUNNING, organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )
    await worker._run("1-0", uuid.uuid4(), context, None, 3)
    assert events == [("retry", "1-0", 3)]


@pytest.mark.asyncio
async def test_retry_limit_dead_letters_and_settles_without_sixth_run(monkeypatch) -> None:
    from app.db.enums import AgentRunStatus
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker, _RunContext

    events = []
    run_id = uuid.uuid4()
    context = _RunContext(
        run_status=AgentRunStatus.RUNNING, organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )

    async def load(self, current_run_id, message_id):
        return context

    async def due(self, message_id):
        return True

    async def begin(self, message_id):
        return 6

    async def dead(self, message_id, reason):
        events.append(("dead", reason))
        return True

    async def settle(self, current_run_id, current_context):
        events.append(("settled", current_run_id))

    async def ack(self, message_id):
        events.append(("ack", message_id))

    async def drive(self, *args):
        raise AssertionError("sixth graph invocation")

    async def claim(self, organization_id, current_run_id):
        return True

    async def release(self, organization_id, current_run_id):
        return None

    monkeypatch.setattr(AgentWorker, "_load_context", load)
    monkeypatch.setattr(AgentWorker, "_retry_due", due)
    monkeypatch.setattr(AgentWorker, "_begin_attempt", begin)
    monkeypatch.setattr(AgentWorker, "_dead_letter", dead)
    monkeypatch.setattr(AgentWorker, "_settle_retry_exhausted", settle)
    monkeypatch.setattr(AgentWorker, "_ack", ack)
    monkeypatch.setattr(AgentWorker, "_run", drive)
    monkeypatch.setattr(AgentWorker, "_claim_run_slot", claim)
    monkeypatch.setattr(AgentWorker, "_release_run_slot", release)
    worker = object.__new__(AgentWorker)
    await worker._dispatch(
        "1-0", RunRequest.new(run_id, RunAction.START).to_fields(), reclaimed=True,
    )
    assert events == [
        ("dead", "retry_exhausted"), ("settled", run_id), ("ack", "1-0"),
    ]


@pytest.mark.asyncio
async def test_retry_exhaustion_never_changes_a_foreign_tenant_run(monkeypatch) -> None:
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from app.db.enums import AgentRunStatus
    from app.worker import worker as worker_module

    run_id = uuid.uuid4()
    run = SimpleNamespace(
        organization_id=uuid.uuid4(), status_enum=AgentRunStatus.RUNNING,
        status=AgentRunStatus.RUNNING.value, completed_at=None,
    )
    context = worker_module._RunContext(
        run_status=AgentRunStatus.RUNNING,
        organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )

    class _Session:
        async def get(self, model, key):
            assert key == run_id
            return run

    @asynccontextmanager
    async def scoped(settings):
        yield _Session()

    async def forbidden_assessment(self, session, organization_id, assessment_id):
        raise AssertionError("cross-tenant assessment lookup")

    monkeypatch.setattr(worker_module, "session_scope", scoped)
    monkeypatch.setattr(worker_module.AgentWorker, "_load_assessment", forbidden_assessment)
    worker = object.__new__(worker_module.AgentWorker)
    worker._settings = object()
    await worker._settle_retry_exhausted(run_id, context)
    assert run.status == AgentRunStatus.RUNNING.value
    assert run.completed_at is None


@pytest.mark.asyncio
async def test_retry_exhaustion_fails_tenant_run_and_assessment(monkeypatch) -> None:
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from app.db.enums import AgentRunStatus, AssessmentStatus
    from app.worker import worker as worker_module

    run_id = uuid.uuid4()
    org_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    run = SimpleNamespace(
        organization_id=org_id, status_enum=AgentRunStatus.RUNNING,
        status=AgentRunStatus.RUNNING.value, completed_at=None,
        heartbeat_at=None, failure_reason=None,
    )
    assessment = SimpleNamespace(
        organization_id=org_id, id=assessment_id,
        status_enum=AssessmentStatus.PLANNING, status=AssessmentStatus.PLANNING.value,
    )
    context = worker_module._RunContext(
        run_status=AgentRunStatus.RUNNING, organization_id=org_id,
        assessment_id=assessment_id, session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=AssessmentStatus.PLANNING,
    )

    class _Session:
        async def get(self, model, key):
            assert key == run_id
            return run

    @asynccontextmanager
    async def scoped(settings):
        yield _Session()

    async def load_assessment(self, session, organization_id, current_assessment_id):
        assert organization_id == org_id
        assert current_assessment_id == assessment_id
        return assessment

    async def transition(session, target, status, *, reason):
        target.status = status.value
        target.status_enum = status

    monkeypatch.setattr(worker_module, "session_scope", scoped)
    monkeypatch.setattr(worker_module, "transition", transition)
    monkeypatch.setattr(worker_module.AgentWorker, "_load_assessment", load_assessment)
    worker = object.__new__(worker_module.AgentWorker)
    worker._settings = object()
    await worker._settle_retry_exhausted(run_id, context)
    assert run.status == AgentRunStatus.FAILED.value
    assert run.completed_at is not None
    assert run.failure_reason
    assert assessment.status == AssessmentStatus.FAILED.value


@pytest.mark.asyncio
async def test_failed_retry_settlement_keeps_stream_message_pending(monkeypatch) -> None:
    from app.db.enums import AgentRunStatus
    from app.worker.protocol import RunAction, RunRequest
    from app.worker.worker import AgentWorker, _RunContext

    context = _RunContext(
        run_status=AgentRunStatus.RUNNING, organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), session_id=uuid.uuid4(),
        heartbeat_at=None, assessment_status=None,
    )
    acked = []

    async def load(self, run_id, message_id):
        return context

    async def due(self, message_id):
        return True

    async def begin(self, message_id):
        return 6

    async def dead(self, message_id, reason):
        return True

    async def settle(self, run_id, current_context):
        raise RuntimeError("database unavailable")

    async def ack(self, message_id):
        acked.append(message_id)

    async def claim(self, organization_id, current_run_id):
        return True

    async def release(self, organization_id, current_run_id):
        return None

    monkeypatch.setattr(AgentWorker, "_load_context", load)
    monkeypatch.setattr(AgentWorker, "_retry_due", due)
    monkeypatch.setattr(AgentWorker, "_begin_attempt", begin)
    monkeypatch.setattr(AgentWorker, "_dead_letter", dead)
    monkeypatch.setattr(AgentWorker, "_settle_retry_exhausted", settle)
    monkeypatch.setattr(AgentWorker, "_ack", ack)
    monkeypatch.setattr(AgentWorker, "_claim_run_slot", claim)
    monkeypatch.setattr(AgentWorker, "_release_run_slot", release)
    worker = object.__new__(AgentWorker)
    await worker._dispatch(
        "1-0", RunRequest.new(uuid.uuid4(), RunAction.START).to_fields(), reclaimed=True,
    )
    assert acked == []


def test_staging_run_dispatch_is_idempotent_and_does_not_publish() -> None:
    from app.db.enums import Role
    from app.services.context import Principal
    from app.worker.dispatch import stage_run_dispatch
    from app.worker.protocol import RunAction

    class _Session:
        def __init__(self):
            self.added = []

        def add(self, row):
            self.added.append(row)

    session = _Session()
    org_id = uuid.uuid4()
    run_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    staged = stage_run_dispatch(
        session, organization_id=org_id, run_id=run_id,
        action=RunAction.START, principal=principal,
    )
    assert session.added == [staged]
    assert staged.organization_id == org_id
    assert staged.run_id == run_id
    assert staged.dispatch_key == f"{run_id}:start"
    assert staged.principal["organization_id"] == str(org_id)
    assert staged.status == "pending"


def test_start_dispatch_refuses_a_foreign_tenant_principal() -> None:
    from app.db.enums import Role
    from app.services.context import Principal
    from app.worker.dispatch import stage_run_dispatch
    from app.worker.protocol import RunAction

    class _Session:
        def add(self, row):
            raise AssertionError("foreign dispatch was staged")

    with pytest.raises(ValueError, match="same-tenant"):
        stage_run_dispatch(
            _Session(), organization_id=uuid.uuid4(), run_id=uuid.uuid4(),
            action=RunAction.START,
            principal=Principal(
                user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER,
            ),
        )


@pytest.mark.asyncio
async def test_outbox_publish_records_stream_id_after_success() -> None:
    from types import SimpleNamespace

    from app.worker.dispatch import publish_staged_dispatch, stage_run_dispatch
    from app.worker.protocol import RunAction

    class _Session:
        def add(self, row):
            return None

    class _Redis:
        def __init__(self):
            self.fields = None

        async def xadd(self, stream, fields):
            self.fields = fields
            return "7-0"

    org_id = uuid.uuid4()
    run_id = uuid.uuid4()
    row = stage_run_dispatch(
        _Session(), organization_id=org_id, run_id=run_id, action=RunAction.RESUME,
    )
    redis = _Redis()
    settings = SimpleNamespace(redis=SimpleNamespace(stream="runs"))
    assert await publish_staged_dispatch(row, redis, settings) is True
    assert row.status == "sent"
    assert row.stream_message_id == "7-0"
    assert row.published_at is not None
    assert redis.fields["run_id"] == str(run_id)
    assert redis.fields["action"] == "resume"


@pytest.mark.asyncio
async def test_outbox_publish_failure_remains_pending_for_retry() -> None:
    from types import SimpleNamespace

    from redis.exceptions import RedisError

    from app.worker.dispatch import publish_staged_dispatch, stage_run_dispatch
    from app.worker.protocol import RunAction

    class _Session:
        def add(self, row):
            return None

    class _Redis:
        async def xadd(self, stream, fields):
            raise RedisError("provider error containing a secret")

    row = stage_run_dispatch(
        _Session(), organization_id=uuid.uuid4(), run_id=uuid.uuid4(),
        action=RunAction.RESUME,
    )
    before = row.available_at
    settings = SimpleNamespace(redis=SimpleNamespace(stream="runs"))
    assert await publish_staged_dispatch(row, _Redis(), settings) is False
    assert row.status == "pending"
    assert row.attempts == 1
    assert row.available_at > before
    assert row.stream_message_id is None
    assert "secret" not in (row.last_error_code or "")


@pytest.mark.asyncio
async def test_outbox_sweep_interleaves_tenants_and_publishes_due_rows() -> None:
    from types import SimpleNamespace

    from sqlalchemy.dialects import postgresql

    from app.worker.dispatch import deliver_pending_dispatches, stage_run_dispatch
    from app.worker.protocol import RunAction

    class _Session:
        def __init__(self):
            self.rows = []
            self.statement = None

        def add(self, row):
            self.rows.append(row)

        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.rows))

    class _Redis:
        def __init__(self):
            self.published = []

        async def xadd(self, stream, fields):
            self.published.append(fields["run_id"])
            return f"{len(self.published)}-0"

    session = _Session()
    org_ids = [uuid.uuid4(), uuid.uuid4()]
    run_ids = [uuid.uuid4(), uuid.uuid4()]
    for org_id, run_id in zip(org_ids, run_ids, strict=True):
        stage_run_dispatch(
            session, organization_id=org_id, run_id=run_id, action=RunAction.RESUME,
        )
    redis = _Redis()
    count = await deliver_pending_dispatches(
        session, redis, SimpleNamespace(redis=SimpleNamespace(stream="runs")), limit=2,
    )
    assert count == 2
    assert redis.published == [str(item) for item in run_ids]
    assert all(row.status == "sent" for row in session.rows)
    compiled = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "row_number() OVER (PARTITION BY" in compiled
    assert "SKIP LOCKED" in compiled
    assert "agent_runs.organization_id = run_dispatches.organization_id" in compiled


def test_recurring_scan_schema_keeps_profile_scope_and_authorization_separate() -> None:
    from app.db.models.assessment import RecurringScan, ScanProfile

    profile_columns = ScanProfile.__table__.columns
    schedule_columns = RecurringScan.__table__.columns
    assert {"organization_id", "config", "name", "created_by_id"} <= set(profile_columns.keys())
    assert {
        "organization_id", "profile_id", "targets", "cron_expression", "timezone",
        "authorization_text", "authorization_expires_at", "next_run_at", "enabled",
    } <= set(schedule_columns.keys())
    assert "authorization_text" not in profile_columns


def test_agent_action_storage_accepts_the_supported_tenable_sync() -> None:
    from sqlalchemy import CheckConstraint

    from app.db.models.agent import AgentAction

    constraint = next(
        item for item in AgentAction.__table__.constraints
        if isinstance(item, CheckConstraint) and item.name.endswith("valid_agent_action")
    )
    assert "sync_tenable_vulnerabilities" in str(constraint.sqltext)


@pytest.mark.asyncio
async def test_immediate_dispatch_lookup_is_tenant_scoped() -> None:
    from types import SimpleNamespace

    from sqlalchemy.dialects import postgresql

    from app.worker.dispatch import deliver_run_dispatch, stage_run_dispatch
    from app.worker.protocol import RunAction

    class _Session:
        def __init__(self):
            self.row = None
            self.statement = None

        def add(self, row):
            self.row = row

        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalar_one_or_none=lambda: self.row)

    class _Redis:
        async def xadd(self, stream, fields):
            return "3-0"

    org_id = uuid.uuid4()
    session = _Session()
    row = stage_run_dispatch(
        session, organization_id=org_id, run_id=uuid.uuid4(), action=RunAction.RESUME,
    )
    success = await deliver_run_dispatch(
        session, organization_id=org_id, dispatch_id=row.id,
        redis=_Redis(), settings=SimpleNamespace(redis=SimpleNamespace(stream="runs")),
    )
    assert success is True
    assert row.status == "sent"
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert org_id in compiled.params.values()
    assert row.id in compiled.params.values()
    assert "agent_runs.organization_id = run_dispatches.organization_id" in str(compiled)


def test_assessment_creation_stages_run_dispatch_in_same_unit_of_work() -> None:
    from types import SimpleNamespace

    from app.api.v1.assessments import _seed_agent_run
    from app.db.enums import Role
    from app.db.models.agent import AgentRun, RunDispatch
    from app.services.context import Principal

    class _Session:
        def __init__(self):
            self.rows = []

        def add(self, row):
            self.rows.append(row)

    session = _Session()
    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    assessment = SimpleNamespace(id=uuid.uuid4(), title="Authorized scope", agent_session_id=None)
    run_id, dispatch_id = _seed_agent_run(session, principal, assessment)
    run = next(row for row in session.rows if isinstance(row, AgentRun))
    dispatch = next(row for row in session.rows if isinstance(row, RunDispatch))
    assert run.id == run_id
    assert dispatch.id == dispatch_id
    assert dispatch.organization_id == org_id
    assert dispatch.run_id == run_id
    assert dispatch.status == "pending"


@pytest.mark.asyncio
async def test_assessment_route_commits_outbox_before_publish_attempt(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.api.v1 import assessments as assessments_route
    from app.db.enums import Role
    from app.db.models.agent import RunDispatch
    from app.services.context import Principal

    events = []
    assessment = SimpleNamespace(
        id=uuid.uuid4(), title="Authorized scope", agent_session_id=None,
    )

    class _Session:
        def __init__(self):
            self.rows = []

        def add(self, row):
            self.rows.append(row)

        async def commit(self):
            events.append(("commit", len(self.rows)))

    async def create(session, principal, payload, settings):
        return assessment

    async def deliver(session, **kwargs):
        events.append(("deliver", kwargs["dispatch_id"]))
        return True

    async def get_assessment(session, principal, assessment_id, *, detail):
        return assessment

    async def project(session, record):
        return record

    monkeypatch.setattr(assessments_route.assessment_service, "create_assessment", create)
    monkeypatch.setattr(assessments_route.assessment_service, "get_assessment", get_assessment)
    monkeypatch.setattr(assessments_route, "deliver_run_dispatch", deliver)
    monkeypatch.setattr(assessments_route, "assessment_detail_out", project)
    session = _Session()
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER,
    )
    result = await assessments_route.create_assessment(
        object(), principal, session, object(), object(),
    )
    dispatch = next(row for row in session.rows if isinstance(row, RunDispatch))
    assert result is assessment
    assert events == [("commit", 3), ("deliver", dispatch.id), ("commit", 3)]


@pytest.mark.asyncio
async def test_approval_resolution_stages_resume_before_commit(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.api.v1 import approvals as approvals_route
    from app.db.enums import Role
    from app.db.models.agent import RunDispatch
    from app.services.context import Principal

    run_id = uuid.uuid4()
    events = []

    class _Session:
        def __init__(self):
            self.rows = []

        def add(self, row):
            self.rows.append(row)

        async def commit(self):
            events.append(("commit", len(self.rows)))

    async def resolve(session, principal, approval_id, payload):
        return SimpleNamespace(agent_run_id=run_id)

    async def deliver(session, **kwargs):
        events.append(("deliver", kwargs["dispatch_id"]))
        return True

    async def get_approval(session, principal, approval_id):
        return SimpleNamespace(resolved_by=None)

    async def project(session, approval, *, resolved_by):
        return approval

    monkeypatch.setattr(approvals_route.approval_service, "resolve_approval", resolve)
    monkeypatch.setattr(approvals_route.approval_service, "get_approval", get_approval)
    monkeypatch.setattr(approvals_route, "deliver_run_dispatch", deliver, raising=False)
    monkeypatch.setattr(approvals_route, "load_approval_out", project)
    session = _Session()
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER,
    )
    await approvals_route.resolve_approval(
        uuid.uuid4(), object(), principal, session, object(), object(),
    )
    dispatch = next(row for row in session.rows if isinstance(row, RunDispatch))
    assert dispatch.run_id == run_id
    assert dispatch.action == "resume"
    assert events == [("commit", 1), ("deliver", dispatch.id), ("commit", 1)]


@pytest.mark.asyncio
async def test_worker_maintenance_recovers_committed_unpublished_runs(monkeypatch) -> None:
    from contextlib import asynccontextmanager

    from app.worker import worker as worker_module

    calls = []
    worker = object.__new__(worker_module.AgentWorker)
    worker._stopping = False
    worker._settings = object()
    worker._redis = object()

    async def one_tick(seconds):
        worker._stopping = True

    @asynccontextmanager
    async def scoped(settings):
        yield object()

    async def no_op(*args, **kwargs):
        return 0

    async def dispatch(session, redis, settings):
        calls.append("dispatch")
        return 1

    async def schedule(session, settings):
        calls.append("schedule")
        return 1

    monkeypatch.setattr(worker_module.asyncio, "sleep", one_tick)
    monkeypatch.setattr(worker_module, "session_scope", scoped)
    monkeypatch.setattr(worker_module, "reclaim_orphans", no_op)
    monkeypatch.setattr(worker_module, "deliver_pending", no_op)
    monkeypatch.setattr(worker_module, "execute_approved_batch", no_op)
    monkeypatch.setattr(worker_module, "refresh_stale_risk_batch", no_op)
    monkeypatch.setattr(worker_module, "deliver_pending_dispatches", dispatch, raising=False)
    monkeypatch.setattr(worker_module, "run_due_scans", schedule, raising=False)
    await worker._maintenance_loop()
    assert calls == ["schedule", "dispatch"]


def test_recurring_scan_cron_uses_tenant_timezone_and_rejects_bad_input() -> None:
    import datetime as dt

    from app.services.recurring_scan import next_scan_time

    base = dt.datetime(2026, 10, 5, 2, 0, tzinfo=dt.UTC)
    assert next_scan_time("0 9 * * *", "Asia/Kolkata", base) == dt.datetime(
        2026, 10, 5, 3, 30, tzinfo=dt.UTC,
    )
    with pytest.raises(ValueError):
        next_scan_time("* * * * * *", "UTC", base)
    with pytest.raises(ValueError):
        next_scan_time("0 9 * * *", "Unknown/Timezone", base)


@pytest.mark.asyncio
async def test_due_scan_refuses_expired_or_cross_tenant_authorization(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.services import recurring_scan as service
    from app.services.context import Principal

    now = dt.datetime(2026, 10, 5, 0, 0, tzinfo=dt.UTC)
    org_id = uuid.uuid4()
    principal = Principal.for_worker(
        organization_id=org_id, user_id=uuid.uuid4(), role=Role.OWNER,
    )
    profile = SimpleNamespace(organization_id=org_id, is_active=True, config={})
    schedule = SimpleNamespace(
        organization_id=org_id, authorization_expires_at=now,
        enabled=True, last_error_code=None,
    )

    async def forbidden(*args, **kwargs):
        raise AssertionError("unauthorized scheduled assessment was created")

    monkeypatch.setattr(service.assessment_service, "create_assessment", forbidden, raising=False)
    assert await service.execute_due_scan(
        object(), schedule, profile, principal, object(), now=now,
    ) is None
    assert schedule.enabled is False
    assert schedule.last_error_code == "authorization_expired"

    schedule.enabled = True
    schedule.authorization_expires_at = now + dt.timedelta(days=1)
    profile.organization_id = uuid.uuid4()
    assert await service.execute_due_scan(
        object(), schedule, profile, principal, object(), now=now,
    ) is None
    assert schedule.enabled is False
    assert schedule.last_error_code == "profile_tenant_mismatch"


@pytest.mark.asyncio
async def test_due_scan_revalidates_scope_and_stages_a_real_run(monkeypatch) -> None:
    import datetime as dt
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.services import recurring_scan as service
    from app.services.context import Principal

    now = dt.datetime(2026, 10, 5, 2, 0, tzinfo=dt.UTC)
    org_id = uuid.uuid4()
    principal = Principal.for_worker(
        organization_id=org_id, user_id=uuid.uuid4(), role=Role.OWNER,
    )
    profile = SimpleNamespace(
        organization_id=org_id, is_active=True,
        config={"scope": "external", "depth": "standard"},
    )
    schedule = SimpleNamespace(
        organization_id=org_id, targets=["example.com"], name="Daily scope",
        authorization_text="I am authorized to assess example.com",
        authorization_evidence="ENG-123",
        authorization_expires_at=now + dt.timedelta(days=1),
        cron_expression="0 9 * * *", timezone="Asia/Kolkata",
        enabled=True, last_error_code=None, next_run_at=now,
        last_run_at=None, last_assessment_id=None,
    )
    assessment = SimpleNamespace(id=uuid.uuid4(), title="Daily scope")
    payloads = []
    staged = []
    statements = []

    class _Session:
        @asynccontextmanager
        async def begin_nested(self):
            yield self

        async def flush(self):
            return None

        async def execute(self, statement):
            statements.append(statement)

    async def create(session, actor, payload, settings, *, authorization_method="explicit_ui"):
        payloads.append((payload, authorization_method))
        assert actor.organization_id == org_id
        return assessment

    def stage(session, actor, record):
        staged.append(record.id)
        return uuid.uuid4(), uuid.uuid4()

    monkeypatch.setattr(service.assessment_service, "create_assessment", create, raising=False)
    monkeypatch.setattr(service, "stage_assessment_run", stage, raising=False)
    result = await service.execute_due_scan(
        _Session(), schedule, profile, principal, object(), now=now,
    )
    assert result == assessment.id
    assert staged == [assessment.id]
    assert payloads[0][0].targets == ["example.com"]
    assert payloads[0][0].authorization.confirmed is True
    assert payloads[0][1] == "scheduled"
    assert schedule.last_assessment_id == assessment.id
    assert schedule.next_run_at == dt.datetime(2026, 10, 5, 3, 30, tzinfo=dt.UTC)
    assert statements == []


@pytest.mark.asyncio
async def test_assessment_creation_stamps_tenant_on_targets_and_append_only_authorizations(
    monkeypatch,
) -> None:
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.db.models.assessment import Assessment, AssessmentTarget, AuthorizationRecord
    from app.schemas.assessment import AssessmentCreateIn
    from app.services import assessment as service
    from app.services.context import Principal

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    organization = SimpleNamespace(entitlements={})
    validated = SimpleNamespace(
        raw="EXAMPLE.COM", canonical="example.com", type=SimpleNamespace(value="domain"),
        host="example.com", port=None, host_count=1, metadata={},
    )

    class _Session:
        def __init__(self):
            self.rows = []

        async def execute(self, statement):
            return SimpleNamespace(scalar_one=lambda: organization)

        def add(self, row):
            self.rows.append(row)

        async def flush(self):
            for row in self.rows:
                if isinstance(row, Assessment) and row.id is None:
                    row.id = uuid.uuid4()

    async def policy(*args):
        return object()

    async def zero(*args):
        return 0

    async def reference(*args):
        return 1

    async def record(*args, **kwargs):
        return None

    monkeypatch.setattr(service, "_policy_for", policy)
    monkeypatch.setattr(service, "_validate_targets", lambda targets, policy: [validated])
    monkeypatch.setattr(service, "_count_active_assessments", zero)
    monkeypatch.setattr(service, "_next_reference", reference)
    monkeypatch.setattr(service, "assert_active_assessment_capacity", lambda **kwargs: None)
    monkeypatch.setattr(service, "load_entitlements", lambda entitlements: object())
    monkeypatch.setattr(service.audit_service, "record", record)
    session = _Session()
    await service.create_assessment(
        session, principal,
        AssessmentCreateIn(
            targets=["EXAMPLE.COM"],
            authorization={"confirmed": True, "attestation_text": "Authorized"},
        ), object(),
        authorization_method="scheduled",
    )
    targets = [row for row in session.rows if isinstance(row, AssessmentTarget)]
    authorizations = [row for row in session.rows if isinstance(row, AuthorizationRecord)]
    assert len(targets) == len(authorizations) == 1
    assert targets[0].organization_id == org_id
    assert authorizations[0].organization_id == org_id
    assert authorizations[0].method == "scheduled"


@pytest.mark.asyncio
async def test_due_scan_sweep_checks_current_membership_and_profile_tenant(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from sqlalchemy.dialects import postgresql

    from app.db.enums import Role
    from app.services import recurring_scan as service

    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    schedule = SimpleNamespace(
        organization_id=org_id, created_by_id=user_id,
        enabled=True, last_error_code=None,
    )
    profile = SimpleNamespace(organization_id=org_id)
    statements = []
    called = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            if len(statements) == 1:
                return SimpleNamespace(all=lambda: [(schedule, profile)])
            return SimpleNamespace(scalar_one_or_none=lambda: Role.OWNER.value)

    async def execute(session, due, selected_profile, actor, settings, *, now):
        called.append(actor)
        return uuid.uuid4()

    monkeypatch.setattr(service, "execute_due_scan", execute)
    count = await service.run_due_scans(
        _Session(), object(), now=dt.datetime(2026, 10, 5, tzinfo=dt.UTC),
    )
    assert count == 1
    assert called[0].organization_id == org_id
    assert called[0].user_id == user_id
    assert called[0].role is Role.OWNER
    due_sql = str(statements[0].compile(dialect=postgresql.dialect()))
    member_sql = str(statements[1].compile(dialect=postgresql.dialect()))
    assert "scan_profiles.organization_id = recurring_scans.organization_id" in due_sql
    assert "SKIP LOCKED" in due_sql
    assert "memberships.organization_id" in member_sql
    assert "users.is_active IS true" in member_sql


@pytest.mark.asyncio
async def test_due_scan_disables_schedule_after_operator_loses_membership(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.services import recurring_scan as service

    schedule = SimpleNamespace(
        organization_id=uuid.uuid4(), created_by_id=uuid.uuid4(),
        enabled=True, last_error_code=None,
    )
    profile = SimpleNamespace(organization_id=schedule.organization_id)

    class _Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(all=lambda: [(schedule, profile)])
            return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def forbidden(*args, **kwargs):
        raise AssertionError("revoked operator launched a scan")

    monkeypatch.setattr(service, "execute_due_scan", forbidden)
    count = await service.run_due_scans(
        _Session(), object(), now=dt.datetime(2026, 10, 5, tzinfo=dt.UTC),
    )
    assert count == 0
    assert schedule.enabled is False
    assert schedule.last_error_code == "operator_inactive"


@pytest.mark.asyncio
async def test_profile_creation_stores_only_tenant_owned_scan_defaults() -> None:
    from app.db.enums import Role
    from app.schemas.assessment import ScanProfileCreateIn
    from app.services.context import Principal
    from app.services.recurring_scan import create_scan_profile

    class _Session:
        def __init__(self):
            self.added = []

        def add(self, row):
            self.added.append(row)

        async def flush(self):
            return None

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    session = _Session()
    profile = await create_scan_profile(
        session, principal,
        ScanProfileCreateIn(name="Standard web", scope="external", depth="standard"),
    )
    assert session.added == [profile]
    assert profile.organization_id == org_id
    assert profile.created_by_id == principal.user_id
    assert profile.config["scope"] == "external"
    assert "targets" not in profile.config
    assert "authorization" not in profile.config


@pytest.mark.asyncio
async def test_schedule_creation_rejects_expired_authority_and_minutely_cron(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.core.errors import InvalidConfigurationError
    from app.db.enums import Role
    from app.schemas.assessment import RecurringScanCreateIn
    from app.services import recurring_scan as service
    from app.services.context import Principal

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    profile_id = uuid.uuid4()
    profile = SimpleNamespace(id=profile_id, organization_id=org_id, is_active=True)

    class _Session:
        def __init__(self):
            self.added = []

        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: profile)

        def add(self, row):
            self.added.append(row)

        async def flush(self):
            return None

    async def policy(session, actor, settings):
        return object()

    monkeypatch.setattr(service.assessment_service, "_policy_for", policy)
    monkeypatch.setattr(service.assessment_service, "_validate_targets", lambda targets, policy: targets)
    now = dt.datetime.now(dt.UTC)
    common = {
        "name": "Daily scope", "profile_id": profile_id, "targets": ["example.com"],
        "timezone": "UTC",
        "authorization": {"confirmed": True, "attestation_text": "Authorized for example.com"},
    }
    session = _Session()
    with pytest.raises(InvalidConfigurationError, match="future"):
        await service.create_recurring_scan(
            session, principal,
            RecurringScanCreateIn(**common, cron_expression="0 9 * * *",
                                  authorization_expires_at=now - dt.timedelta(minutes=1)),
            object(),
        )
    with pytest.raises(InvalidConfigurationError, match="15 minutes"):
        await service.create_recurring_scan(
            session, principal,
            RecurringScanCreateIn(**common, cron_expression="* * * * *",
                                  authorization_expires_at=now + dt.timedelta(days=1)),
            object(),
        )
    assert session.added == []


@pytest.mark.asyncio
async def test_schedule_creation_rejects_cross_tenant_profile(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.core.errors import ResourceNotFoundError
    from app.db.enums import Role
    from app.schemas.assessment import RecurringScanCreateIn
    from app.services import recurring_scan as service
    from app.services.context import Principal

    tenant_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=tenant_id, role=Role.OWNER)
    profile_id = uuid.uuid4()

    class _Session:
        def __init__(self):
            self.added = []
            self.statement = None

        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalar_one_or_none=lambda: None)

        def add(self, row):
            self.added.append(row)

    session = _Session()
    payload = RecurringScanCreateIn(
        name="Daily", profile_id=profile_id, targets=["example.com"],
        cron_expression="0 9 * * *", timezone="UTC",
        authorization={"confirmed": True, "attestation_text": "Authorized"},
        authorization_expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
    )
    with pytest.raises(ResourceNotFoundError):
        await service.create_recurring_scan(session, principal, payload, object())
    sql = str(session.statement.compile(compile_kwargs={"literal_binds": True}))
    assert tenant_id.hex in sql
    assert profile_id.hex in sql
    assert session.added == []


@pytest.mark.asyncio
async def test_schedule_creation_canonicalizes_targets_and_stages_tenant_row(monkeypatch) -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.schemas.assessment import RecurringScanCreateIn
    from app.services import recurring_scan as service
    from app.services.context import Principal

    org_id = uuid.uuid4()
    profile_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    profile = SimpleNamespace(id=profile_id, organization_id=org_id, is_active=True)

    class _Session:
        def __init__(self):
            self.added = []

        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: profile)

        def add(self, row):
            self.added.append(row)

        async def flush(self):
            return None

    async def policy(session, principal, settings):
        return object()

    monkeypatch.setattr(service.assessment_service, "_policy_for", policy)
    monkeypatch.setattr(
        service.assessment_service, "_validate_targets",
        lambda targets, policy: [SimpleNamespace(canonical="example.com")],
    )
    session = _Session()
    result = await service.create_recurring_scan(
        session, principal,
        RecurringScanCreateIn(
            name="Daily", profile_id=profile_id, targets=["EXAMPLE.COM"],
            cron_expression="0 9 * * *", timezone="UTC",
            authorization={"confirmed": True, "attestation_text": "Authorized"},
            authorization_expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
        ), object(),
    )
    assert session.added == [result]
    assert result.organization_id == org_id
    assert result.targets == ["example.com"]
    assert result.created_by_id == principal.user_id


@pytest.mark.asyncio
async def test_pause_schedule_tenant_scopes_lookup() -> None:
    from types import SimpleNamespace

    from app.api.v1.assessments import pause_recurring_scan
    from app.core.errors import ResourceNotFoundError
    from app.db.enums import Role
    from app.services.context import Principal

    org_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)

    class _Session:
        def __init__(self):
            self.statement = None
            self.committed = False

        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalar_one_or_none=lambda: None)

        async def commit(self):
            self.committed = True

    session = _Session()
    with pytest.raises(ResourceNotFoundError):
        await pause_recurring_scan(schedule_id, principal, session)
    sql = str(session.statement.compile(compile_kwargs={"literal_binds": True}))
    assert org_id.hex in sql
    assert schedule_id.hex in sql
    assert not session.committed


@pytest.mark.asyncio
async def test_due_scan_claim_fairly_caps_one_tenant_per_sweep() -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.services.recurring_scan import run_due_scans

    class _Session:
        def __init__(self):
            self.statement = None

        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(all=lambda: [])

    session = _Session()
    assert await run_due_scans(
        session, object(), now=dt.datetime.now(dt.UTC), limit=10,
    ) == 0
    sql = str(session.statement).lower()
    assert "row_number() over" in sql
    assert "partition by recurring_scans.organization_id" in sql


@pytest.mark.asyncio
async def test_worker_liveness_expires_crashed_processes_and_reports_pool_status() -> None:
    import datetime as dt

    from app.api.v1.health import _probe_worker
    from app.worker.worker import AgentWorker

    class _Redis:
        def __init__(self):
            self.members: dict[str, float] = {}

        async def zadd(self, key, members):
            self.members.update(members)
            return 1

        async def zremrangebyscore(self, key, minimum, maximum):
            expired = [name for name, score in self.members.items() if score <= maximum]
            for name in expired:
                self.members.pop(name)
            return len(expired)

        async def zcount(self, key, minimum, maximum):
            return sum(minimum <= score <= maximum for score in self.members.values())

        async def zrem(self, key, member):
            self.members.pop(member, None)
            return 1

    redis = _Redis()
    worker = object.__new__(AgentWorker)
    worker._redis = redis
    worker._stream = "runs"
    worker._worker_id = "worker-live"
    now = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
    redis.members["worker-crashed"] = now.timestamp() - 180
    await worker._pulse_liveness(now=now)
    assert redis.members == {"worker-live": now.timestamp()}
    live = await _probe_worker(redis, "runs", now=now)
    assert live.healthy is True
    assert live.detail == "1 active"
    stale = await _probe_worker(redis, "runs", now=now + dt.timedelta(minutes=3))
    assert stale.healthy is False
    assert stale.detail == "0 active"
    await worker._remove_liveness()
    assert redis.members == {}


@pytest.mark.asyncio
async def test_worker_metrics_report_only_requesting_tenants_jobs() -> None:
    from types import SimpleNamespace

    from app.api.v1.assessments import worker_metrics
    from app.db.enums import Role
    from app.services.context import Principal

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)

    class _Session:
        def __init__(self):
            self.statements = []
            self.results = [
                [("queued", 3), ("running", 1), ("failed", 2)],
                [("pending", 4)],
                [("QUEUED", 7), ("RUNNING", 1)],
            ]

        async def execute(self, statement):
            self.statements.append(statement)
            rows = self.results.pop(0)
            return SimpleNamespace(all=lambda: rows)

    session = _Session()
    result = await worker_metrics(principal, session)
    assert result.runs == {"queued": 3, "running": 1, "failed": 2}
    assert result.pending_dispatches == 4
    assert result.scanner_jobs == {"QUEUED": 7, "RUNNING": 1}
    assert len(session.statements) == 3
    for statement in session.statements:
        sql = str(statement.compile(compile_kwargs={"literal_binds": True}))
        assert org_id.hex in sql


@pytest.mark.asyncio
async def test_tenant_scanner_limit_is_enforced_below_deployment_limit(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.core.config import Settings
    from app.services import job as service

    class _Pipeline:
        def incr(self, key):
            return self

        def expire(self, key, ttl):
            return self

        async def execute(self):
            return [2, True, 2, True]

    class _Redis:
        def pipeline(self):
            return _Pipeline()

    released = []

    async def release(redis, settings, organization_id):
        released.append(organization_id)

    monkeypatch.setattr(service, "release_slot", release)
    organization_id = uuid.uuid4()
    admitted = await service.claim_slot(
        _Redis(), Settings(), organization_id, organization_limit=1,
    )
    assert admitted is False
    assert released == [organization_id]

    org = SimpleNamespace(is_active=True, max_concurrent_scanner_jobs=1)

    class _Session:
        async def get(self, model, key):
            assert key == organization_id
            return org

    assert await service.organization_scanner_limit(
        _Session(), organization_id, Settings(),
    ) == 1
