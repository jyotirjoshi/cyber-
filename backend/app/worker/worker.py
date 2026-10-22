"""The Redis Streams consumer that drives assessments to completion (FR-033, FR-037, FR-040).

The API never runs a graph in a request: it records an :class:`~app.db.models.agent.AgentRun`
and enqueues a :class:`~app.worker.protocol.RunRequest` on a stream.  This worker is the pool
that consumes that stream.  One :class:`AgentWorker` is one process; you scale by running more
of them, and a Redis *consumer group* hands each message to exactly one worker.  Everything
hard about this file is a consequence of one requirement -- **an assessment must survive the
worker running it crashing** (FR-033) -- and one invariant that makes that possible:

    **Ack after settle.**  A message is acknowledged only once its run has reached a settled
    state -- interrupted at the approval gate, completed, failed, or cancelled.  While a run is
    in flight its message stays in the group's pending-entries list (PEL), unacknowledged.  If
    the worker dies mid-run, the message is still pending, and another worker reclaims it and
    resumes from the LangGraph checkpoint.  A worker that shuts down cleanly mid-run does the
    same thing on purpose: it leaves the message pending rather than acking, so the run is
    picked up elsewhere.

Two consequences of that invariant drive the rest of the design:

* A *healthy* long run holds its message in the PEL for the whole run -- which can be hours.
  ``XAUTOCLAIM`` reclaims any entry idle longer than ``claim_idle_ms`` (two minutes), so it
  will grab a perfectly healthy run's message.  The reclaiming worker must therefore not take
  the message as licence to re-drive the run: it checks the run's *heartbeat* (stamped every
  few seconds by the owner while it works) and, if fresh, **defers** -- leaves the message
  pending, drives nothing.  Only a stale heartbeat means the owner is actually gone.  The
  run's own database status, never the queue message, is the authority for what to do next
  (the same rule the approval gate follows, FR-011); :meth:`AgentRunner.advance` embodies it,
  and this worker's job is to establish liveness before calling it.

* Acknowledgement is group-scoped: ``XACK`` removes the entry from the group PEL no matter
  which consumer currently holds it.  So the owner can settle its run and ack its message even
  after ``XAUTOCLAIM`` moved that entry to another consumer -- the reclaimer's copy simply
  evaporates.  This is why the defer-on-fresh-heartbeat dance is safe rather than a leak.

**Cancellation (FR-037)** comes from the operator, out of band, as an assessment moved to
``cancelling`` by the API.  A per-run monitor task polls for that while the graph runs; on
seeing it, it cancels the in-flight ``advance``.  A ``CancelledError`` out of ``advance`` is
then disambiguated by cause: our monitor (operator cancel -> finalize the cancellation, tell
the owner, ack) versus process shutdown (leave pending for reclaim, propagate).  The graph's
own nodes unwind their Docker containers on cancellation; this worker flags the scanner jobs
(:func:`cancel_jobs_for_assessment`) and moves the assessment to ``cancelled``.

**Orphaned scanner jobs (FR-040)** are a separate reclaim from run messages: a maintenance
task runs :func:`reclaim_orphans` on a timer to fail ``ScannerJob`` rows whose own worker
stopped heartbeating.  It is independent of run dispatch so a single busy worker still reaps
them.

**No secret, host, finding title or CVE is logged (SEC-002).**  Every log line here carries
ids, statuses, counts and exception *type names* -- never ``str(exc)`` on a failure path, and
never the principal payload a message carried.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, cast

import structlog
from redis.asyncio.client import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.registry import AgentDeps
from app.agent.runner import AgentRunner, RunOutcome
from app.core.config import Settings
from app.core.errors import ConflictError, CynuxError, PermissionDeniedError
from app.db.enums import AgentRunStatus, AssessmentStatus, ReportFormat, ReportStatus
from app.db.models.agent import AgentRun
from app.db.models.agent_task import AgentTask
from app.db.models.assessment import Assessment
from app.db.models.report import Report
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.integrations.storage import ObjectStorage
from app.reporting.generate import generate as generate_report
from app.services.agent_action import execute_approved_batch, settle_assessment_action_receipt
from app.services.agent_task_executor import recover_all_stale_tasks
from app.services.asm_discovery import run_due_surfaces
from app.services.assessment import transition
from app.services.attack_simulation import execute_pending_techniques, run_due_campaigns
from app.services.automation import execute_pending_automations, queue_due_automation_schedules
from app.services.canonical_intel_refresh import refresh_stale_intel_batch
from app.services.canonical_risk_refresh import refresh_stale_risk_batch
from app.services.compliance import expire_compliance_records
from app.services.context import Principal
from app.services.custom_connector import run_pending_connector_runs
from app.services.integration_sync import run_due_integration_syncs
from app.services.job import cancel_jobs_for_assessment, reclaim_orphans
from app.services.knowledge_indexer import run_due_knowledge_indexing
from app.services.notification import deliver_pending
from app.services.recurring_scan import run_due_scans
from app.services.remediation_governance import (
    complete_assessment_retest,
    complete_retest,
    expire_risk_acceptances,
)
from app.services.report import reconcile_report_distributions, run_due_report_schedules
from app.services.sla_escalation import emit_overdue_sla_escalations
from app.services.ticket import refresh_due_ticket_statuses
from app.services.workflow import execute_due_workflows, queue_due_workflow_schedules
from app.worker.dispatch import deliver_pending_dispatches
from app.worker.protocol import (
    WORKER_LIVENESS_MAX_AGE_SECONDS,
    RunAction,
    RunRequest,
    worker_liveness_key,
)

log = structlog.get_logger(__name__)

#: Run statuses with nothing left to drive. Mirrors the runner's own terminal set (kept local
#: rather than imported: it is private there, and the worker's need for it is its own).
_TERMINAL_RUN_STATUSES: frozenset[AgentRunStatus] = frozenset(
    {
        AgentRunStatus.COMPLETED,
        AgentRunStatus.PARTIALLY_COMPLETED,
        AgentRunStatus.BLOCKED,
        AgentRunStatus.FAILED,
        AgentRunStatus.CANCELLED,
    }
)

#: How long ``XREADGROUP`` blocks waiting for a new message. Bounds shutdown latency when the
#: worker is idle: a stop request is noticed within this window (an in-flight run is cancelled
#: immediately, so this only gates the idle case).
_READ_BLOCK_MS = 5_000

#: One process drives one run at a time. Claiming more would pin the extra entries in
#: this consumer's PEL for the duration of a long scan instead of offering them to peers.
_READ_BATCH = 1
_RECLAIM_BATCH = 1

#: Cadence of the per-run monitor: it stamps the run heartbeat (liveness for reclaim) and polls
#: for an operator cancellation. Far below ``claim_idle_ms`` so a healthy run's heartbeat never
#: looks stale, and low enough that a cancel is honoured within a few seconds.
_MONITOR_INTERVAL_SECONDS = 5.0

#: Cadence of the scanner-orphan sweep (FR-040). Independent of run dispatch.
_MAINTENANCE_INTERVAL_SECONDS = 30.0

#: Backoff after a Redis read error, so a transient outage does not become a hot loop.
_ERROR_BACKOFF_SECONDS = 2.0
_RETRY_BASE_SECONDS = 120
_RETRY_MAX_SECONDS = 1800
_RETRY_STATE_TTL_SECONDS = 7 * 24 * 60 * 60
_MAX_RUN_ATTEMPTS = 5
_RUN_SLOT_LEASE_MS = 90_000
_RUN_SLOT_CLAIM_LUA = """
local key, run_key, member = KEYS[1], KEYS[2], ARGV[4]
local now, lease, limit = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
local owner = redis.call('GET', run_key)
if owner and owner ~= member then
    return 0
end
if not redis.call('ZSCORE', key, member) and redis.call('ZCARD', key) >= limit then
    return 0
end
redis.call('ZADD', key, now + lease, member)
redis.call('PEXPIRE', key, lease * 2)
redis.call('SET', run_key, member, 'PX', lease)
return 1
"""
_RUN_SLOT_RENEW_LUA = """
local key, run_key, member = KEYS[1], KEYS[2], ARGV[3]
local now, lease = tonumber(ARGV[1]), tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
if redis.call('GET', run_key) ~= member or not redis.call('ZSCORE', key, member) then
    return 0
end
redis.call('ZADD', key, now + lease, member)
redis.call('PEXPIRE', key, lease * 2)
redis.call('PEXPIRE', run_key, lease)
return 1
"""
_RUN_SLOT_RELEASE_LUA = """
redis.call('ZREM', KEYS[1], ARGV[1])
if redis.call('GET', KEYS[2]) == ARGV[1] then
    redis.call('DEL', KEYS[2])
end
return 1
"""


@dataclass(frozen=True, slots=True)
class _RunContext:
    """The run and assessment facts a dispatch decision needs, read in one transaction.

    A snapshot, not a live row: every field is a scalar copied out of the session so the
    dispatch logic can branch without holding a transaction open across the (long) graph run.
    """

    run_status: AgentRunStatus
    organization_id: uuid.UUID
    assessment_id: uuid.UUID | None
    session_id: uuid.UUID | None
    heartbeat_at: dt.datetime | None
    assessment_status: AssessmentStatus | None


@dataclass(slots=True)
class _CancelState:
    """Shared between a run and its monitor to disambiguate why ``advance`` was cancelled.

    ``operator`` is set by the monitor the instant it decides to cancel for an operator
    cancellation; ``stop`` tells the monitor to exit once the run has settled.  Not frozen: the
    monitor flips ``operator`` in place, which is the whole point.
    """

    operator: bool = False
    lease_lost: bool = False
    stop: asyncio.Event = field(default_factory=asyncio.Event)


class AgentWorker:
    """Consume run requests and drive each to a settled state, crash-safely.

    Built once per process over a shared :class:`AgentDeps` and a single :class:`AgentRunner`
    (which owns the per-worker LangGraph checkpointer).  :meth:`run` is the entry point; a
    signal handler calls :meth:`request_stop` for graceful shutdown.
    """

    __slots__ = (
        "_consumer",
        "_current_advance",
        "_deps",
        "_group",
        "_redis",
        "_runner",
        "_settings",
        "_stopping",
        "_stream",
        "_task_concurrency",
        "_task_handler",
        "_task_slots",
        "_inflight_tasks",
        "_worker_id",
    )

    def __init__(
        self,
        settings: Settings,
        redis: Redis,
        deps: AgentDeps,
        runner: AgentRunner,
        *,
        worker_id: str,
        task_handler: Any | None = None,
    ) -> None:
        self._settings = settings
        self._redis = redis
        self._deps = deps
        self._runner = runner
        self._worker_id = worker_id
        self._task_handler = task_handler
        #: The consumer name inside the group. One per process, so the PEL attributes each
        #: in-flight message to the worker holding it and reclaim can find a dead one's work.
        self._consumer = worker_id
        self._stream = settings.redis.stream
        self._group = settings.redis.consumer_group
        self._stopping = False
        self._current_advance: asyncio.Task[RunOutcome] | None = None
        self._task_concurrency = settings.agent.worker_max_concurrency
        self._task_slots = asyncio.Semaphore(self._task_concurrency)
        self._inflight_tasks: set[asyncio.Task[None]] = set()

    # -- lifecycle -----------------------------------------------------------

    async def run(self) -> None:
        """Set up the consumer group, then consume until asked to stop.

        The maintenance sweep runs as a sibling task so it keeps reaping orphaned scanner jobs
        even while this loop is blocked driving a single long run.  A ``CancelledError`` raised
        into the loop while stopping is the in-flight run being cancelled for shutdown -- its
        message is intentionally left pending for reclaim -- so it exits the loop cleanly rather
        than crashing the process.
        """
        await self._ensure_group()
        await self._pulse_liveness()
        log.info(
            "worker.started",
            worker_id=self._worker_id,
            stream=self._stream,
            group=self._group,
        )
        maintenance = asyncio.create_task(self._maintenance_loop(), name="worker-maintenance")
        try:
            while not self._stopping:
                try:
                    await self._consume_once()
                except asyncio.CancelledError:
                    if self._stopping:
                        break
                    raise
        finally:
            maintenance.cancel()
            await asyncio.gather(maintenance, return_exceptions=True)
            await self._drain_task_dispatches(cancel=True)
            try:
                await self._remove_liveness()
            except RedisError as exc:
                log.warning("worker.liveness_remove_failed", error=type(exc).__name__)
            log.info("worker.stopped", worker_id=self._worker_id)

    def request_stop(self) -> None:
        """Ask the worker to stop; safe to call from a signal handler (no awaits).

        Sets the stop flag -- the consume loop notices it within one read block -- and cancels
        any in-flight ``advance`` immediately.  Cancelling the run rather than draining it is
        deliberate: a run can take hours, and its checkpoint means another worker resumes it
        with no lost work (FR-033), so a prompt shutdown costs nothing.
        """
        if self._stopping:
            return
        self._stopping = True
        log.info("worker.stop_requested", worker_id=self._worker_id)
        task = self._current_advance
        if task is not None and not task.done():
            task.cancel()
        for inflight in tuple(self._inflight_tasks):
            if not inflight.done():
                inflight.cancel()

    async def _ensure_group(self) -> None:
        """Create the consumer group (and the stream), tolerating a group that exists.

        ``id="0"`` so the group also drains anything already on the stream when a fresh
        deployment first starts its workers; ``mkstream`` so the first worker up does not error
        on a stream no publisher has created yet.  ``BUSYGROUP`` is the expected outcome on
        every start after the first and is not an error.
        """
        try:
            await cast(
                Awaitable[Any],
                self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True),
            )
            log.info("worker.group_created", stream=self._stream, group=self._group)
        except ResponseError as exc:
            # The message is a Redis protocol string ("BUSYGROUP ..."), not a secret; matching
            # on it is how redis-py itself distinguishes this benign case.
            if "BUSYGROUP" not in str(exc):
                raise
            log.debug("worker.group_exists", stream=self._stream, group=self._group)

    # -- consume -------------------------------------------------------------

    async def _consume_once(self) -> None:
        """One pass: reclaim crashed workers' pending entries, then read new ones.

        Reclaim runs first and only here -- i.e. only when the worker is free, because a busy
        worker is inside ``advance`` and never reaches this line -- so a single worker never
        reclaims work it cannot currently run.  The blocking read then parks the worker until a
        new run arrives or the block elapses.
        """
        await self._reclaim_pending()
        if self._stopping:
            return
        try:
            response = await cast(
                Awaitable[Any],
                self._redis.xreadgroup(
                    self._group,
                    self._consumer,
                    {self._stream: ">"},
                    count=_READ_BATCH,
                    block=_READ_BLOCK_MS,
                ),
            )
        except RedisError as exc:
            log.warning("worker.read_failed", error=type(exc).__name__)
            await asyncio.sleep(_ERROR_BACKOFF_SECONDS)
            return
        for _stream_name, messages in response or []:
            for message_id, fields in messages:
                if self._stopping:
                    return
                await self._dispatch_entry(message_id, fields, reclaimed=False)

    async def _reclaim_pending(self) -> None:
        """Claim pending entries idle longer than ``claim_idle_ms`` and dispatch them.

        Best-effort: a Redis error here is logged and skipped, because the next pass retries and
        a failed reclaim must never take down the consume loop.  A claimed entry whose stream
        data was trimmed away comes back with no fields -- there is nothing to run, so it is
        acked to evict it from the PEL.
        """
        try:
            response = await cast(
                Awaitable[Any],
                self._redis.xautoclaim(
                    self._stream,
                    self._group,
                    self._consumer,
                    min_idle_time=self._settings.redis.claim_idle_ms,
                    start_id="0-0",
                    count=_RECLAIM_BATCH,
                ),
            )
        except RedisError as exc:
            log.warning("worker.reclaim_failed", error=type(exc).__name__)
            return
        # parse_xautoclaim -> [cursor, [(id, {fields}), ...], [deleted_ids]]; the deleted list is
        # absent on Redis < 7, so index defensively rather than unpacking a fixed arity.
        messages = response[1] if isinstance(response, list | tuple) and len(response) > 1 else []
        for message_id, fields in messages:
            if self._stopping:
                return
            if not fields:
                await self._ack(message_id)
                continue
            await self._dispatch_entry(message_id, fields, reclaimed=True)

    async def _dispatch_entry(
        self, message_id: str, fields: Mapping[str, str], *, reclaimed: bool
    ) -> None:
        """Dispatch one stream entry, parallelizing only durable DAG task messages.

        Assessment and supervisor messages continue through the single-run path because
        ``_current_advance`` is intentionally process-local state. Generic DAG tasks own
        independent database leases, so they can safely execute in parallel up to the hard
        worker bound. Waiting on the semaphore applies backpressure instead of claiming an
        unbounded number of Redis entries.
        """

        if fields.get("action") != RunAction.TASK.value:
            await self._dispatch(message_id, fields, reclaimed=reclaimed)
            return
        await self._task_slots.acquire()
        if self._stopping:
            self._task_slots.release()
            return
        task = asyncio.create_task(
            self._dispatch_task_entry(message_id, fields, reclaimed=reclaimed),
            name=f"agent-task-{message_id}",
        )
        self._inflight_tasks.add(task)
        task.add_done_callback(self._task_dispatch_done)

    async def _dispatch_task_entry(
        self, message_id: str, fields: Mapping[str, str], *, reclaimed: bool
    ) -> None:
        try:
            await self._dispatch(message_id, fields, reclaimed=reclaimed)
        finally:
            self._task_slots.release()

    def _task_dispatch_done(self, task: asyncio.Task[None]) -> None:
        self._inflight_tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log.error(
                "worker.task_dispatch_failed",
                worker_id=self._worker_id,
                error=type(error).__name__,
            )

    async def _drain_task_dispatches(self, *, cancel: bool) -> None:
        tasks = tuple(self._inflight_tasks)
        if cancel:
            for task in tasks:
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _dispatch(
        self, message_id: str, fields: Mapping[str, str], *, reclaimed: bool
    ) -> None:
        """Decide what a single message means and act on it.

        The order of the guards is load-bearing: a malformed message is dropped before anything
        touches the database; a reclaimed message whose run is still being heartbeated is
        deferred before we consider its assessment (the live owner will handle a cancel too); an
        assessment being cancelled or already terminal is settled without running the graph; and
        only a genuinely runnable message reaches :meth:`_run`.
        """
        try:
            request = RunRequest.from_fields(fields)
        except ValueError as exc:
            # Preserve only metadata, never the possibly secret-bearing payload.
            log.warning("worker.poison_message", message_id=message_id, error=type(exc).__name__)
            if await self._dead_letter(message_id, "invalid_request"):
                await self._ack(message_id)
            return

        if request.action is RunAction.TASK:
            await self._dispatch_agent_task(message_id, request)
            return
        if request.action is RunAction.SUPERVISE:
            await self._dispatch_supervisor(message_id, request)
            return

        run_id = request.run_id
        ctx = await self._load_context(run_id, message_id)
        if ctx is None:
            log.warning("worker.run_missing", run_id=str(run_id), message_id=message_id)
            if await self._dead_letter(message_id, "run_missing"):
                await self._ack(message_id)
            return

        if ctx.run_status is AgentRunStatus.RUNNING and self._heartbeat_fresh(ctx.heartbeat_at):
            # A reclaimed original message may now belong to a healthy owner; leave it
            # pending so that owner can acknowledge it. A separate fresh delivery is a
            # duplicate and must not start a second graph invocation.
            if reclaimed:
                log.debug("worker.reclaim_deferred", run_id=str(run_id), message_id=message_id)
            else:
                log.info("worker.duplicate_deferred", run_id=str(run_id), message_id=message_id)
                await self._ack(message_id)
            return

        if ctx.assessment_status is AssessmentStatus.CANCELLING:
            await self._cancel_teardown(run_id, ctx, self._principal_of(request))
            await self._ack(message_id)
            return

        if ctx.assessment_status is not None and ctx.assessment_status.is_terminal:
            await self._settle_orphaned_run(run_id, ctx)
            await self._ack(message_id)
            return

        try:
            if not await self._retry_due(message_id):
                log.debug("worker.retry_deferred", run_id=str(run_id), message_id=message_id)
                return
            if not await self._claim_run_slot(ctx.organization_id, run_id):
                log.info(
                    "worker.tenant_capacity_deferred", organization_id=str(ctx.organization_id)
                )
                return
        except RedisError as exc:
            log.warning("worker.run_admission_failed", run_id=str(run_id), error=type(exc).__name__)
            return
        try:
            try:
                attempts = await self._begin_attempt(message_id)
            except RedisError as exc:
                log.warning(
                    "worker.retry_state_failed", run_id=str(run_id), error=type(exc).__name__
                )
                return
            if attempts > _MAX_RUN_ATTEMPTS:
                if await self._dead_letter(message_id, "retry_exhausted"):
                    try:
                        await self._settle_retry_exhausted(run_id, ctx)
                    except Exception as exc:
                        log.warning(
                            "worker.retry_settle_failed",
                            run_id=str(run_id),
                            error=type(exc).__name__,
                        )
                        return
                    await self._ack(message_id)
                return

            await self._run(message_id, run_id, ctx, self._principal_of(request), attempts)
        finally:
            await self._release_run_slot(ctx.organization_id, run_id)

    async def _dispatch_agent_task(self, message_id: str, request: RunRequest) -> None:
        """Execute one task message when the configured orchestrator runtime is enabled."""
        if request.task_id is None:  # guarded by RunRequest, defensive at the boundary
            if await self._dead_letter(message_id, "task_id_missing"):
                await self._ack(message_id)
            return
        handler = self._task_handler
        if handler is None:
            log.warning(
                "worker.task_runtime_unavailable",
                run_id=str(request.run_id),
                task_id=str(request.task_id),
            )
            return
        ctx = await self._load_context(request.run_id, message_id)
        if ctx is None:
            if await self._dead_letter(message_id, "run_missing"):
                await self._ack(message_id)
            return
        from app.db.session import get_sessionmaker
        from app.services.agent_task_executor import execute_task

        await self._warn_if_task_queue_is_slow(ctx.organization_id, request.task_id)
        settled = await execute_task(
            ctx.organization_id,
            request.task_id,
            get_sessionmaker(self._settings),
            handler,
            worker_id=self._worker_id,
            lease_seconds=self._settings.agent.task_lease_seconds,
        )
        if settled:
            await self._ack(message_id)

    async def _warn_if_task_queue_is_slow(
        self, organization_id: uuid.UUID, task_id: uuid.UUID
    ) -> None:
        async with session_scope(self._settings) as session:
            created_at = await session.scalar(
                tenant_select(AgentTask, organization_id)
                .with_only_columns(AgentTask.created_at)
                .where(AgentTask.id == task_id)
            )
        if created_at is None:
            return
        queued_at = created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=dt.UTC)
        latency = max(0.0, (_now() - queued_at).total_seconds())
        if latency >= self._settings.agent.queue_latency_alert_seconds:
            log.warning(
                "worker.agent_task_queue_latency_high",
                organization_id=str(organization_id),
                task_id=str(task_id),
                queue_latency_seconds=round(latency, 3),
            )

    async def _dispatch_supervisor(self, message_id: str, request: RunRequest) -> None:
        """Materialize a generic objective exactly once, leaving transient failures pending."""

        ctx = await self._load_context(request.run_id, message_id)
        if ctx is None:
            if await self._dead_letter(message_id, "run_missing"):
                await self._ack(message_id)
            return
        from app.db.session import get_sessionmaker
        from app.services.multi_agent_runtime import execute_supervisor_run

        try:
            await execute_supervisor_run(
                self._settings,
                self._deps,
                request.run_id,
                get_sessionmaker(self._settings),
            )
        except (ConflictError, PermissionDeniedError) as exc:
            log.warning(
                "worker.supervisor_rejected",
                run_id=str(request.run_id),
                error=type(exc).__name__,
            )
            async with session_scope(self._settings) as session:
                run = await session.get(AgentRun, request.run_id)
                if run is not None and run.status not in {
                    AgentRunStatus.COMPLETED.value,
                    AgentRunStatus.PARTIALLY_COMPLETED.value,
                    AgentRunStatus.BLOCKED.value,
                    AgentRunStatus.FAILED.value,
                    AgentRunStatus.CANCELLED.value,
                }:
                    run.status = AgentRunStatus.BLOCKED.value
                    run.failure_category = "policy"
                    run.failure_reason = "The multi-agent supervisor could not authorize this run."
                    run.stop_reason = "policy_blocked"
                    run.completed_at = _now()
                    await session.commit()
            await self._ack(message_id)
            return
        except Exception as exc:
            log.warning(
                "worker.supervisor_retry_pending",
                run_id=str(request.run_id),
                error=type(exc).__name__,
            )
            return
        await self._ack(message_id)

    def _run_slot_key(self, organization_id: uuid.UUID) -> str:
        return f"{self._stream}:run-slots:{organization_id}"

    def _run_slot_member(self, run_id: uuid.UUID) -> str:
        return f"{self._worker_id}:{run_id}"

    def _run_lock_key(self, organization_id: uuid.UUID, run_id: uuid.UUID) -> str:
        return f"{self._stream}:run-lock:{organization_id}:{run_id}"

    async def _claim_run_slot(self, organization_id: uuid.UUID, run_id: uuid.UUID) -> bool:
        now_ms = int(_now().timestamp() * 1000)
        accepted = await cast(
            Awaitable[int],
            self._redis.eval(
                _RUN_SLOT_CLAIM_LUA,
                2,
                self._run_slot_key(organization_id),
                self._run_lock_key(organization_id, run_id),
                now_ms,
                _RUN_SLOT_LEASE_MS,
                self._settings.agent.max_concurrent_runs_per_org,
                self._run_slot_member(run_id),
            ),
        )
        return int(accepted) == 1

    async def _release_run_slot(self, organization_id: uuid.UUID, run_id: uuid.UUID) -> None:
        try:
            await cast(
                Awaitable[int],
                self._redis.eval(
                    _RUN_SLOT_RELEASE_LUA,
                    2,
                    self._run_slot_key(organization_id),
                    self._run_lock_key(organization_id, run_id),
                    self._run_slot_member(run_id),
                ),
            )
        except RedisError as exc:
            log.warning("worker.run_slot_release_failed", error=type(exc).__name__)

    async def _renew_run_slot(self, organization_id: uuid.UUID, run_id: uuid.UUID) -> bool:
        renewed = await cast(
            Awaitable[int],
            self._redis.eval(
                _RUN_SLOT_RENEW_LUA,
                2,
                self._run_slot_key(organization_id),
                self._run_lock_key(organization_id, run_id),
                int(_now().timestamp() * 1000),
                _RUN_SLOT_LEASE_MS,
                self._run_slot_member(run_id),
            ),
        )
        return int(renewed) == 1

    async def _run(
        self,
        message_id: str,
        run_id: uuid.UUID,
        ctx: _RunContext,
        principal: Principal | None,
        attempts: int = 1,
    ) -> None:
        """Drive one run under a heartbeat + cancel monitor, then ack iff it settled.

        ``advance`` runs as its own task so the monitor can cancel *it* (an operator
        cancellation) and so shutdown can cancel it via :meth:`request_stop`.  The two causes of
        a ``CancelledError`` are told apart by :attr:`_CancelState.operator`: our monitor set it,
        or it was shutdown.  Every settled outcome and every benign race acks; an unexpected
        error leaves the message pending so reclaim retries it once the fault clears.
        """
        canceller = _CancelState()
        advance_task = asyncio.create_task(
            self._runner.advance(run_id, principal=principal), name=f"advance-{run_id}"
        )
        self._current_advance = advance_task
        monitor = asyncio.create_task(
            self._monitor(run_id, ctx, advance_task, canceller), name=f"monitor-{run_id}"
        )
        try:
            outcome = await advance_task
        except asyncio.CancelledError:
            if canceller.operator and not self._stopping:
                # Operator cancellation (FR-037): finish it even though we are unwinding a
                # cancelled task -- shield the teardown so a racing shutdown cannot truncate it.
                await asyncio.shield(self._cancel_teardown(run_id, ctx, principal))
                await self._ack(message_id)
                return
            if canceller.lease_lost and not self._stopping:
                log.warning("worker.run_lease_lost", run_id=str(run_id))
                try:
                    await self._schedule_retry(message_id, attempts)
                except RedisError as exc:
                    log.warning("worker.retry_schedule_failed", error=type(exc).__name__)
                return
            # Shutdown: leave the run RUNNING and its message pending for reclaim (FR-033).
            log.info("worker.run_shutdown_interrupt", run_id=str(run_id))
            raise
        except ConflictError:
            # A duplicate delivery or a settle that raced in from another worker: benign under
            # at-least-once delivery. Ack; the real owner drove the run.
            log.info("worker.run_duplicate", run_id=str(run_id))
            await self._ack(message_id)
            return
        except CynuxError as exc:
            # A permanently unprocessable run must be inspectable after it leaves the queue.
            log.warning(
                "worker.run_unprocessable",
                run_id=str(run_id),
                error_code=exc.code,
                error_category=exc.category.value,
            )
            if await self._dead_letter(message_id, "unprocessable_run"):
                try:
                    await self._settle_retry_exhausted(run_id, ctx)
                except Exception as settle_exc:
                    log.warning(
                        "worker.unprocessable_settle_failed",
                        run_id=str(run_id),
                        error=type(settle_exc).__name__,
                    )
                    return
                await self._ack(message_id)
            return
        except Exception as exc:
            # advance settles graph failures internally, so this is an unexpected fault in its
            # own bookkeeping (e.g. the database blinked while settling). Do NOT ack -- leave the
            # message pending so reclaim retries once the fault clears.
            log.error("worker.run_error", run_id=str(run_id), exc_type=type(exc).__name__)
            try:
                await self._schedule_retry(message_id, attempts)
            except RedisError as retry_exc:
                log.warning(
                    "worker.retry_schedule_failed",
                    run_id=str(run_id),
                    error=type(retry_exc).__name__,
                )
            return
        finally:
            canceller.stop.set()
            monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)
            self._current_advance = None

        log.info("worker.run_settled", run_id=str(run_id), status=outcome.status.value)
        if outcome.status in {
            AgentRunStatus.COMPLETED,
            AgentRunStatus.PARTIALLY_COMPLETED,
        }:
            await self._record_completed_retest(ctx, run_id)
            await self._generate_completion_reports(ctx, run_id)
        elif outcome.status in {
            AgentRunStatus.BLOCKED,
            AgentRunStatus.FAILED,
            AgentRunStatus.CANCELLED,
        }:
            await self._record_terminal_action_receipt(ctx, run_id, outcome.status.value)
            await self._record_terminal_retest_outcome(ctx, run_id, outcome.status.value)
        await self._ack(message_id)

    async def _record_completed_retest(self, ctx: _RunContext, run_id: uuid.UUID) -> None:
        if ctx.assessment_id is None:
            return
        try:
            async with session_scope(self._settings) as session:
                await complete_assessment_retest(
                    session,
                    organization_id=ctx.organization_id,
                    assessment_id=ctx.assessment_id,
                    run_id=run_id,
                )
        except Exception as exc:
            log.warning(
                "worker.retest_completion_failed", run_id=str(run_id), error_type=type(exc).__name__
            )

    async def _generate_completion_reports(
        self, ctx: _RunContext, run_id: uuid.UUID | None
    ) -> None:
        """Generate one executive HTML/PDF pair when an assessment reaches completion.

        This executes outside the graph-settlement transaction.  A storage or BYOK-model
        outage must leave the assessment completed; the report renderer records its own
        lifecycle and the next report schedule/manual request can recover independently.
        """
        if ctx.assessment_id is None:
            return
        try:
            async with session_scope(self._settings) as session:
                assessment = (
                    await session.execute(
                        tenant_select(Assessment, ctx.organization_id).where(
                            Assessment.id == ctx.assessment_id
                        )
                    )
                ).scalar_one_or_none()
                if assessment is None or assessment.status_enum is not AssessmentStatus.COMPLETED:
                    return
                principal = Principal.for_system(organization_id=ctx.organization_id)
                storage = ObjectStorage(self._settings)
                for fmt in (ReportFormat.HTML, ReportFormat.PDF):
                    title = (
                        f"Automatic board report · Assessment {assessment.reference} "
                        f"({fmt.value.upper()})"
                    )
                    existing = (
                        await session.execute(
                            select(Report)
                            .where(
                                Report.organization_id == ctx.organization_id,
                                Report.assessment_id == assessment.id,
                                Report.audience == "executive",
                                Report.title == title,
                            )
                            .order_by(Report.created_at.desc(), Report.id.desc())
                            .limit(1)
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if existing is not None and existing.status_enum in {
                        ReportStatus.READY,
                        ReportStatus.PENDING,
                        ReportStatus.GENERATING,
                    }:
                        continue
                    await generate_report(
                        session,
                        assessment,
                        fmt=fmt,
                        audience="executive",
                        storage=storage,
                        settings=self._settings,
                        principal=principal,
                        title=title,
                        report=existing,
                    )
                    log.info(
                        "worker.completion_report_generated",
                        assessment_id=str(assessment.id),
                        run_id=str(run_id),
                        format=fmt.value,
                    )
        except Exception as exc:
            log.warning(
                "worker.completion_report_failed",
                assessment_id=str(ctx.assessment_id),
                run_id=str(run_id),
                error_type=type(exc).__name__,
            )

    async def _recover_completion_reports(self, *, limit: int = 10) -> int:
        """Backfill completion reports missed during a transient renderer/storage outage."""
        automatic_prefix = "Automatic board report · Assessment "
        completed_report_count = (
            select(func.count())
            .where(
                Report.organization_id == Assessment.organization_id,
                Report.assessment_id == Assessment.id,
                Report.audience == "executive",
                Report.title.like(f"{automatic_prefix}%"),
                Report.status.in_(
                    (
                        ReportStatus.READY.value,
                        ReportStatus.PENDING.value,
                        ReportStatus.GENERATING.value,
                    )
                ),
            )
            .correlate(Assessment)
        )
        async with session_scope(self._settings) as session:
            candidates = (
                await session.execute(
                    select(Assessment.organization_id, Assessment.id)
                    .where(
                        Assessment.status == AssessmentStatus.COMPLETED.value,
                        completed_report_count.scalar_subquery() < 2,
                    )
                    .order_by(Assessment.completed_at.desc().nullslast(), Assessment.id.desc())
                    .limit(max(1, min(limit, 50)))
                )
            ).all()
        for organization_id, assessment_id in candidates:
            await self._generate_completion_reports(
                _RunContext(
                    run_status=AgentRunStatus.COMPLETED,
                    organization_id=organization_id,
                    assessment_id=assessment_id,
                    session_id=None,
                    heartbeat_at=None,
                    assessment_status=AssessmentStatus.COMPLETED,
                ),
                None,
            )
        return len(candidates)

    async def _render_one_automation_report(self, session: AsyncSession) -> int:
        """Claim and render one report staged by the automation action executor."""
        report = (
            await session.execute(
                select(Report)
                .where(
                    Report.status == ReportStatus.PENDING.value,
                    Report.title.like("Automation · %"),
                )
                .order_by(Report.created_at, Report.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
        ).scalar_one_or_none()
        if report is None:
            return 0
        assessment = (
            await session.execute(
                tenant_select(Assessment, report.organization_id).where(
                    Assessment.id == report.assessment_id
                )
            )
        ).scalar_one_or_none()
        if assessment is None:
            report.status = ReportStatus.FAILED.value
            report.failure_reason = "The source assessment is no longer available."
            return 1
        await generate_report(
            session,
            assessment,
            fmt=ReportFormat(report.format),
            audience=report.audience,
            storage=ObjectStorage(self._settings),
            settings=self._settings,
            principal=Principal.for_system(organization_id=report.organization_id),
            title=report.title,
            report=report,
        )
        return 1

    async def _record_terminal_action_receipt(
        self,
        ctx: _RunContext,
        run_id: uuid.UUID,
        outcome: str,
    ) -> None:
        """Report a settled run without re-running its assessment on transcript failure."""
        try:
            async with session_scope(self._settings) as session:
                await settle_assessment_action_receipt(
                    session,
                    organization_id=ctx.organization_id,
                    run_id=run_id,
                    outcome=outcome,
                )
        except Exception as exc:
            log.warning(
                "worker.action_receipt_failed",
                run_id=str(run_id),
                error_type=type(exc).__name__,
            )

    async def _record_terminal_retest_outcome(
        self,
        ctx: _RunContext,
        run_id: uuid.UUID,
        outcome: str,
    ) -> None:
        if ctx.assessment_id is None:
            return
        try:
            async with session_scope(self._settings) as session:
                await complete_retest(
                    session,
                    organization_id=ctx.organization_id,
                    assessment_id=ctx.assessment_id,
                    outcome=outcome,
                    evidence={"run_id": str(run_id), "assessment_status": outcome},
                )
        except Exception as exc:
            log.warning(
                "worker.retest_outcome_failed", run_id=str(run_id), error_type=type(exc).__name__
            )

    async def _monitor(
        self,
        run_id: uuid.UUID,
        ctx: _RunContext,
        advance_task: asyncio.Task[RunOutcome],
        canceller: _CancelState,
    ) -> None:
        """Stamp the run heartbeat and watch for an operator cancellation, until the run settles.

        One transaction per tick does both jobs.  The heartbeat is what a reclaiming worker
        reads to decide the owner is alive; the cancel poll is what turns an out-of-band
        ``cancelling`` assessment into a cancelled ``advance``.  A tick that fails to reach the
        database is logged and skipped -- a transient blip must neither kill the monitor (which
        would stop the heartbeat and trigger a false reclaim) nor cancel the run.
        """
        interval = _MONITOR_INTERVAL_SECONDS
        while not canceller.stop.is_set():
            try:
                await asyncio.wait_for(canceller.stop.wait(), timeout=interval)
                return  # stop was set -- the run has settled
            except TimeoutError:
                pass
            try:
                renewed = await self._renew_run_slot(ctx.organization_id, run_id)
            except RedisError as exc:
                log.warning("worker.run_lease_renew_failed", error=type(exc).__name__)
                renewed = False
            if not renewed:
                canceller.lease_lost = True
                advance_task.cancel()
                return
            try:
                cancelling = await self._heartbeat_and_check_cancel(run_id, ctx)
            except Exception as exc:
                log.warning(
                    "worker.monitor_tick_failed", run_id=str(run_id), error=type(exc).__name__
                )
                continue
            if cancelling:
                canceller.operator = True
                advance_task.cancel()
                return

    async def _heartbeat_and_check_cancel(self, run_id: uuid.UUID, ctx: _RunContext) -> bool:
        """Bump ``heartbeat_at`` for a still-running run and report whether it is being cancelled."""
        async with session_scope(self._settings) as session:
            run = await session.get(AgentRun, run_id)
            if run is not None and run.status_enum is AgentRunStatus.RUNNING:
                run.heartbeat_at = _now()
            if ctx.assessment_id is None:
                return False
            status = await self._assessment_status(session, ctx.organization_id, ctx.assessment_id)
        return status is AssessmentStatus.CANCELLING

    # -- settle paths --------------------------------------------------------

    async def _cancel_teardown(
        self, run_id: uuid.UUID, ctx: _RunContext, principal: Principal | None
    ) -> None:
        """Finalize an operator cancellation: stop the scans, cancel the assessment, settle the run.

        Ordered so the audit trail is honest (FR-037): flag the scanner jobs first (their own
        executors see the flag and stop the containers), then move the assessment
        ``cancelling`` -> ``cancelled`` and the run to ``cancelled``, all in one transaction.
        The completion event is emitted after the commit -- a pure fan-out, never a DB write --
        so a socket blip cannot roll back the cancellation.  Idempotent: a run already terminal,
        or an assessment already past ``cancelling``, is left untouched, so a reclaim that redoes
        this is harmless.
        """
        async with session_scope(self._settings) as session:
            run = await session.get(AgentRun, run_id)
            if run is None or run.organization_id != ctx.organization_id:
                return
            receipt_eligible = run.status_enum not in _TERMINAL_RUN_STATUSES
            assessment = None
            if ctx.assessment_id is not None:
                assessment = await self._load_assessment(
                    session, ctx.organization_id, ctx.assessment_id
                )
            if assessment is not None and not assessment.status_enum.is_terminal:
                await cancel_jobs_for_assessment(session, assessment, principal=principal)
                if assessment.status_enum is AssessmentStatus.CANCELLING:
                    await transition(
                        session,
                        assessment,
                        AssessmentStatus.CANCELLED,
                        reason="Cancelled by operator.",
                    )
            if assessment is not None and assessment.status_enum is AssessmentStatus.COMPLETED:
                receipt_eligible = False
            if run.status_enum not in _TERMINAL_RUN_STATUSES:
                now = _now()
                run.status = AgentRunStatus.CANCELLED.value
                run.completed_at = now
                run.heartbeat_at = now

        if receipt_eligible:
            await self._record_terminal_action_receipt(ctx, run_id, "cancelled")
        if ctx.session_id is not None:
            emitter = self._deps.emitter(
                session_id=ctx.session_id, assessment_id=ctx.assessment_id, run_id=run_id
            )
            await emitter.complete(
                assessment_id=ctx.assessment_id, status=AssessmentStatus.CANCELLED
            )
        log.info("worker.run_cancelled", run_id=str(run_id))

    async def _settle_orphaned_run(self, run_id: uuid.UUID, ctx: _RunContext) -> None:
        """Mark a non-terminal run whose assessment already ended as cancelled, and move on.

        This should not happen -- the runner settles a run and its assessment together -- so it
        is a defensive settle of an orphan (e.g. a crash between the two writes) that stops the
        graph from being re-run against a finished assessment.  No event: the assessment's own
        terminal event was emitted when it ended.
        """
        async with session_scope(self._settings) as session:
            run = await session.get(AgentRun, run_id)
            if run is None or run.status_enum in _TERMINAL_RUN_STATUSES:
                return
            now = _now()
            run.status = AgentRunStatus.CANCELLED.value
            run.completed_at = now
            run.heartbeat_at = now
            run.failure_reason = (
                "The assessment reached a terminal state before this run could complete."
            )
        log.warning(
            "worker.run_orphaned_settled",
            run_id=str(run_id),
            assessment_status=ctx.assessment_status.value if ctx.assessment_status else None,
        )

    async def _settle_retry_exhausted(self, run_id: uuid.UUID, ctx: _RunContext) -> None:
        """End a run only after all recoverable worker attempts have been spent."""
        reason = "The worker could not complete this assessment after repeated internal failures."
        async with session_scope(self._settings) as session:
            run = await session.get(AgentRun, run_id)
            if run is None or run.organization_id != ctx.organization_id:
                return
            receipt_eligible = run.status_enum not in _TERMINAL_RUN_STATUSES
            if run.status_enum not in _TERMINAL_RUN_STATUSES:
                now = _now()
                run.status = AgentRunStatus.FAILED.value
                run.completed_at = now
                run.heartbeat_at = now
                run.failure_reason = reason
            if ctx.assessment_id is not None:
                assessment = await self._load_assessment(
                    session, ctx.organization_id, ctx.assessment_id
                )
                if assessment is not None and not assessment.status_enum.is_terminal:
                    await transition(session, assessment, AssessmentStatus.FAILED, reason=reason)
                if assessment is not None and assessment.status_enum is AssessmentStatus.COMPLETED:
                    receipt_eligible = False
        if receipt_eligible:
            await self._record_terminal_action_receipt(ctx, run_id, "failed")
        log.error("worker.run_retry_exhausted", run_id=str(run_id))

    # -- data access ---------------------------------------------------------

    async def _load_context(self, run_id: uuid.UUID, message_id: str) -> _RunContext | None:
        """Snapshot the run and its assessment status, stamping the queue id for traceability.

        Returns ``None`` when the run row is gone (a rolled-back enqueue, or a purge), which the
        caller treats as a message to drop.  The queue message id is recorded on a non-terminal
        run so a stuck run can be traced back to its stream entry, skipping the write when it is
        already current (a repeated reclaim-defer must not churn the row).
        """
        async with session_scope(self._settings) as session:
            run = await session.get(AgentRun, run_id)
            if run is None:
                return None
            if (
                run.status_enum not in _TERMINAL_RUN_STATUSES
                and run.queue_message_id != message_id
                and (run.status_enum is not AgentRunStatus.RUNNING or run.queue_message_id is None)
            ):
                run.queue_message_id = message_id
            assessment_status = None
            if run.assessment_id is not None:
                assessment_status = await self._assessment_status(
                    session, run.organization_id, run.assessment_id
                )
            return _RunContext(
                run_status=run.status_enum,
                organization_id=run.organization_id,
                assessment_id=run.assessment_id,
                session_id=run.session_id,
                heartbeat_at=run.heartbeat_at,
                assessment_status=assessment_status,
            )

    async def _assessment_status(
        self, session: AsyncSession, organization_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> AssessmentStatus | None:
        """The assessment's status column, tenant-scoped (SEC-003), or ``None`` if absent.

        Selects the single column rather than loading the row: the monitor calls this every few
        seconds, and it needs a status, not an ORM object.
        """
        stmt = select(Assessment.status).where(
            Assessment.organization_id == organization_id,
            Assessment.id == assessment_id,
        )
        raw = (await session.execute(stmt)).scalar_one_or_none()
        if raw is None:
            return None
        try:
            return AssessmentStatus(raw)
        except ValueError:
            return None

    async def _load_assessment(
        self, session: AsyncSession, organization_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> Assessment | None:
        """Load the assessment row for a cancel teardown, tenant-scoped (SEC-003).

        Returns ``None`` rather than raising if it is gone: a cancellation of an assessment that
        has since been deleted is a no-op, not an error.
        """
        stmt = tenant_select(Assessment, organization_id).where(Assessment.id == assessment_id)
        return (await session.execute(stmt)).scalar_one_or_none()

    # -- maintenance ---------------------------------------------------------

    async def _maintenance_loop(self) -> None:
        """Run independent, non-overlapping maintenance lanes with separate sessions.

        Each lane has at most one in-flight cycle per worker. Slow provider calls
        and report rendering cannot hold up dispatch, approved actions, or the
        Redis liveness signal. Existing database claims coordinate other workers.
        Cancelling this supervisor drains every child and rolls back its session.
        """
        operations: tuple[
            tuple[str, Callable[[AsyncSession], Awaitable[Any]], str | None, str], ...
        ] = (
            ("reaper", reclaim_orphans, None, "worker.maintenance_failed"),
            (
                "agent-task-leases",
                self._recover_agent_task_leases,
                "worker.agent_task_leases_recovered",
                "worker.agent_task_lease_recovery_failed",
            ),
            (
                "knowledge-indexing",
                lambda _session: run_due_knowledge_indexing(self._settings),
                "worker.knowledge_indexed",
                "worker.knowledge_index_failed",
            ),
            (
                "scans",
                lambda session: run_due_scans(session, self._settings),
                "worker.recurring_scans_started",
                "worker.recurring_scan_failed",
            ),
            (
                "reports",
                lambda session: run_due_report_schedules(
                    session, self._settings, renderer=generate_report
                ),
                "worker.report_schedules_completed",
                "worker.report_schedule_failed",
            ),
            (
                "automation-reports",
                self._render_one_automation_report,
                "worker.automation_report_rendered",
                "worker.automation_report_failed",
            ),
            (
                "report-distributions",
                reconcile_report_distributions,
                "worker.report_distributions_reconciled",
                "worker.report_distribution_reconcile_failed",
            ),
            (
                "report-recovery",
                lambda _session: self._recover_completion_reports(),
                "worker.completion_reports_recovery_attempted",
                "worker.completion_report_recovery_failed",
            ),
            (
                "campaigns",
                lambda session: run_due_campaigns(session, self._settings),
                "worker.attack_simulation_campaigns_started",
                "worker.attack_simulation_campaign_failed",
            ),
            (
                "bas-techniques",
                execute_pending_techniques,
                "worker.attack_simulation_techniques_settled",
                "worker.attack_simulation_technique_failed",
            ),
            (
                "dispatch",
                lambda session: deliver_pending_dispatches(session, self._redis, self._settings),
                "worker.run_dispatches_published",
                "worker.run_dispatch_failed",
            ),
            (
                "notifications",
                lambda session: deliver_pending(
                    session, settings=self._settings, redis=self._redis
                ),
                None,
                "worker.notification_delivery_failed",
            ),
            (
                "integration-syncs",
                lambda session: run_due_integration_syncs(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.integration_syncs_completed",
                "worker.integration_sync_failed",
            ),
            (
                "custom-connectors",
                lambda session: run_pending_connector_runs(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.custom_connector_runs_completed",
                "worker.custom_connector_run_failed",
            ),
            (
                "tickets",
                lambda session: refresh_due_ticket_statuses(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.ticket_statuses_refreshed",
                "worker.ticket_status_refresh_failed",
            ),
            (
                "agent-actions",
                lambda session: execute_approved_batch(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.agent_actions_settled",
                "worker.agent_action_execution_failed",
            ),
            (
                "automations",
                lambda session: execute_pending_automations(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.automation_executions_settled",
                "worker.automation_execution_failed",
            ),
            (
                "automation-schedules",
                queue_due_automation_schedules,
                "worker.automation_schedules_queued",
                "worker.automation_schedule_failed",
            ),
            (
                "workflows",
                lambda session: execute_due_workflows(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.workflow_runs_settled",
                "worker.workflow_execution_failed",
            ),
            (
                "workflow-schedules",
                queue_due_workflow_schedules,
                "worker.workflow_schedules_queued",
                "worker.workflow_schedule_failed",
            ),
            (
                "sla",
                lambda session: emit_overdue_sla_escalations(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.sla_escalations_emitted",
                "worker.sla_escalation_failed",
            ),
            (
                "risk-expiry",
                expire_risk_acceptances,
                "worker.risk_acceptances_expired",
                "worker.risk_acceptance_expiry_failed",
            ),
            (
                "compliance-expiry",
                expire_compliance_records,
                "worker.compliance_records_expired",
                "worker.compliance_record_expiry_failed",
            ),
            (
                "risk-refresh",
                refresh_stale_risk_batch,
                "worker.canonical_risk_refreshed",
                "worker.canonical_risk_refresh_failed",
            ),
            (
                "intel",
                lambda session: refresh_stale_intel_batch(
                    session, settings=self._settings, redis=self._redis
                ),
                "worker.canonical_intel_refreshed",
                "worker.canonical_intel_refresh_failed",
            ),
            (
                "asm",
                lambda session: run_due_surfaces(session, self._settings),
                "worker.asm_surfaces_completed",
                "worker.asm_surface_failed",
            ),
        )
        tasks = [
            asyncio.create_task(self._liveness_loop(), name="worker-liveness"),
            *(
                asyncio.create_task(
                    self._maintenance_lane(operation, success_event, error_event),
                    name=f"worker-maintenance-{name}",
                )
                for name, operation, success_event, error_event in operations
            ),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _recover_agent_task_leases(self, session: AsyncSession) -> int:
        return len(await recover_all_stale_tasks(session))

    async def _maintenance_lane(
        self,
        operation: Callable[[AsyncSession], Awaitable[Any]],
        success_event: str | None,
        error_event: str,
    ) -> None:
        while not self._stopping:
            await asyncio.sleep(_MAINTENANCE_INTERVAL_SECONDS)
            if self._stopping:
                return
            try:
                async with session_scope(self._settings) as session:
                    count = await operation(session)
                if count and success_event:
                    log.info(success_event, count=count)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(error_event, error=type(exc).__name__)

    async def _liveness_loop(self) -> None:
        while not self._stopping:
            await asyncio.sleep(_MAINTENANCE_INTERVAL_SECONDS)
            if self._stopping:
                return
            try:
                await self._pulse_liveness()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("worker.liveness_pulse_failed", error=type(exc).__name__)

    async def _pulse_liveness(self, *, now: dt.datetime | None = None) -> None:
        score = (now or _now()).timestamp()
        key = worker_liveness_key(self._stream)
        await self._redis.zadd(key, {self._worker_id: score})
        await self._redis.zremrangebyscore(key, "-inf", score - WORKER_LIVENESS_MAX_AGE_SECONDS)

    async def _remove_liveness(self) -> None:
        await self._redis.zrem(worker_liveness_key(self._stream), self._worker_id)

    # -- helpers -------------------------------------------------------------

    def _heartbeat_fresh(self, heartbeat_at: dt.datetime | None) -> bool:
        """Whether a run's heartbeat is recent enough that its owner is presumed alive.

        The threshold is ``claim_idle_ms``: the same idle bound ``XAUTOCLAIM`` uses to reclaim,
        so a run heartbeating faster than that is by definition still owned.  A run that has
        never heartbeated (``None``) is not fresh -- it either just started or its worker died
        before the first tick, and re-driving from the checkpoint is correct either way.
        """
        if heartbeat_at is None:
            return False
        age_ms = (_now() - heartbeat_at).total_seconds() * 1000.0
        return age_ms < self._settings.redis.claim_idle_ms

    def _principal_of(self, request: RunRequest) -> Principal | None:
        """Rebuild the acting principal a START carried, or ``None`` for a RESUME.

        :meth:`Principal.from_dict` re-validates the role, so a message that somehow carried a
        malformed authority yields ``None`` rather than an unenforceable one -- the runner then
        fails a run that needed a seed, instead of acting under a bad principal (SEC-002). The
        error names its type only, never the payload.
        """
        if request.principal is None:
            return None
        try:
            return Principal.from_dict(request.principal)
        except Exception as exc:
            log.warning("worker.principal_unreadable", error=type(exc).__name__)
            return None

    async def _ack(self, message_id: str) -> None:
        """Acknowledge settled work before deleting its stream entry."""
        try:
            await cast(Awaitable[int], self._redis.xack(self._stream, self._group, message_id))
            await cast(Awaitable[int], self._redis.xdel(self._stream, message_id))
        except RedisError as exc:
            log.warning("worker.ack_failed", message_id=message_id, error=type(exc).__name__)

    async def _dead_letter(self, message_id: str, reason: str) -> bool:
        """Persist a safe failure record before removing an undeliverable stream entry."""
        try:
            await cast(
                Awaitable[Any],
                self._redis.xadd(
                    f"{self._stream}:dead",
                    {"source_message_id": message_id, "reason": reason},
                ),
            )
        except RedisError as exc:
            log.warning(
                "worker.dead_letter_failed", message_id=message_id, error=type(exc).__name__
            )
            return False
        return True

    def _retry_key(self, message_id: str) -> str:
        return f"{self._stream}:retry:{message_id}"

    async def _begin_attempt(self, message_id: str) -> int:
        """Count actual graph invocations, including ones killed by process crashes."""
        key = self._retry_key(message_id)
        count = await cast(Awaitable[int], self._redis.hincrby(key, "attempts", 1))
        await cast(Awaitable[bool], self._redis.expire(key, _RETRY_STATE_TTL_SECONDS))
        return int(count)

    async def _schedule_retry(self, message_id: str, attempts: int) -> None:
        delay = min(_RETRY_BASE_SECONDS * (2 ** (attempts - 1)), _RETRY_MAX_SECONDS)
        due_ms = int((_now().timestamp() + delay) * 1000)
        await cast(
            Awaitable[int], self._redis.hset(self._retry_key(message_id), "due_ms", str(due_ms))
        )

    async def _retry_due(self, message_id: str) -> bool:
        due_ms = await cast(
            Awaitable[bytes | str | None],
            self._redis.hget(self._retry_key(message_id), "due_ms"),
        )
        return due_ms is None or int(due_ms) <= int(_now().timestamp() * 1000)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["AgentWorker"]
