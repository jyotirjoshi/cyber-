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
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from typing import Any, cast

import structlog
from redis.asyncio.client import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.registry import AgentDeps
from app.agent.runner import AgentRunner, RunOutcome
from app.core.config import Settings
from app.core.errors import ConflictError, CynuxError
from app.db.enums import AgentRunStatus, AssessmentStatus
from app.db.models.agent import AgentRun
from app.db.models.assessment import Assessment
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.services.assessment import transition
from app.services.context import Principal
from app.services.job import cancel_jobs_for_assessment, reclaim_orphans
from app.worker.protocol import RunRequest

log = structlog.get_logger(__name__)

#: Run statuses with nothing left to drive. Mirrors the runner's own terminal set (kept local
#: rather than imported: it is private there, and the worker's need for it is its own).
_TERMINAL_RUN_STATUSES: frozenset[AgentRunStatus] = frozenset(
    {AgentRunStatus.COMPLETED, AgentRunStatus.FAILED, AgentRunStatus.CANCELLED}
)

#: How long ``XREADGROUP`` blocks waiting for a new message. Bounds shutdown latency when the
#: worker is idle: a stop request is noticed within this window (an in-flight run is cancelled
#: immediately, so this only gates the idle case).
_READ_BLOCK_MS = 5_000

#: Upper bound on messages pulled per read / reclaim. The worker drives runs one at a time, so
#: this batches the *reads*, not the execution -- extra entries wait in the PEL.
_READ_BATCH = 10
_RECLAIM_BATCH = 20

#: Cadence of the per-run monitor: it stamps the run heartbeat (liveness for reclaim) and polls
#: for an operator cancellation. Far below ``claim_idle_ms`` so a healthy run's heartbeat never
#: looks stale, and low enough that a cancel is honoured within a few seconds.
_MONITOR_INTERVAL_SECONDS = 5.0

#: Cadence of the scanner-orphan sweep (FR-040). Independent of run dispatch.
_MAINTENANCE_INTERVAL_SECONDS = 30.0

#: Backoff after a Redis read error, so a transient outage does not become a hot loop.
_ERROR_BACKOFF_SECONDS = 2.0


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
    ) -> None:
        self._settings = settings
        self._redis = redis
        self._deps = deps
        self._runner = runner
        self._worker_id = worker_id
        #: The consumer name inside the group. One per process, so the PEL attributes each
        #: in-flight message to the worker holding it and reclaim can find a dead one's work.
        self._consumer = worker_id
        self._stream = settings.redis.stream
        self._group = settings.redis.consumer_group
        self._stopping = False
        self._current_advance: asyncio.Task[RunOutcome] | None = None

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
                await self._dispatch(message_id, fields, reclaimed=False)

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
            await self._dispatch(message_id, fields, reclaimed=True)

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
            # A poison message: acknowledge and drop it, or it is redelivered forever and wedges
            # the group. The error never quotes the payload (SEC-002).
            log.warning("worker.poison_message", message_id=message_id, error=type(exc).__name__)
            await self._ack(message_id)
            return

        run_id = request.run_id
        ctx = await self._load_context(run_id, message_id)
        if ctx is None:
            log.warning("worker.run_missing", run_id=str(run_id), message_id=message_id)
            await self._ack(message_id)
            return

        if reclaimed and self._heartbeat_fresh(ctx.heartbeat_at):
            # A live worker still owns this run (see the module docstring on healthy long runs).
            # Leave the entry pending -- the owner will settle and ack it.
            log.debug("worker.reclaim_deferred", run_id=str(run_id), message_id=message_id)
            return

        if ctx.assessment_status is AssessmentStatus.CANCELLING:
            await self._cancel_teardown(run_id, ctx, self._principal_of(request))
            await self._ack(message_id)
            return

        if ctx.assessment_status is not None and ctx.assessment_status.is_terminal:
            await self._settle_orphaned_run(run_id, ctx)
            await self._ack(message_id)
            return

        await self._run(message_id, run_id, ctx, self._principal_of(request))

    async def _run(
        self,
        message_id: str,
        run_id: uuid.UUID,
        ctx: _RunContext,
        principal: Principal | None,
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
            # advance raises CynuxError only for a run that cannot be processed at all (missing
            # or not an assessment run). Retrying will not help, so ack and drop.
            log.warning(
                "worker.run_unprocessable",
                run_id=str(run_id),
                error_code=exc.code,
                error_category=exc.category.value,
            )
            await self._ack(message_id)
            return
        except Exception as exc:
            # advance settles graph failures internally, so this is an unexpected fault in its
            # own bookkeeping (e.g. the database blinked while settling). Do NOT ack -- leave the
            # message pending so reclaim retries once the fault clears.
            log.error("worker.run_error", run_id=str(run_id), exc_type=type(exc).__name__)
            return
        finally:
            canceller.stop.set()
            monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)
            self._current_advance = None

        log.info("worker.run_settled", run_id=str(run_id), status=outcome.status.value)
        await self._ack(message_id)

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
            if run is not None and run.status_enum not in _TERMINAL_RUN_STATUSES:
                now = _now()
                run.status = AgentRunStatus.CANCELLED.value
                run.completed_at = now
                run.heartbeat_at = now

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
            if run.status_enum not in _TERMINAL_RUN_STATUSES and run.queue_message_id != message_id:
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
        """Periodically fail scanner jobs whose worker stopped heartbeating (FR-040).

        A sibling of the consume loop, not part of it, so a worker busy driving one long run
        still reaps orphaned ``ScannerJob`` rows.  This reclaims *scanner jobs*, which is a
        different thing from ``XAUTOCLAIM`` reclaiming *run messages* -- the two failure modes
        (a scanner's executor died; the run's worker died) are independent.
        """
        while not self._stopping:
            try:
                await asyncio.sleep(_MAINTENANCE_INTERVAL_SECONDS)
                async with session_scope(self._settings) as session:
                    await reclaim_orphans(session)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("worker.maintenance_failed", error=type(exc).__name__)

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
        """Acknowledge a message, removing it from the group PEL (group-scoped; see the module docstring)."""
        try:
            await cast(Awaitable[int], self._redis.xack(self._stream, self._group, message_id))
        except RedisError as exc:
            log.warning("worker.ack_failed", message_id=message_id, error=type(exc).__name__)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["AgentWorker"]
