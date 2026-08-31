"""Drive one assessment run and own its ``AgentRun`` lifecycle (FR-033, FR-040; PRD §54).

The graph in :mod:`app.agent.graph` is pure control flow; the nodes in
:mod:`app.agent.nodes` each own a slice of *product* state and degrade around their own
non-fatal failures (FR-040).  This module is the seam between the two and the layer the
worker actually calls: a single ``advance`` entry drives a run from wherever it is -- a fresh
start, a resume past the approval interrupt, or a crash reclaim -- and turns whatever the
graph did -- ran to the end, paused at the gate, or raised -- into a settled ``AgentRun`` row
and the matching terminal event.  **The runner is the single writer of a
run's top-level status** (``queued`` -> ``running`` -> ``interrupted`` / ``completed`` /
``failed``); the step recorder in :mod:`app.agent.nodes._common` deliberately manages only
the per-node ``agent_steps`` rows and the ``current_node`` cursor, never the run status.

**Outcome is decided by mechanism, not by anything the model said.**  Three post-conditions,
each read from ground truth:

* The graph is compiled with ``interrupt_before=["execute_scanners"]``.  When ``ainvoke``
  returns with :attr:`StateSnapshot.next` still pointing at that node, the run *paused* for
  human approval (FR-011): it is recorded ``interrupted`` and the worker leaves it for a
  resume.  This is a return, not an exception -- LangGraph settles the checkpoint and hands
  control back.
* When ``ainvoke`` returns with an empty ``next``, the graph reached ``END``: the run is
  ``completed`` and a terminal completion event is emitted.
* When ``ainvoke`` *raises*, a node let a non-degradable error escape (a failed scanner is
  swallowed by its node; a broken evidence chain -- storage, DefectDojo, report render -- is
  not).  Whatever reached here fails the run: the ``AgentRun`` and, if it is not already
  terminal, the ``Assessment`` are moved to ``failed`` with a user-safe reason, the owner is
  notified, and an error event is emitted (FR-040).

**Cancellation is the worker's, not the runner's.**  A ``CancelledError`` is not an
``Exception`` and is never caught here; it propagates untouched so the worker can run its own
teardown (move the assessment through ``cancelling`` -> ``cancelled``, tear down containers,
mark the run ``cancelled``).  ``session_scope`` rolls back the in-flight transaction on the
way out.

**No secret, host, finding title or CVE is ever logged (SEC-002).**  The failure path logs
the error *code*, its *category* and the raising exception's *type name* -- never
``str(exc)``, which can quote a provider response or an internal hostname.  The one place a
target is named is the failure notification's subject line, which addresses the owner about
their own asset -- SEC-002 governs logs, prompts and errors, not an alert addressed to the
asset's owner (the same carve-out :mod:`app.agent.nodes.report` relies on).

The LangGraph checkpointer is opened once per worker by :func:`checkpointer_for` and passed
in: its Postgres pool outlives any single run and is shared across every run the worker
executes, exactly like the :class:`~app.agent.registry.AgentDeps` the runner is built with.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import cast

import structlog
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import StateSnapshot
from psycopg import AsyncConnection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import AsyncConnectionPool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.base import ExecutableOption

from app.agent.graph import build_graph
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, initial_state, optional_state_uuid
from app.core.config import Settings
from app.core.errors import ConflictError, CynuxError
from app.db.enums import (
    AgentRunStatus,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    Scope,
)
from app.db.models.agent import AgentRun
from app.db.models.assessment import Assessment
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.services.assessment import assessment_or_404, transition
from app.services.context import Principal
from app.services.notification import notify_assessment_failed

log = structlog.get_logger(__name__)

#: The node the graph pauses *before* (must match ``build_graph``'s ``interrupt_before``).
#: A settled snapshot whose ``next`` names this node is a run paused for approval, not a
#: completed one -- that distinction is the whole of :meth:`AgentRunner._settle`.
_INTERRUPT_NODE = "execute_scanners"

#: Recorded on ``AgentRun.interrupt_kind`` when a run pauses at the one human gate.  The
#: pipeline has exactly one interrupt (scope approval, FR-011), so this is the only kind.
_INTERRUPT_APPROVAL = "approval"

#: The run statuses from which there is nothing left to drive.  A message re-presenting a run
#: in one of these -- a duplicate delivery, or the reclaim of a run another worker already
#: finished -- is a no-op: :meth:`AgentRunner.advance` reports the recorded outcome and the
#: worker simply acks, without re-running the graph or re-emitting the (already sent) terminal
#: event.  ``running`` is deliberately absent: a run left ``running`` by a dead worker is *not*
#: settled, and reclaiming it is the whole point of :meth:`AgentRunner.advance`.
_TERMINAL_RUN_STATUSES: frozenset[AgentRunStatus] = frozenset(
    {AgentRunStatus.COMPLETED, AgentRunStatus.FAILED, AgentRunStatus.CANCELLED}
)

#: The checkpoint pool is separate from the SQLAlchemy engine pool and, because
#: :class:`AsyncPostgresSaver` serialises all checkpoint I/O on an internal lock, it exists
#: for connection *resilience* (recycle/reconnect over a long-lived worker) rather than
#: throughput -- so it stays small.  A shared saver does not parallelise across runs no
#: matter how large this pool is.
_CHECKPOINT_POOL_MIN_SIZE = 1
_CHECKPOINT_POOL_MAX_SIZE = 4

#: User-safe failure text for an exception outside the error taxonomy.  The real exception is
#: logged by type name only; its text never reaches the operator, the ``AgentRun`` row or the
#: ``Assessment`` row (SEC-002).
_UNEXPECTED_USER_MESSAGE = (
    "The assessment could not be completed because of an unexpected internal error."
)


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """The settled result of an :meth:`AgentRunner.advance` call.

    ``status`` is always one of ``interrupted``, ``completed`` or ``failed`` -- never
    ``running`` or ``queued``, because ``advance`` does not return until the graph has paused
    at the approval gate, reached ``END`` or raised.  (A re-dispatch of an already-terminal run
    also settles here, reporting the recorded outcome without re-running anything.)  Every
    field is a plain scalar so the worker can log it and decide what to do next (ack the
    message, leave the run for a resume, retry) without touching the database again.
    """

    run_id: uuid.UUID
    status: AgentRunStatus
    report_id: uuid.UUID | None = None
    findings_total: int = 0
    failure_category: str | None = None

    @property
    def interrupted(self) -> bool:
        """True when the run paused at the approval gate and is awaiting a resume."""
        return self.status is AgentRunStatus.INTERRUPTED

    @property
    def completed(self) -> bool:
        """True when the run reached the end of the pipeline."""
        return self.status is AgentRunStatus.COMPLETED

    @property
    def failed(self) -> bool:
        """True when a non-degradable error terminated the run."""
        return self.status is AgentRunStatus.FAILED


@asynccontextmanager
async def checkpointer_for(settings: Settings) -> AsyncIterator[AsyncPostgresSaver]:
    """Open the process-scoped LangGraph checkpointer for a worker's lifetime.

    A worker opens this once, around all the runs it will ever execute, and hands the saver
    to every :class:`AgentRunner` it builds.  The checkpointer is what makes a day-long wait
    for approval survivable: the graph channels live in Postgres keyed by ``thread_id``, so a
    resume re-enters the graph rather than replaying anything (FR-033).

    Design notes, each load-bearing:

    * It runs on the *sync* psycopg DSN (``settings.db.sync_dsn``), not the asyncpg one the
      ORM uses -- ``AsyncPostgresSaver`` speaks psycopg.
    * The pool's connection kwargs are mandated by the saver: ``autocommit=True`` (its
      ``setup`` runs migrations and each checkpoint write commits on its own),
      ``prepare_threshold=0`` (server-side prepared statements do not survive pgbouncer in
      transaction mode), and ``row_factory=dict_row`` (``setup`` reads ``row["v"]`` by name).
    * ``open=False`` + ``async with pool`` ties the pool's open/close to this block, so the
      worker's shutdown closes every checkpoint connection deterministically.
    * ``setup()`` creates the checkpoint tables if absent and MUST run before the first
      checkpoint; it is idempotent, so opening the saver on an already-migrated database is a
      no-op beyond a couple of catalog reads.
    """
    async with AsyncConnectionPool(
        conninfo=settings.db.sync_dsn,
        min_size=_CHECKPOINT_POOL_MIN_SIZE,
        max_size=_CHECKPOINT_POOL_MAX_SIZE,
        open=False,
        kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
    ) as pool:
        # The pool's connections are configured with ``row_factory=dict_row`` above, so every
        # row they yield is a ``dict`` -- exactly what ``AsyncPostgresSaver.setup`` needs when
        # it reads ``row["v"]``.  That factory rides in a runtime ``kwargs`` dict the pool
        # constructor cannot fold into its static element type (it defaults to tuple rows), so
        # the dict-row guarantee is asserted here rather than inferred.
        saver = AsyncPostgresSaver(cast(AsyncConnectionPool[AsyncConnection[DictRow]], pool))
        await saver.setup()
        log.info("agent.checkpointer.ready")
        yield saver


class AgentRunner:
    """Runs one assessment graph per call, over a per-worker :class:`AgentDeps` and saver.

    The graph is built *once* per runner (``__init__``), binding the live dependencies onto
    every node; ``advance`` then invokes that same compiled graph against a run's own
    ``thread_id``.  Building per runner rather than per call keeps the (cheap but non-trivial)
    wiring out of the hot path and matches the lifetime of ``deps`` and ``checkpointer``,
    which are themselves per-worker.
    """

    __slots__ = ("_deps", "_graph", "_worker_id")

    def __init__(
        self,
        deps: AgentDeps,
        checkpointer: BaseCheckpointSaver,
        *,
        worker_id: str | None = None,
    ) -> None:
        self._deps = deps
        self._graph: CompiledStateGraph = build_graph(deps, checkpointer)
        self._worker_id = worker_id

    async def advance(self, run_id: uuid.UUID, *, principal: Principal | None = None) -> RunOutcome:
        """Drive a run to its next settled state, from wherever it currently is.

        This is the sole entry the worker calls -- for a fresh dispatch and for a
        post-approval resume alike -- and it is deliberately safe to call more than once for
        the same run, because that is what carries an assessment across a worker crash
        (FR-033).  At-least-once stream delivery and the reclaim of a dead worker's pending
        message (``claim_idle_ms``) both re-present a run here, and the run's own database
        status -- never the queue message that carried it -- decides what happens (the rule
        the scan node already follows for approvals, FR-011):

        * ``queued``      -- seed fresh state and invoke from the first node.
        * ``interrupted`` -- resume past the approval gate with ``None`` input.
        * ``running``     -- a crash reclaim: resume from the last checkpoint, or, if the
          previous worker died in the sliver between marking the run running and the first
          checkpoint, re-seed and start over.
        * terminal        -- already settled by whoever drove it first; report the recorded
          outcome and touch neither the graph, the database nor the socket.

        ``principal`` is needed only to *seed* -- a queued run, or a checkpoint-less reclaim --
        and rides in the dispatch message for exactly those; a resume passes ``None`` and the
        initiating principal is recovered from the checkpoint instead.  A message that would
        require a seed but carries no principal is a corrupt queue entry: the run is failed
        rather than left stuck.  The caller must have established that no *live* worker is
        already driving this run (a fresh heartbeat means hands off); ``advance`` assumes that.
        """
        status, thread_id, settled = await self._inspect(run_id)
        if settled is not None:
            log.info("agent.run.already_settled", run_id=str(run_id), status=status.value)
            return settled
        config = _run_config(thread_id)
        try:
            seed = await self._enter(run_id, config, status, principal)
        except ConflictError:
            # Another worker settled or is driving this run in the gap between inspecting and
            # entering it. Benign under at-least-once delivery -- propagate so the worker acks
            # the duplicate without failing a run it does not own.
            raise
        except CynuxError as exc:
            # A run that cannot be seeded (a resume/reclaim with no principal and no checkpoint
            # to resume from) is a corrupt dispatch; fail it so it is not left stuck running.
            return await self._settle_failure(run_id, config, exc, principal=principal)
        try:
            await self._graph.ainvoke(seed, config=config)
        except Exception as exc:
            return await self._settle_failure(run_id, config, exc, principal=principal)
        return await self._settle(run_id, config)

    # -- entry bookkeeping ---------------------------------------------------

    async def _inspect(self, run_id: uuid.UUID) -> tuple[AgentRunStatus, str, RunOutcome | None]:
        """Read a run's status and thread id, short-circuiting one already settled.

        Runs in its own transaction before any graph work.  A run that is not a runnable
        assessment (a mis-routed chat run with no assessment or session) is refused here via
        :func:`_run_identity`, and a run already in a terminal state yields its recorded
        outcome so :meth:`advance` returns without re-running the graph or re-emitting a
        terminal event.
        """
        async with session_scope(self._deps.settings) as session:
            run = await _load_run(session, run_id)
            _run_identity(run)  # refuse a non-assessment run before touching the graph
            status = run.status_enum
            thread_id = run.thread_id
            settled = _outcome_from(run) if status in _TERMINAL_RUN_STATUSES else None
        return status, thread_id, settled

    async def _enter(
        self,
        run_id: uuid.UUID,
        config: RunnableConfig,
        status: AgentRunStatus,
        principal: Principal | None,
    ) -> AssessmentState | None:
        """Move a run to ``running`` and return its seed state, or ``None`` to resume.

        Whether to seed or resume is derived from the run's status and, for a ``running``
        reclaim, from whether a checkpoint exists: a queued run and a checkpoint-less reclaim
        seed fresh state (and need the initiating ``principal``); an interrupted run and a
        checkpointed reclaim resume with ``None`` input.  The transition to ``running`` and the
        seed build share one transaction, and a run found already terminal here -- a settle
        that raced in from another driver -- is refused rather than resurrected.  Runs before
        ``ainvoke`` and mostly outside its ``try``, so a guard failure surfaces as its own
        outcome (a benign :class:`ConflictError` the worker acks, or a corrupt-dispatch
        failure) rather than being mistaken for a graph error.
        """
        reclaim = status is AgentRunStatus.RUNNING
        if reclaim:
            has_checkpoint = await self._has_checkpoint(config)
        else:
            # queued -> nothing has been checkpointed yet (seed); interrupted -> the interrupt
            # checkpoint always exists (resume).
            has_checkpoint = status is AgentRunStatus.INTERRUPTED
        must_seed = not has_checkpoint

        seed_principal: Principal | None = None
        if must_seed:
            if principal is None:
                raise CynuxError(
                    f"run {run_id} needs a fresh seed but no principal was supplied",
                    user_message="This assessment run is misconfigured and cannot be processed.",
                    context={"run_id": str(run_id), "status": status.value},
                )
            seed_principal = principal

        async with session_scope(self._deps.settings) as session:
            run = await _load_run(session, run_id)
            if run.status_enum in _TERMINAL_RUN_STATUSES:
                raise ConflictError(
                    f"run {run_id} is already {run.status}",
                    user_message="This assessment run has already finished.",
                    context={"run_id": str(run_id), "status": run.status},
                )
            assessment_id, session_id = _run_identity(run)
            now = _now()
            run.status = AgentRunStatus.RUNNING.value
            run.worker_id = self._worker_id
            run.heartbeat_at = now
            if status is AgentRunStatus.QUEUED:
                # ``understand`` performs the created -> planning assessment transition, so the
                # runner leaves the assessment status alone on a fresh start.
                if run.started_at is None:
                    run.started_at = now
            else:
                # A resume or a reclaim: count it and clear any interrupt bookkeeping.
                run.resumed_count = run.resumed_count + 1
                run.interrupt_kind = None
                run.pending_approval_id = None

            seed: AssessmentState | None = None
            if seed_principal is not None:
                run.current_node = None
                assessment = await _load_assessment(session, run.organization_id, assessment_id)
                seed = initial_state(
                    assessment_id=assessment.id,
                    organization_id=run.organization_id,
                    session_id=session_id,
                    run_id=run.id,
                    thread_id=run.thread_id,
                    principal=seed_principal,
                    objective=_objective_of(assessment),
                    depth=AssessmentDepth(assessment.depth),
                    scope=Scope(assessment.scope),
                    scope_budget=self._deps.settings.agent.default_scope_budget,
                )
            thread_id = run.thread_id
        log.info(
            "agent.run.entered",
            run_id=str(run_id),
            thread_id=thread_id,
            from_status=status.value,
            mode="seed" if must_seed else "resume",
            reclaim=reclaim,
            worker=self._worker_id,
        )
        return seed

    async def _has_checkpoint(self, config: RunnableConfig) -> bool:
        """Whether the graph has checkpointed at least once on this thread.

        Distinguishes the two ``running`` reclaims: a run with a checkpoint crashed mid-pipeline
        and resumes from it; one with none crashed before the first node persisted anything and
        must seed afresh.  Best-effort -- an unreadable checkpoint is treated as absent, which
        re-seeds rather than resuming into a void.
        """
        try:
            snapshot = await self._graph.aget_state(config)
        except Exception as exc:
            log.warning("agent.run.state_unavailable", error=type(exc).__name__)
            return False
        return snapshot.created_at is not None

    # -- outcome routing -----------------------------------------------------

    async def _settle(self, run_id: uuid.UUID, config: RunnableConfig) -> RunOutcome:
        """Route a non-raising invocation to interrupt or completion from the checkpoint.

        The distinction is ground truth, not a self-report: a non-empty
        :attr:`StateSnapshot.next` means LangGraph stopped the run at the ``interrupt_before``
        node (the approval gate); an empty ``next`` means it reached ``END``.
        """
        snapshot = await self._graph.aget_state(config)
        if snapshot.next:
            return await self._settle_interrupt(run_id, snapshot)
        return await self._settle_complete(run_id, snapshot)

    async def _settle_interrupt(self, run_id: uuid.UUID, snapshot: StateSnapshot) -> RunOutcome:
        """Record a paused run as ``interrupted`` and point at the approval it is blocked on.

        No terminal event is emitted -- ``request_approval`` already published the
        ``approval_required`` event before the interrupt.  ``pending_approval_id`` is read
        from the checkpoint so the API can find the exact approval row to grant, and
        ``current_node`` is set to the gate the run stopped at (the node it will run next on
        resume).
        """
        approval_id = optional_state_uuid(snapshot.values, "approval_id")
        paused_at = snapshot.next[0] if snapshot.next else _INTERRUPT_NODE
        async with session_scope(self._deps.settings) as session:
            run = await _load_run(session, run_id)
            run.status = AgentRunStatus.INTERRUPTED.value
            run.interrupt_kind = _INTERRUPT_APPROVAL
            run.pending_approval_id = approval_id
            run.current_node = paused_at
            run.heartbeat_at = _now()
        log.info(
            "agent.run.interrupted",
            run_id=str(run_id),
            node=paused_at,
            has_approval=approval_id is not None,
        )
        return RunOutcome(run_id=run_id, status=AgentRunStatus.INTERRUPTED)

    async def _settle_complete(self, run_id: uuid.UUID, snapshot: StateSnapshot) -> RunOutcome:
        """Record a finished run as ``completed`` and emit the terminal completion event.

        The assessment's own ``completed`` transition, counter recompute and completion
        *notification* were done atomically by :mod:`app.agent.nodes.report`; this settles the
        *run* and emits the run-level terminal event with the authoritative assessment status
        and finding count (read here, not trusted from the graph state).  The completion event
        is published outside the transaction -- it is a pure fan-out, never a database write.
        """
        report_id = optional_state_uuid(snapshot.values, "report_id")
        async with session_scope(self._deps.settings) as session:
            run = await _load_run(session, run_id)
            assessment_id, session_id = _run_identity(run)
            now = _now()
            run.status = AgentRunStatus.COMPLETED.value
            run.completed_at = now
            run.current_node = None
            run.heartbeat_at = now
            duration = _duration_seconds(run.started_at, now)
            assessment = await _load_assessment(session, run.organization_id, assessment_id)
            status = assessment.status_enum
            findings_total = assessment.findings_total
        emitter = self._deps.emitter(
            session_id=session_id, assessment_id=assessment_id, run_id=run_id
        )
        await emitter.complete(
            assessment_id=assessment_id,
            status=status,
            findings_total=findings_total,
            report_id=report_id,
            duration_seconds=duration,
        )
        log.info(
            "agent.run.completed",
            run_id=str(run_id),
            findings_total=findings_total,
            has_report=report_id is not None,
        )
        return RunOutcome(
            run_id=run_id,
            status=AgentRunStatus.COMPLETED,
            report_id=report_id,
            findings_total=findings_total,
        )

    async def _settle_failure(
        self,
        run_id: uuid.UUID,
        config: RunnableConfig,
        exc: BaseException,
        *,
        principal: Principal | None = None,
    ) -> RunOutcome:
        """Fail the run, fail the assessment if it is not already terminal, and alert (FR-040).

        Everything that reaches here is fatal: a degradable error was handled inside its node
        and never surfaced.  A non-taxonomy exception is wrapped in a generic internal
        :class:`CynuxError` so it carries a user-safe message and a category, and the raw
        exception's text is dropped (SEC-002); only its type name is logged.

        The critical writes and the notification share one transaction -- mirroring
        :mod:`app.agent.nodes.report`'s atomic completion, so "the run failed" and "the owner
        was told" cannot diverge.  The assessment is only transitioned when it is not already
        terminal (a race with cancellation, or a failure in the terminal report node after the
        assessment was already marked failed elsewhere).  The acting principal is the one
        ``advance`` passed in when seeding, else the one recovered from the checkpoint (the
        only source on a resume); without either we still fail the run and emit the error, but
        skip the notification, which needs an authority to address.
        """
        error = exc if isinstance(exc, CynuxError) else _wrap_unexpected(exc)
        log.error(
            "agent.run.failed",
            run_id=str(run_id),
            error_code=error.code,
            error_category=error.category.value,
            exc_type=type(exc).__name__,
        )
        recovered, stage = await self._recover_context(config)
        actor = principal or recovered

        async with session_scope(self._deps.settings) as session:
            run = await _load_run(session, run_id)
            assessment_id, session_id = _run_identity(run)
            now = _now()
            run.status = AgentRunStatus.FAILED.value
            run.completed_at = now
            run.failure_reason = error.user_message[:4000]
            run.failure_category = error.category.value
            run.heartbeat_at = now
            # current_node is left pointing at the node that raised -- the most useful
            # breadcrumb for an operator asking why the run stopped.
            assessment = await _load_assessment(
                session, run.organization_id, assessment_id, selectinload(Assessment.targets)
            )
            if not assessment.status_enum.is_terminal:
                await transition(
                    session, assessment, AssessmentStatus.FAILED, reason=error.user_message
                )
                # ``transition`` writes failure_reason but not the taxonomy category (SEC-002
                # keeps the two concerns separate); the column is the runner's to set.
                assessment.failure_category = error.category.value
            if actor is not None:
                await notify_assessment_failed(
                    session,
                    actor,
                    assessment_id=assessment_id,
                    target=_target_label(assessment),
                    reason=error.user_message,
                    settings=self._deps.settings,
                    redis=self._deps.redis,
                )
            else:
                log.warning("agent.run.failed_without_principal", run_id=str(run_id))

        emitter = self._deps.emitter(
            session_id=session_id, assessment_id=assessment_id, run_id=run_id
        )
        await emitter.error(error, stage=stage)
        return RunOutcome(
            run_id=run_id, status=AgentRunStatus.FAILED, failure_category=error.category.value
        )

    async def _recover_context(
        self, config: RunnableConfig
    ) -> tuple[Principal | None, AssessmentStage | None]:
        """Read the acting principal and current stage from the last checkpoint.

        On ``resume`` no principal is passed in, so the initiating principal is recovered from
        the state the run was seeded with; :meth:`Principal.from_dict` re-validates the role so
        a tampered checkpoint cannot resurrect an unenforceable authority.  Best-effort: a
        checkpoint that cannot be read -- or a failure so early that none was written -- yields
        ``(None, None)`` and the caller falls back to the ``start`` principal.
        """
        try:
            snapshot = await self._graph.aget_state(config)
        except Exception as exc:
            log.warning("agent.run.state_unavailable", error=type(exc).__name__)
            return None, None
        values = snapshot.values or {}
        principal: Principal | None = None
        raw_principal = values.get("principal")
        if isinstance(raw_principal, dict):
            try:
                principal = Principal.from_dict(raw_principal)
            except Exception as exc:
                log.warning("agent.run.principal_unreadable", error=type(exc).__name__)
        stage: AssessmentStage | None = None
        raw_stage = values.get("stage")
        if isinstance(raw_stage, str) and raw_stage:
            try:
                stage = AssessmentStage(raw_stage)
            except ValueError:
                stage = None
        return principal, stage


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _run_config(thread_id: str) -> RunnableConfig:
    """The LangGraph invocation config that pins a run to its checkpoint thread."""
    return RunnableConfig(configurable={"thread_id": thread_id})


def _outcome_from(run: AgentRun) -> RunOutcome:
    """The recorded outcome of a run that is already terminal, for an idempotent re-dispatch.

    A crash reclaim or a duplicate delivery can re-present a run another worker already drove
    to completion, failure or cancellation.  There is nothing left to run and its terminal
    event was emitted the first time, so the outcome is read straight from the row -- the
    worker acks the message and moves on without re-touching the graph, the database or the
    socket.  ``report_id`` and ``findings_total`` are left at their defaults: the outcome is
    only used to decide *that* the run is done, not to re-render or re-notify.
    """
    return RunOutcome(
        run_id=run.id,
        status=run.status_enum,
        failure_category=run.failure_category,
    )


async def _load_run(session: AsyncSession, run_id: uuid.UUID) -> AgentRun:
    """Load a run by primary key, or refuse: a missing row is a broken queue entry.

    Loaded by PK without a tenant filter on purpose -- the ``run_id`` comes from the worker's
    own queue, not from an untrusted request, and the assessment it points at *is* loaded
    under a tenant filter (defence in depth against a corrupt ``organization_id``).
    """
    run = await session.get(AgentRun, run_id)
    if run is None:
        raise CynuxError(
            f"agent run {run_id} is missing",
            user_message="This assessment run could not be found.",
            context={"run_id": str(run_id)},
        )
    return run


async def _load_assessment(
    session: AsyncSession,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
    *options: ExecutableOption,
) -> Assessment:
    """Load the run's assessment under a tenant filter (SEC-003), for mutation or read.

    Mirrors :func:`app.agent.nodes._common.load_assessment` but keys off the run's own
    columns rather than the graph state, so the runner depends on the authoritative row
    (the run) rather than on channel values a checkpoint could carry.  Pass ``selectinload``
    options for any relationship the caller will touch -- ``LAZY`` turns an un-loaded access
    into a raise.
    """
    stmt = tenant_select(Assessment, organization_id, *options).where(
        Assessment.id == assessment_id
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    return assessment_or_404(row, assessment_id)


def _run_identity(run: AgentRun) -> tuple[uuid.UUID, uuid.UUID]:
    """Narrow a run's nullable ``assessment_id``/``session_id``, or refuse to run it.

    Both columns are nullable at the schema level because ``agent_runs`` also stores chat runs
    with no assessment; an assessment run created by the API always has both.  A row missing
    either is a mis-routed or corrupt queue entry, not a runnable assessment, so fail loudly
    rather than emit events to a null session.
    """
    if run.assessment_id is None or run.session_id is None:
        raise CynuxError(
            f"agent run {run.id} is not a runnable assessment run",
            user_message="This assessment run is misconfigured and cannot be processed.",
            context={"run_id": str(run.id)},
        )
    return run.assessment_id, run.session_id


def _objective_of(assessment: Assessment) -> str:
    """The operator's free-text objective, seeded into ``request_interpretation`` at create.

    Empty string when the assessment began from a bare target rather than a sentence (FR-004);
    the ``understand`` node then produces a targets-only interpretation.
    """
    interpretation = assessment.request_interpretation or {}
    return str(interpretation.get("objective", "") or "")


def _target_label(assessment: Assessment) -> str:
    """A concise label for the assessment's target(s), for the failure alert's subject.

    Reads the eager-loaded ``targets``; falls back to the human reference number.  This names
    the owner's own asset in an alert addressed to them, which SEC-002 (logs, prompts, errors)
    does not govern -- the same carve-out :func:`app.agent.nodes.report._target_label` uses.
    """
    targets = assessment.targets
    if not targets:
        return f"assessment #{assessment.reference}"
    first = targets[0].canonical_value
    if len(targets) == 1:
        return first
    return f"{first} and {len(targets) - 1} more"


def _wrap_unexpected(exc: BaseException) -> CynuxError:
    """Wrap a non-taxonomy exception as an internal :class:`CynuxError` with a safe message.

    The original text is deliberately dropped from the user message and the persisted
    failure reason (SEC-002); the internal message carries the *type name* only, and
    type-name logging happens at the call site.  A base ``CynuxError`` is category
    ``internal_error`` and non-degradable, which is correct for an unclassified failure.
    """
    return CynuxError(
        f"unexpected error: {type(exc).__name__}",
        user_message=_UNEXPECTED_USER_MESSAGE,
        cause=exc,
    )


def _duration_seconds(started_at: dt.datetime | None, end: dt.datetime) -> int | None:
    """Whole seconds from ``started_at`` to ``end``; ``None`` if the run never started."""
    if started_at is None:
        return None
    return max(0, int((end - started_at).total_seconds()))


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["AgentRunner", "RunOutcome", "checkpointer_for"]
