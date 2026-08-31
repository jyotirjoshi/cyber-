"""Shared node machinery: the step recorder and the state re-hydration helpers (FR-032, FR-038).

Every node does the same four things around its actual work: re-hydrate the principal and
event emitter from the checkpointed state, load the assessment it operates on under a
tenant filter, and bracket the work in a recorded *step* so the operator's live timeline
and the durable audit trail both see it happen.  Those four live here so a node body is
just its own logic.

The load-bearing piece is :func:`record_step`, and its shape is dictated by one hard
requirement: **a step that fails must still be recorded as failed.**  A node body runs in
its own transaction, and a fatal error rolls that transaction back -- so if the step row
were written in the same transaction as the work, the evidence of the failure would roll
back with the work, and the timeline would show a step eternally "running".  So the
recorder uses three separate transactions:

1. *Before* the body, in its own transaction: write the step as ``running`` and point
   :attr:`AgentRun.current_node` at this node, then commit.  The live checklist can now
   show work in progress through a multi-minute scan.
2. The body runs in *its* own transaction(s), which this recorder never joins.
3. *After* the body: on success, commit the step as ``completed`` (or ``degraded``); on
   failure, mark it ``failed`` in an **independent** transaction that never raises -- the
   same pattern :func:`app.services.audit.record_independently` uses, and for the same
   reason.  The original exception is then re-raised for the runner to turn into a run
   failure.

Progress is emitted from the recorded rows, never self-reported: :func:`record_step`
derives the FR-038 checklist with :func:`app.services.progress.stage_checklist` from the
``agent_steps`` it just wrote, so a stage can only show complete if a row says it is.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.base import ExecutableOption

from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.config import Settings
from app.core.errors import CynuxError
from app.db.enums import AssessmentStage, AuditOutcome, StepStatus
from app.db.models.agent import AgentRun, AgentStep
from app.db.models.assessment import Assessment
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.services import audit as audit_service
from app.services.assessment import assessment_or_404
from app.services.context import Principal
from app.services.events import EventEmitter
from app.services.progress import checklist_percent, stage_checklist

log = structlog.get_logger(__name__)

#: Cap on a single step digest, restated from the SEC-006 rationale in
#: :mod:`app.db.models.agent`: ``input_digest``/``output_digest`` are bounded summaries a
#: reviewer reads, never full scanner payloads.  A caller that hands over something large
#: gets it truncated here rather than one careless join away from a prompt.
_MAX_DIGEST_CHARS = 4000


# ---------------------------------------------------------------------------
# State re-hydration
# ---------------------------------------------------------------------------


def principal_from(state: AssessmentState) -> Principal:
    """Rebuild the acting principal from the checkpointed state.

    :meth:`Principal.from_dict` re-validates the role and actor type, so a hand-edited or
    downgrade-era checkpoint cannot resurrect a principal with an unenforceable role.  It
    is the initiating user's authority, never a superuser's -- a node's permission checks
    are the operator's own.
    """
    return Principal.from_dict(state["principal"])


def emitter_from(deps: AgentDeps, state: AssessmentState) -> EventEmitter:
    """A session-bound emitter for the run described by ``state``.

    Built through :meth:`AgentDeps.emitter` so the session, assessment and run ids come
    from one place and a node cannot publish under the wrong session.
    """
    return deps.emitter(
        session_id=state_uuid(state, "session_id"),
        assessment_id=state_uuid(state, "assessment_id"),
        run_id=state_uuid(state, "run_id"),
    )


async def load_assessment(
    session: AsyncSession,
    state: AssessmentState,
    *options: ExecutableOption,
) -> Assessment:
    """Load the run's assessment under a tenant filter, for mutation by the node.

    Uses :func:`~app.db.repository.tenant_select` rather than
    :func:`~app.services.assessment.get_assessment`: the node is processing the run it was
    created for -- the run's existence is the authority -- so this does not re-gate on the
    ``ASSESSMENT_READ`` permission, but it still refuses to cross a tenant boundary.  Pass
    ``selectinload(...)`` options for any relationship the node will touch, because
    :data:`~app.db.base.LAZY` turns an un-loaded access into a raise rather than a query.
    """
    organization_id = state_uuid(state, "organization_id")
    assessment_id = state_uuid(state, "assessment_id")
    stmt = tenant_select(Assessment, organization_id, *options).where(
        Assessment.id == assessment_id
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    return assessment_or_404(row, assessment_id)


# ---------------------------------------------------------------------------
# The step recorder
# ---------------------------------------------------------------------------


class StepHandle:
    """The body's handle to the step it is running inside.

    A node uses this to attach the *summary* of what it did -- an output digest, an
    artifact reference, a degradation note -- which :func:`record_step` writes onto the
    step row when the body finishes.  It is deliberately not a database object: the body
    mutates a plain value here and the recorder persists it in a separate transaction, so
    nothing the body touches can be accidentally committed with the body's own work.
    """

    __slots__ = (
        "_artifact",
        "_degradation_note",
        "_label",
        "_output",
        "_output_truncated",
        "_tool_name",
        "assessment_id",
        "audit_action",
        "audit_resource_type",
        "emitter",
        "node",
        "org_id",
        "principal",
        "run_id",
        "settings",
        "stage",
        "step_id",
    )

    def __init__(
        self,
        *,
        step_id: uuid.UUID | None,
        run_id: uuid.UUID,
        org_id: uuid.UUID,
        assessment_id: uuid.UUID,
        node: str,
        stage: AssessmentStage | None,
        principal: Principal,
        emitter: EventEmitter,
        settings: Settings,
        audit_action: str | None,
        audit_resource_type: str,
        label: str | None,
        tool_name: str | None,
    ) -> None:
        self.step_id = step_id
        self.run_id = run_id
        self.org_id = org_id
        self.assessment_id = assessment_id
        self.node = node
        self.stage = stage
        self.principal = principal
        self.emitter = emitter
        self.settings = settings
        self.audit_action = audit_action
        self.audit_resource_type = audit_resource_type
        self._label = label
        self._tool_name = tool_name
        self._output: dict[str, Any] = {}
        self._output_truncated = False
        self._artifact: str | None = None
        self._degradation_note: str | None = None

    def record_output(self, digest: dict[str, Any], *, truncated: bool = False) -> None:
        """Attach a JSON-safe summary of what this step produced.

        ``truncated`` records that the digest is partial and the full artifact lives
        elsewhere -- honest partiality rather than a silent cut (SEC-006).
        """
        self._output = _digest(digest)
        self._output_truncated = truncated

    def set_artifact(self, reference: str | None) -> None:
        """Point the step at the object-storage key holding its full output."""
        self._artifact = reference[:1000] if reference else None

    def degrade(self, note: str) -> None:
        """Mark this step ``degraded``: it finished, but without a non-essential input.

        ``note`` must be user-safe -- it renders in the timeline and the report appendix
        (FR-039, SEC-002).  A degraded step is a *success* with a caveat, so the run
        continues; use it for a missing enrichment source, not a fatal error.
        """
        self._degradation_note = note

    def relabel(self, label: str | None) -> None:
        """Replace the one-line activity label once the body knows the specifics.

        A node often opens with a generic label ("Scanning") and refines it when it knows
        the shape of the work ("Scanning 12 hosts with Nmap").
        """
        self._label = label[:300] if label else None

    def set_tool(self, name: str | None) -> None:
        self._tool_name = name[:80] if name else None

    async def thinking(self, text: str) -> None:
        """Narrate progress to the operator, tagged with this node.

        Composed by the node, never lifted from model reasoning, so it cannot echo an
        untrusted prompt back onto the socket (SEC-005).
        """
        await self.emitter.thinking(text, node=self.node)

    def _audit_detail(self) -> dict[str, Any]:
        detail: dict[str, Any] = {"node": self.node}
        if self.stage is not None:
            detail["stage"] = self.stage.value
        detail.update(self._output)
        return detail


@asynccontextmanager
async def record_step(
    deps: AgentDeps,
    state: AssessmentState,
    *,
    node: str,
    stage: AssessmentStage | None = None,
    label: str | None = None,
    tool_name: str | None = None,
    audit_action: str | None = None,
    audit_resource_type: str = "assessment",
    input_digest: dict[str, Any] | None = None,
) -> AsyncIterator[StepHandle]:
    """Bracket a node's work in a recorded, event-emitting, audited step.

    Yields a :class:`StepHandle` the body attaches its output summary to.  See the module
    docstring for the three-transaction structure; the short version is that the step is
    written ``running`` before the body and settled (``completed`` / ``degraded`` /
    ``failed``) after it, in transactions separate from the body's own so the record of a
    failure survives the rollback of the work that failed.

    ``audit_action`` writes an :mod:`~app.services.audit` row for genuine tool
    invocations (FR-032); leave it unset for steps whose domain services already audit
    themselves (a status transition, a degradation), so nothing is audited twice.  Run
    status (``running`` / ``interrupted`` / ``completed`` / ``failed``) is the runner's
    to manage, not this recorder's -- it owns only the step rows, the ``current_node``
    cursor, the progress events and the optional tool audit.
    """
    run_id = state_uuid(state, "run_id")
    org_id = state_uuid(state, "organization_id")
    assessment_id = state_uuid(state, "assessment_id")
    principal = principal_from(state)
    emitter = emitter_from(deps, state)
    started = _now()

    step_id = await _begin_step(
        settings=deps.settings,
        emitter=emitter,
        org_id=org_id,
        run_id=run_id,
        assessment_id=assessment_id,
        node=node,
        stage=stage,
        label=label,
        tool_name=tool_name,
        input_digest=input_digest,
    )

    handle = StepHandle(
        step_id=step_id,
        run_id=run_id,
        org_id=org_id,
        assessment_id=assessment_id,
        node=node,
        stage=stage,
        principal=principal,
        emitter=emitter,
        settings=deps.settings,
        audit_action=audit_action,
        audit_resource_type=audit_resource_type,
        label=label,
        tool_name=tool_name,
    )

    try:
        yield handle
    except Exception as exc:
        # Only ``Exception`` -- a ``CancelledError`` during worker shutdown is left to
        # propagate untouched rather than risk a database write mid-cancellation; the
        # orphaned ``running`` step is reconciled by the worker's recovery sweep.
        await _fail_step(handle, exc, started)
        raise
    else:
        await _settle_step(handle, started)


# ---------------------------------------------------------------------------
# Step lifecycle internals
# ---------------------------------------------------------------------------


async def _begin_step(
    *,
    settings: Settings,
    emitter: EventEmitter,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    assessment_id: uuid.UUID,
    node: str,
    stage: AssessmentStage | None,
    label: str | None,
    tool_name: str | None,
    input_digest: dict[str, Any] | None,
) -> uuid.UUID | None:
    """Write the ``running`` step and advance the run cursor, in one committed transaction.

    Returns the new step's id, or ``None`` if the write failed -- in which case the body
    still runs (its work matters more than its timeline row) and the settle/fail path
    below tolerates the missing id.
    """
    try:
        async with session_scope(settings) as session:
            seq = await _next_step_seq(session, org_id, run_id)
            step = AgentStep(
                organization_id=org_id,
                run_id=run_id,
                seq=seq,
                node=node,
                stage=stage.value if stage else None,
                tool_name=tool_name,
                status=StepStatus.RUNNING.value,
                label=label,
                input_digest=_digest(input_digest),
                started_at=_now(),
            )
            session.add(step)
            run = await session.get(AgentRun, run_id)
            if run is not None:
                run.current_node = node
                if tool_name:
                    run.tool_call_count += 1
            await session.flush()
            step_id = step.id
            await _emit_progress(
                session,
                emitter,
                org_id=org_id,
                run_id=run_id,
                assessment_id=assessment_id,
                fallback_stage=stage,
            )
            return step_id
    except Exception as exc:
        log.warning("agent.step.begin_failed", node=node, error=type(exc).__name__)
        return None


async def _settle_step(handle: StepHandle, started: dt.datetime) -> None:
    """Commit the step as ``completed`` (or ``degraded``) and emit updated progress."""
    ended = _now()
    duration_ms = int((ended - started).total_seconds() * 1000)
    status = StepStatus.DEGRADED if handle._degradation_note else StepStatus.COMPLETED
    try:
        async with session_scope(handle.settings) as session:
            await _apply_terminal(
                session, handle, status=status, ended=ended, duration_ms=duration_ms
            )
            if handle.audit_action:
                await audit_service.record(
                    session,
                    action=handle.audit_action,
                    principal=handle.principal,
                    resource_type=handle.audit_resource_type,
                    resource_id=handle.assessment_id,
                    outcome=AuditOutcome.SUCCESS,
                    detail=handle._audit_detail(),
                )
            await _emit_progress(
                session,
                handle.emitter,
                org_id=handle.org_id,
                run_id=handle.run_id,
                assessment_id=handle.assessment_id,
                fallback_stage=handle.stage,
            )
    except Exception as exc:
        log.warning("agent.step.settle_failed", node=handle.node, error=type(exc).__name__)


async def _fail_step(handle: StepHandle, exc: Exception, started: dt.datetime) -> None:
    """Record the step as ``failed`` in an independent transaction that never raises.

    The body's transaction has already rolled back, taking its work with it; this writes
    the failed step in a fresh transaction so the timeline and the audit trail keep the
    evidence.  It swallows its own errors -- it runs on the way to re-raising the original,
    and an error here must not replace the one being reported (mirrors
    :func:`app.services.audit.record_independently`).  The error *event* is left to the
    runner, which owns the run's terminal failure and would otherwise double-emit.
    """
    ended = _now()
    duration_ms = int((ended - started).total_seconds() * 1000)
    cynux = exc if isinstance(exc, CynuxError) else None
    failure_code = (cynux.code if cynux else type(exc).__name__)[:60]
    failure_detail = (
        cynux.user_message if cynux else "The agent hit an unexpected error at this step."
    )
    try:
        async with session_scope(handle.settings) as session:
            await _apply_terminal(
                session,
                handle,
                status=StepStatus.FAILED,
                ended=ended,
                duration_ms=duration_ms,
                failure_code=failure_code,
                failure_detail=failure_detail,
            )
            if handle.audit_action:
                await audit_service.record(
                    session,
                    action=handle.audit_action,
                    principal=handle.principal,
                    resource_type=handle.audit_resource_type,
                    resource_id=handle.assessment_id,
                    outcome=AuditOutcome.FAILURE,
                    reason=failure_detail,
                    detail=handle._audit_detail(),
                )
    except Exception as inner:
        log.warning("agent.step.fail_record_failed", node=handle.node, error=type(inner).__name__)
    log.warning(
        "agent.step.failed",
        node=handle.node,
        failure_code=failure_code,
        error=type(exc).__name__,
    )


async def _apply_terminal(
    session: AsyncSession,
    handle: StepHandle,
    *,
    status: StepStatus,
    ended: dt.datetime,
    duration_ms: int,
    failure_code: str | None = None,
    failure_detail: str | None = None,
) -> None:
    """Write the collected outcome onto the step row, if it exists."""
    if handle.step_id is None:
        return
    step = await session.get(AgentStep, handle.step_id)
    if step is None:  # pragma: no cover - the row was just written in _begin_step
        return
    step.status = status.value
    step.completed_at = ended
    step.duration_ms = duration_ms
    step.output_digest = handle._output
    step.output_truncated = handle._output_truncated
    step.artifact_reference = handle._artifact
    step.degradation_note = handle._degradation_note
    step.failure_code = failure_code
    step.failure_detail = failure_detail
    if handle._label is not None:
        step.label = handle._label
    if handle._tool_name is not None:
        step.tool_name = handle._tool_name


async def _emit_progress(
    session: AsyncSession,
    emitter: EventEmitter,
    *,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    assessment_id: uuid.UUID,
    fallback_stage: AssessmentStage | None,
) -> None:
    """Emit an FR-038 progress event derived from the recorded steps.

    Best-effort: progress is observability, and a failure to render the checklist must not
    fail the step that was otherwise fine (mirrors the never-fail-a-run rule in
    :mod:`app.services.events`).  The checklist comes from ``agent_steps`` and
    :data:`~app.db.enums.STAGE_ORDER`, never from anything the agent asserted about itself.
    """
    try:
        assessment = await _load_assessment_row(session, org_id, assessment_id)
        steps = (
            (
                await session.execute(
                    tenant_select(AgentStep, org_id)
                    .where(AgentStep.run_id == run_id)
                    .order_by(AgentStep.seq)
                )
            )
            .scalars()
            .all()
        )
        # ``stage_checklist`` types its inputs as plain-``str`` Protocols; the ORM rows
        # expose those attributes as ``Mapped[str]``, which the SQLAlchemy mypy plugin
        # would fold back to ``str`` -- but ``plugins = []`` here, and descriptor
        # ``__get__`` is not consulted for Protocol member matching.  The runtime contract
        # holds (instance access yields ``str``), so this bridges the static gap only.
        rows = stage_checklist(assessment, steps)  # type: ignore[arg-type]
        await emitter.progress(
            stage=_progress_stage(fallback_stage, assessment),
            progress_percent=checklist_percent(rows),
            stages=list(rows),
        )
    except Exception as exc:
        log.debug("agent.progress.emit_failed", error=type(exc).__name__)


async def _load_assessment_row(
    session: AsyncSession,
    org_id: uuid.UUID,
    assessment_id: uuid.UUID,
) -> Assessment:
    stmt = tenant_select(Assessment, org_id).where(Assessment.id == assessment_id)
    row = (await session.execute(stmt)).scalar_one_or_none()
    return assessment_or_404(row, assessment_id)


async def _next_step_seq(session: AsyncSession, org_id: uuid.UUID, run_id: uuid.UUID) -> int:
    """The next per-run step sequence, ``max + 1``.

    The graph runs one node at a time within a run, so there is no concurrent writer to
    race the ``(run_id, seq)`` unique constraint -- unlike the event ``seq``, which several
    emitters share and which Redis therefore allocates with ``INCR``.
    """
    current = (
        await session.execute(
            select(func.max(AgentStep.seq)).where(
                AgentStep.organization_id == org_id,
                AgentStep.run_id == run_id,
            )
        )
    ).scalar()
    return int(current or 0) + 1


def _progress_stage(step_stage: AssessmentStage | None, assessment: Assessment) -> AssessmentStage:
    """The stage to label a progress event with: this step's, else the assessment's."""
    if step_stage is not None:
        return step_stage
    try:
        return AssessmentStage(assessment.current_stage)
    except ValueError:  # pragma: no cover - column is CHECK-constrained
        return AssessmentStage.QUEUED


def _digest(value: dict[str, Any] | None) -> dict[str, Any]:
    """Bound a digest to :data:`_MAX_DIGEST_CHARS`, replacing an oversized value in place.

    Charges each value against a shared budget and truncates the one that overruns rather
    than dropping keys, so a large ``stdout`` never crowds out the small ``exit_code`` that
    follows it -- the same reasoning as :func:`app.services.audit._bounded`.
    """
    if not value:
        return {}
    out: dict[str, Any] = {}
    budget = _MAX_DIGEST_CHARS
    for key, item in value.items():
        text = item if isinstance(item, str) else repr(item)
        if len(text) > budget:
            out[str(key)] = text[:budget] + "…"
            break
        out[str(key)] = item
        budget -= len(text)
    return out


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "StepHandle",
    "emitter_from",
    "load_assessment",
    "principal_from",
    "record_step",
]
