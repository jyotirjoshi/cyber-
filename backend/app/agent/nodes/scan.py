"""Node: execute_scanners -- the approved, active scan (FR-011, FR-006, FR-040).

This is the one node that runs an *active* scanner against a target, and it sits directly
behind the FR-011 approval interrupt (``interrupt_before=["execute_scanners"]``).  Everything
before it -- recon, discovery -- is passive (FR-008); everything it does here sends packets to
a customer's systems, so its whole design is about not doing that without live, re-checked
authority.

**Authority is re-read from the database, never trusted from graph state.**  A checkpoint can
be hours stale and an approval can be granted, customized, rejected or revoked in the gap, so
the node calls :func:`app.services.approval.granted_approval` inside its own transaction and
drives its target set from that approval's ``approved_payload`` alone
(:func:`~app.services.approval.approval_targets`).  ``granted_approval`` already filters to a
resolved, granted decision, so a ``None`` return means *do not scan*.  The ``approval_id`` in
the channel is a convenience for logging; it is never authority (see :mod:`app.agent.state`).

**Every approved target is re-validated (FR-006).**  Recon wrote its discovered assets without
a policy check, and the org's deny-list may have grown since the operator approved the scope,
so each ``asset.name`` is put back through :func:`app.core.targets.validate_target` against the
org-augmented policy.  That both produces the canonical string the scanner layer requires and
drops any host that is now private, deny-listed or malformed -- the policy gate the recon path
deliberately left to this node.

**It drives ``execute_job`` directly, unlike :mod:`app.agent.nodes.recon`.**  Recon replicates
the job lifecycle because it must read ``out/`` before the workdir is purged; this node has no
such need -- the scanner report is DefectDojo's to parse (the importer node uploads it from
object storage), so :func:`app.services.job.execute_job` owns the whole lifecycle: mark
RUNNING, heartbeat, run the sandboxed container, archive artifacts, finalize the row, purge the
workdir, and write the SCANNER_START/COMPLETE/FAIL audit rows (FR-032).  The node only claims a
concurrency slot around each run (FR-014) and releases it in a ``finally``.

**A failed scanner is not a failed assessment (FR-040).**  No capacity, a refused invocation,
a crash, a timeout -- each is folded into an FR-039 degradation and the run proceeds to
analysis with whatever it has.  ``execute_job`` records a scanner fault on the job row and then
*re-raises* a :class:`~app.core.errors.ScannerError`, which this node catches and degrades on;
only a failure to advance the state machine or persist a step is fatal, and that is left to
:func:`~app.agent.nodes._common.record_step`.

The node transitions the assessment ``waiting_for_approval -> scanning`` and, when a scope was
approved, runs Nmap, Nuclei and ZAP in turn.  Nothing about a host reaches the socket or the
logs -- summaries and degradation notes carry counts only (SEC-002).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Literal

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.nodes._common import StepHandle, load_assessment, record_step
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.config import Settings, TargetPolicySettings
from app.core.errors import InvalidTargetError, ScannerError, TargetDeniedError
from app.core.targets import validate_target
from app.db.enums import (
    AssessmentStage,
    AssessmentStatus,
    JobStatus,
    RiskLevel,
    ScannerName,
)
from app.db.models.assessment import Approval
from app.db.models.asset import Asset
from app.db.models.identity import Organization
from app.db.models.scanner import ScannerJob
from app.db.session import session_scope
from app.services.approval import approval_targets, granted_approval
from app.services.assessment import record_degradation, transition
from app.services.asset import assets_by_ids
from app.services.job import claim_slot, enqueue_job, execute_job, release_slot
from app.services.organization import load_policy

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers and the
#: ``interrupt_before=["execute_scanners"]`` the runner compiles the approval gate with.
_NODE = "execute_scanners"

#: How long to wait for a free concurrency slot before giving up and degrading, mirroring
#: :mod:`app.agent.nodes.recon`. A minute of bounded polling lets transient contention clear
#: without holding the graph open indefinitely.
_SLOT_WAIT_SECONDS = 60.0
_SLOT_POLL_SECONDS = 3.0

#: The active scanners, in execution order. Also the allow-list: an approved scope that somehow
#: named a non-scanner (or recon) is filtered against this, so only these three ever run here.
_ACTIVE_SCANNERS: tuple[ScannerName, ...] = (
    ScannerName.NMAP,
    ScannerName.NUCLEI,
    ScannerName.ZAP,
)

#: The progress stage each scanner reports under. :mod:`app.services.progress` indexes the
#: FR-038 checklist by stage, so one step per scanner at its own stage keeps the timeline right.
_SCAN_STAGE: dict[ScannerName, AssessmentStage] = {
    ScannerName.NMAP: AssessmentStage.SCAN_NMAP,
    ScannerName.NUCLEI: AssessmentStage.SCAN_NUCLEI,
    ScannerName.ZAP: AssessmentStage.SCAN_ZAP,
}

#: Operator-facing scanner names for labels, summaries and degradation notes.
_SCANNER_LABELS: dict[ScannerName, str] = {
    ScannerName.NMAP: "Nmap",
    ScannerName.NUCLEI: "Nuclei",
    ScannerName.ZAP: "OWASP ZAP",
}

#: FR-002 risk badge per scanner. ZAP crawls and submits forms, so it is the highest-risk of
#: the three even in its passive baseline mode.
_RISK_LEVEL: dict[ScannerName, RiskLevel] = {
    ScannerName.NMAP: RiskLevel.MEDIUM,
    ScannerName.NUCLEI: RiskLevel.MEDIUM,
    ScannerName.ZAP: RiskLevel.HIGH,
}

# -- user-safe degradation notes and impacts (SEC-002: counts and names only, never hosts) ---

_IMPACT_NOT_RUN = "Findings this scanner would have produced are not included in the results."
_IMPACT_PARTIAL = "This scan did not complete, so its findings may be incomplete."
_IMPACT_NO_SCAN = (
    "Only passive reconnaissance results are available; no active vulnerability scanning was "
    "performed."
)

_NO_APPROVAL_NOTE = (
    "No approved scan scope was found, so no active scanning was performed. Findings are "
    "limited to passive reconnaissance."
)
_NO_SCANNERS_NOTE = "The approved scope included no scanners, so no active scanning was performed."
_NO_TARGETS_NOTE = (
    "None of the approved targets are permitted by the current target policy, so no active "
    "scanning was performed."
)


@dataclass(frozen=True, slots=True)
class _ScanPlan:
    """What the authorization transaction decided, carried into the run phase without an ORM row.

    ``skip`` is set when the node must do nothing at all (a terminal or otherwise unexpected
    status): the assessment is left untouched.  ``jobs`` empty with ``skip`` false is the
    *no-scan* case -- the assessment was advanced to ``scanning`` but nothing was approved, so
    ``no_scan_reason`` explains why for the timeline and the report appendix.
    """

    skip: bool
    jobs: list[tuple[ScannerName, list[str]]]
    no_scan_reason: str


async def execute_scanners(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Run the approved active scanners in sandboxed containers (FR-011, FR-006, FR-040)."""
    if state.get("scanned"):
        # A crash-resume after this node already ran. The scan is durable on the job rows;
        # re-running would re-scan the targets, so this is a hard no-op.
        return {"scanned": True}

    plan = await _authorize_and_plan(deps, state)
    if plan.skip:
        return {"scanned": True}

    if not plan.jobs:
        # Advanced to ``scanning`` but nothing was approved to scan. Record one degraded step
        # for timeline visibility and an FR-039 degradation so the report explains the gap.
        async with record_step(
            deps,
            state,
            node=_NODE,
            stage=AssessmentStage.SCAN_NMAP,
            label="No active scanning",
        ) as step:
            await step.thinking(plan.no_scan_reason)
            step.degrade(plan.no_scan_reason)
            step.record_output({"scanned": 0})
            await _degrade(
                deps,
                state,
                stage=AssessmentStage.SCAN_NMAP,
                reason=plan.no_scan_reason,
                impact=_IMPACT_NO_SCAN,
            )
        return {"scanned": True, "stage": AssessmentStage.SCAN_NMAP.value}

    for scanner, targets in plan.jobs:
        async with record_step(
            deps,
            state,
            node=_NODE,
            stage=_SCAN_STAGE[scanner],
            label=f"Scanning {len(targets)} target(s) with {_SCANNER_LABELS[scanner]}",
            tool_name=scanner.value,
            input_digest={"scanner": scanner.value, "targets": len(targets)},
        ) as step:
            # A ScannerError must be caught *inside* the body: record_step re-raises any
            # Exception as a failed run (FR-040 would be violated otherwise).
            await _run_scanner(deps, state, step, scanner, targets)

    return {"scanned": True, "stage": _SCAN_STAGE[plan.jobs[-1][0]].value}


# ---------------------------------------------------------------------------
# Authorization and planning: re-read the approval, re-validate every target
# ---------------------------------------------------------------------------


async def _authorize_and_plan(deps: AgentDeps, state: AssessmentState) -> _ScanPlan:
    """Re-read authority from the database and decide what to scan, in one transaction.

    The security-critical step (FR-011): the granting approval is re-read here, not trusted
    from the channel, and the scope comes from its ``approved_payload`` alone.  The assessment
    is then advanced ``waiting_for_approval -> scanning`` in *both* the scan and no-scan
    branches, because that is the only forward path past the interrupt and the downstream
    analysis node expects ``scanning``; the transition is idempotent when a crash-resume finds
    the assessment already ``scanning``.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        status = assessment.status_enum
        if status not in (AssessmentStatus.WAITING_FOR_APPROVAL, AssessmentStatus.SCANNING):
            # Terminal, cancelling, or a status this node has no business acting from. The
            # ``scanned`` guard already prevents normal re-entry; this covers a stale or
            # hand-edited checkpoint without raising a transition ConflictError.
            log.info("agent.scan.skip_status", status=status.value)
            return _ScanPlan(skip=True, jobs=[], no_scan_reason="")

        approval = await granted_approval(session, state_uuid(state, "assessment_id"))
        targets, scanners, reason = await _resolve_scope(session, state, approval, deps.settings)

        await transition(
            session, assessment, AssessmentStatus.SCANNING, stage=AssessmentStage.SCAN_NMAP
        )

        if not targets or not scanners:
            return _ScanPlan(skip=False, jobs=[], no_scan_reason=reason)
        # The same re-validated target set goes to every approved scanner; each adapter
        # reshapes it to its own needs (Nmap to bare hosts, ZAP to web origins) and refuses if
        # nothing usable remains, which surfaces here as a per-scanner degradation.
        return _ScanPlan(
            skip=False,
            jobs=[(scanner, targets) for scanner in scanners],
            no_scan_reason="",
        )


async def _resolve_scope(
    session: AsyncSession,
    state: AssessmentState,
    approval: Approval | None,
    settings: Settings,
) -> tuple[list[str], list[ScannerName], str]:
    """The approved, re-validated ``(targets, scanners)`` -- or empties with a reason.

    Reads the approval's ``approved_payload`` (never ``requested_payload``, never graph state),
    resolves the approved asset ids to rows under a tenant filter, and re-validates each against
    the org-augmented policy (FR-006).  The scanner set is intersected with
    :data:`_ACTIVE_SCANNERS` so ordering is fixed and a stray non-scanner cannot run.
    """
    if approval is None:
        return [], [], _NO_APPROVAL_NOTE

    asset_ids, scanner_values = approval_targets(approval)
    scanners = [scanner for scanner in _ACTIVE_SCANNERS if scanner.value in scanner_values]
    if not scanners:
        return [], [], _NO_SCANNERS_NOTE

    org_id = state_uuid(state, "organization_id")
    assets = await assets_by_ids(session, org_id, asset_ids)
    policy = await _scan_policy(session, org_id, settings)
    targets = _canonical_targets(assets, policy)
    if not targets:
        return [], [], _NO_TARGETS_NOTE

    return targets, scanners, ""


async def _scan_policy(
    session: AsyncSession, org_id: uuid.UUID, settings: Settings
) -> TargetPolicySettings:
    """The global target policy augmented with the org's extra deny entries (mirrors
    ``assessment._policy_for``).

    :func:`app.services.organization.load_policy` is synchronous and defaults safely, so a
    missing or malformed org policy simply yields the global settings.
    """
    organization = await session.get(Organization, org_id)
    if organization is None:
        return settings.targets
    extra = load_policy(organization).denied_targets
    if not extra:
        return settings.targets
    return settings.targets.model_copy(update={"deny_list": [*settings.targets.deny_list, *extra]})


def _canonical_targets(assets: list[Asset], policy: TargetPolicySettings) -> list[str]:
    """Re-validate each approved asset and return its canonical scanner string, de-duplicated.

    This is the FR-006 gate the recon path defers: a host that has become private or landed on
    the deny-list since approval is dropped here.  The dropped host is never logged -- only the
    policy code that dropped it (SEC-002).
    """
    seen: dict[str, None] = {}
    for asset in assets:
        try:
            validated = validate_target(asset.name, policy)
        except (InvalidTargetError, TargetDeniedError) as exc:
            log.info("agent.scan.target_dropped", reason=exc.code)
            continue
        seen.setdefault(validated.canonical, None)
    return list(seen)


# ---------------------------------------------------------------------------
# Execution: one slot-bounded ``execute_job`` per scanner, degrading on any fault
# ---------------------------------------------------------------------------


async def _run_scanner(
    deps: AgentDeps,
    state: AssessmentState,
    step: StepHandle,
    scanner: ScannerName,
    targets: list[str],
) -> None:
    """Claim a slot, run one scanner through ``execute_job``, and degrade on any scanner fault.

    Never re-raises a :class:`ScannerError`: a scanner failure is recorded on the job row by
    ``execute_job`` and folded into a degradation here (FR-040).  The slot is released in a
    ``finally`` so a crash between claim and release cannot leak capacity.
    """
    org_id = state_uuid(state, "organization_id")
    label = _SCANNER_LABELS[scanner]

    if not await _acquire_slot(deps, org_id):
        await _emit_tool(step, scanner, status="failed", summary=f"No capacity for {label}")
        step.record_output({"scanner": scanner.value, "status": "no_capacity"})
        await _apply_degradation(
            deps, state, step, scanner, reason=_capacity_reason(scanner), impact=_IMPACT_NOT_RUN
        )
        return

    await _emit_tool(
        step,
        scanner,
        status="started",
        summary=f"Scanning {len(targets)} target(s) with {label}",
    )
    status: str | None = None
    duration_ms: int | None = None
    failure: ScannerError | None = None
    try:
        status, duration_ms = await _enqueue_and_execute(deps, state, scanner, targets)
    except ScannerError as exc:
        # A refused invocation, an unreachable daemon, a crash or a timeout are all this class.
        # None of them fail the assessment -- they degrade it.
        failure = exc
    finally:
        await release_slot(deps.redis, deps.settings, org_id)

    if failure is not None:
        log.warning("agent.scan.scanner_failed", scanner=scanner.value, failure_code=failure.code)
        await _emit_tool(step, scanner, status="failed", summary=f"{label} could not run")
        step.record_output(
            {
                "scanner": scanner.value,
                "status": JobStatus.FAILED.value,
                "failure_code": failure.code,
            }
        )
        await _apply_degradation(
            deps, state, step, scanner, reason=_fatal_reason(scanner), impact=_IMPACT_NOT_RUN
        )
        return

    succeeded = status == JobStatus.COMPLETED.value
    await _emit_tool(
        step,
        scanner,
        status="succeeded" if succeeded else "failed",
        summary=f"{label} {'completed' if succeeded else 'did not finish cleanly'}",
        duration_ms=duration_ms,
    )
    step.record_output({"scanner": scanner.value, "status": status or JobStatus.FAILED.value})
    if not succeeded:
        await _apply_degradation(
            deps, state, step, scanner, reason=_partial_reason(scanner), impact=_IMPACT_PARTIAL
        )


async def _apply_degradation(
    deps: AgentDeps,
    state: AssessmentState,
    step: StepHandle,
    scanner: ScannerName,
    *,
    reason: str,
    impact: str,
) -> None:
    """Mark this step degraded and record the matching assessment-level degradation (FR-039)."""
    step.degrade(reason)
    await _degrade(deps, state, stage=_SCAN_STAGE[scanner], reason=reason, impact=impact)


async def _enqueue_and_execute(
    deps: AgentDeps,
    state: AssessmentState,
    scanner: ScannerName,
    targets: list[str],
) -> tuple[str, int | None]:
    """Enqueue the job, then run it to a terminal state; returns ``(job status, duration ms)``.

    Two transactions: the first creates and commits the QUEUED row (which audits the enqueue),
    the second hands a fresh instance to :func:`app.services.job.execute_job`.  ``execute_job``
    commits its own session repeatedly and runs its own heartbeat, so it gets its own scope --
    it must not share the enqueue's.  A fatal scanner fault is recorded on the row by
    ``execute_job`` and re-raised as a :class:`ScannerError` for :func:`_run_scanner` to degrade
    on; a timeout or non-zero exit returns a non-``COMPLETED`` status without raising.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        job = await enqueue_job(session, assessment, scanner=scanner, targets=targets)
        job_id = job.id

    async with session_scope(deps.settings) as session:
        row = await session.get(ScannerJob, job_id)
        if row is None:  # pragma: no cover - the row was just committed above
            raise ScannerError(
                "scanner job disappeared between enqueue and execution",
                context={"job_id": str(job_id)},
            )
        finished = await execute_job(
            session, row, runner=deps.runner, storage=deps.storage, settings=deps.settings
        )
        status = finished.status
        duration = finished.duration_seconds

    duration_ms = int(duration * 1000) if duration is not None else None
    return status, duration_ms


async def _acquire_slot(deps: AgentDeps, org_id: uuid.UUID) -> bool:
    """Claim one concurrency slot, waiting briefly for capacity (FR-014, mirrors recon).

    :func:`app.services.job.claim_slot` fails closed on a Redis outage; the bounded poll lets
    transient contention clear without holding the graph open indefinitely.
    """
    attempts = max(1, int(_SLOT_WAIT_SECONDS / _SLOT_POLL_SECONDS))
    for attempt in range(attempts):
        if await claim_slot(deps.redis, deps.settings, org_id):
            return True
        if attempt + 1 < attempts:
            await asyncio.sleep(_SLOT_POLL_SECONDS)
    return False


async def _emit_tool(
    step: StepHandle,
    scanner: ScannerName,
    *,
    status: Literal["started", "succeeded", "failed"],
    summary: str,
    duration_ms: int | None = None,
) -> None:
    """Emit an FR-002 tool-activity event through the step's emitter (counts only, SEC-002).

    Best-effort by construction: :meth:`EventEmitter.tool_call` publishes through the event
    bus, which swallows a Redis outage, so this never fails the scan.
    """
    await step.emitter.tool_call(
        tool=scanner.value,
        status=status,
        risk_level=_RISK_LEVEL[scanner],
        summary=summary,
        duration_ms=duration_ms,
    )


async def _degrade(
    deps: AgentDeps,
    state: AssessmentState,
    *,
    stage: AssessmentStage,
    reason: str,
    impact: str,
) -> None:
    """Record an FR-039 degradation in its own transaction; never fail the run over it.

    ``record_degradation`` writes its own ASSESSMENT_DEGRADED audit row.  Bookkeeping, so a
    failure to persist the note degrades to a log line rather than failing the assessment;
    ``except Exception`` leaves a ``CancelledError`` to propagate untouched.
    """
    try:
        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            await record_degradation(
                session,
                assessment,
                stage=stage,
                component="scanner",
                reason=reason,
                impact=impact,
            )
    except Exception as exc:
        log.warning("agent.scan.degrade_record_failed", error=type(exc).__name__)


def _capacity_reason(scanner: ScannerName) -> str:
    return f"{_SCANNER_LABELS[scanner]} was skipped because no scanning capacity was available."


def _partial_reason(scanner: ScannerName) -> str:
    return f"{_SCANNER_LABELS[scanner]} did not finish cleanly; its results may be incomplete."


def _fatal_reason(scanner: ScannerName) -> str:
    return f"{_SCANNER_LABELS[scanner]} could not be run."


__all__ = ["execute_scanners"]
