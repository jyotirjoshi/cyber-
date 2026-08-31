"""Derived progress and the FR-038 stage checklist.

FR-038 promises the operator a live view of where an assessment is: a percentage and a
checklist of stages.  Everything here computes that from two sources of truth --
:data:`~app.db.enums.STAGE_ORDER` and the recorded ``agent_steps`` rows -- and from
nothing else.

That is a deliberate constraint, not an implementation detail.  The obvious alternative is
to let the agent report its own progress ("I'm 80% done"), and it fails in the one way
that matters: a stage the graph skipped would still be rendered as complete, because the
number and the checklist would come from the same optimistic narrator.  Deriving from
recorded steps means a stage can only appear finished if a row says a node finished it, so
the checklist and the audit trail cannot disagree.

The ``percent`` a run reports therefore moves *backwards* in exactly one case -- a resumed
run whose recorded steps show less progress than a stale cached value -- and that is
correct: the recorded steps are what happened.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Sequence
from typing import Protocol

from app.db.enums import (
    STAGE_ORDER,
    AssessmentStage,
    AssessmentStatus,
    StepStatus,
)
from app.schemas.assessment import StageOut

#: Human labels for the checklist. Every member of :data:`STAGE_ORDER` needs one, plus the
#: two stages outside it (``QUEUED``, ``DONE``) so a status line always has something to
#: show.  Kept here rather than in ``enums`` because these are UI copy: they get reworded
#: without a migration, and the enum *values* are what the database stores.
STAGE_LABELS: dict[AssessmentStage, str] = {
    AssessmentStage.QUEUED: "Queued",
    AssessmentStage.UNDERSTANDING: "Understanding request",
    AssessmentStage.VALIDATING: "Validating target",
    AssessmentStage.AUTHORIZING: "Checking authorization",
    AssessmentStage.PLANNING: "Planning assessment",
    AssessmentStage.RECON: "Passive reconnaissance",
    AssessmentStage.ASSET_ANALYSIS: "Analyzing assets",
    AssessmentStage.APPROVAL: "Awaiting your approval",
    AssessmentStage.SCAN_NMAP: "Port and service scan",
    AssessmentStage.SCAN_NUCLEI: "Vulnerability scan",
    AssessmentStage.SCAN_ZAP: "Web application scan",
    AssessmentStage.IMPORT: "Importing findings",
    AssessmentStage.ENRICH: "Threat intelligence",
    AssessmentStage.AI_ANALYSIS: "AI analysis",
    AssessmentStage.PRIORITIZE: "Risk prioritization",
    AssessmentStage.REMEDIATION: "Generating remediation",
    AssessmentStage.ACTIONS: "Creating tickets and alerts",
    AssessmentStage.REPORT: "Building report",
    AssessmentStage.DONE: "Complete",
}

#: Stages that only run for a depth that reaches them. A ``passive`` assessment never
#: scans, and rendering three permanently-pending scan rows would read as "stuck" rather
#: than "not applicable" -- so :func:`stage_checklist` marks them ``SKIPPED``.
_ACTIVE_SCAN_STAGES: frozenset[AssessmentStage] = frozenset(
    {AssessmentStage.SCAN_NMAP, AssessmentStage.SCAN_NUCLEI, AssessmentStage.SCAN_ZAP}
)


class _StepLike(Protocol):
    """The fields :func:`stage_checklist` reads off an ``agent_steps`` row.

    A protocol rather than the ORM class so the function can be called with the rows a
    query returned, with an ``AgentStepOut``, or with a plain stand-in in tests -- and so
    this module does not import the model layer to compute a projection.
    """

    stage: str | None
    status: str
    label: str | None
    degradation_note: str | None
    failure_code: str | None
    started_at: dt.datetime | None
    completed_at: dt.datetime | None


class _AssessmentLike(Protocol):
    status: str
    current_stage: str
    depth: str


def percent_for(stage: AssessmentStage) -> int:
    """Completion percentage for a stage, from its position in :data:`STAGE_ORDER`.

    ``QUEUED`` is 0 and ``DONE`` is 100; everything else is the fraction of the ordered
    stage list *completed on entering* that stage.  Entering a stage means the ones before
    it finished, so ``UNDERSTANDING`` -- the first -- reports 0 rather than 6: a progress
    bar that jumps to 6% before any work has happened overstates what is done, and the
    first stage is precisely where an operator is watching for "did it start at all".
    """
    if stage is AssessmentStage.DONE:
        return 100
    if stage is AssessmentStage.QUEUED:
        return 0
    try:
        index = STAGE_ORDER.index(stage)
    except ValueError:  # pragma: no cover - defensive; every stage is in the map above
        return 0
    return int(index * 100 / len(STAGE_ORDER))


def percent_for_value(raw: str | None) -> int:
    """:func:`percent_for` for the string a database column holds.

    The columns are ``varchar`` with a CHECK rather than a native enum, so an unknown
    value is possible in principle -- from a hand-edited row, or a downgrade after a stage
    was added.  It reports 0 instead of raising: a progress bar is not worth a 500.
    """
    if not raw:
        return 0
    try:
        return percent_for(AssessmentStage(raw))
    except ValueError:
        return 0


def stage_checklist(
    assessment: _AssessmentLike,
    steps: Iterable[_StepLike] = (),
) -> list[StageOut]:
    """The FR-038 checklist: one row per stage in :data:`STAGE_ORDER`, in order.

    Status for each stage is decided in this priority:

    1. **A recorded step wins.**  If ``agent_steps`` has a row for the stage, its status
       is the stage's status.  The most advanced row wins when a stage ran more than once
       (a retry), because a stage that failed and then succeeded is complete.
    2. **The current stage is running**, if no step says otherwise -- the row is written
       when the node finishes, so there is a window where the node is working and nothing
       is recorded yet.
    3. **Stages before the current one are complete** *only* on a terminal-success
       assessment.  Mid-run they stay ``PENDING`` rather than being back-filled: a stage
       with no recorded step did not demonstrably happen, and inferring otherwise is the
       exact failure this function is built to avoid.
    4. **Inapplicable stages are skipped**, not left pending -- see
       :data:`_ACTIVE_SCAN_STAGES`.

    Nothing here consults the agent's own account of its progress.
    """
    status = _status_or_none(assessment.status)
    current = _stage_or_none(assessment.current_stage)
    by_stage = _index_steps(steps)
    current_index = STAGE_ORDER.index(current) if current in STAGE_ORDER else -1
    skipped = _inapplicable_stages(assessment)

    rows: list[StageOut] = []
    for index, stage in enumerate(STAGE_ORDER):
        step = by_stage.get(stage)
        if step is not None:
            rows.append(
                StageOut(
                    stage=stage,
                    label=STAGE_LABELS[stage],
                    status=_step_status(step),
                    started_at=step.started_at,
                    completed_at=step.completed_at,
                    detail=_detail(step),
                )
            )
            continue

        if stage in skipped:
            state = StepStatus.SKIPPED
            detail: str | None = "Not applicable for this assessment depth."
        elif stage is current and status is not None and not status.is_terminal:
            state, detail = StepStatus.RUNNING, None
        elif status is AssessmentStatus.COMPLETED:
            # A completed assessment did pass through every applicable stage; a missing
            # step row here means it produced nothing worth recording, not that it was
            # skipped.
            state, detail = StepStatus.COMPLETED, None
        elif status is not None and status.is_terminal and index >= max(current_index, 0):
            # Failed or cancelled: everything from where it stopped onward never ran.
            state, detail = StepStatus.SKIPPED, _terminal_detail(status)
        else:
            state, detail = StepStatus.PENDING, None

        rows.append(StageOut(stage=stage, label=STAGE_LABELS[stage], status=state, detail=detail))
    return rows


def checklist_percent(rows: Sequence[StageOut]) -> int:
    """Percentage from a rendered checklist: what fraction of it is settled.

    Used where the checklist has already been computed, so the number the UI shows and the
    rows it lists cannot disagree -- the failure mode being a bar at 90% above a list with
    half its stages pending.  ``SKIPPED`` counts as settled: a passive assessment that will
    never scan is not permanently 70% done.
    """
    if not rows:
        return 0
    settled = sum(
        1
        for row in rows
        if row.status in (StepStatus.COMPLETED, StepStatus.SKIPPED, StepStatus.DEGRADED)
    )
    return int(settled * 100 / len(rows))


def stage_for_status(status: AssessmentStatus) -> AssessmentStage:
    """A representative stage for a coarse status.

    Used when a status change arrives without a stage -- a cancellation, or a failure
    raised before any node set one -- so ``current_stage`` is never left describing work
    that is no longer happening.
    """
    return _STATUS_STAGE.get(status, AssessmentStage.QUEUED)


_STATUS_STAGE: dict[AssessmentStatus, AssessmentStage] = {
    AssessmentStatus.CREATED: AssessmentStage.QUEUED,
    AssessmentStatus.PLANNING: AssessmentStage.PLANNING,
    AssessmentStatus.DISCOVERY: AssessmentStage.RECON,
    AssessmentStatus.WAITING_FOR_APPROVAL: AssessmentStage.APPROVAL,
    AssessmentStatus.SCANNING: AssessmentStage.SCAN_NMAP,
    AssessmentStatus.ANALYZING: AssessmentStage.AI_ANALYSIS,
    AssessmentStatus.REMEDIATING: AssessmentStage.REMEDIATION,
    AssessmentStatus.COMPLETED: AssessmentStage.DONE,
    # Failed and cancelled keep whichever stage they stopped at; the caller only falls
    # back to this map when there is none, and "queued" is the honest answer for a run
    # that never got anywhere.
    AssessmentStatus.CANCELLING: AssessmentStage.QUEUED,
    AssessmentStatus.CANCELLED: AssessmentStage.QUEUED,
    AssessmentStatus.FAILED: AssessmentStage.QUEUED,
}


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

#: How far along a step status is, for picking a winner when a stage ran twice. A retry
#: that succeeded outranks the attempt that failed; ``DEGRADED`` outranks ``COMPLETED``
#: because it carries strictly more information -- the note saying what was missing.
_STEP_RANK: dict[StepStatus, int] = {
    StepStatus.PENDING: 0,
    StepStatus.SKIPPED: 1,
    StepStatus.RUNNING: 2,
    StepStatus.FAILED: 3,
    StepStatus.COMPLETED: 4,
    StepStatus.DEGRADED: 5,
}


def _index_steps(steps: Iterable[_StepLike]) -> dict[AssessmentStage, _StepLike]:
    """Most advanced step per stage.

    Steps with no stage -- the error handler, a bare tool call -- are ignored rather than
    bucketed somewhere plausible: a checklist row is a claim about a stage, and a step
    that names no stage cannot support one.
    """
    best: dict[AssessmentStage, _StepLike] = {}
    for step in steps:
        stage = _stage_or_none(step.stage)
        if stage is None or stage not in STAGE_ORDER:
            continue
        incumbent = best.get(stage)
        if incumbent is None or _rank(step) >= _rank(incumbent):
            best[stage] = step
    return best


def _rank(step: _StepLike) -> int:
    status = _step_status(step)
    return _STEP_RANK.get(status, 0)


def _step_status(step: _StepLike) -> StepStatus:
    try:
        return StepStatus(step.status)
    except ValueError:
        return StepStatus.PENDING


def _detail(step: _StepLike) -> str | None:
    """What to show under a checklist row.

    A degradation note comes first: FR-039 requires that a stage which completed without a
    dependency says so, and it is the more actionable of the two.  ``failure_code`` is a
    taxonomy code, never a raw exception message (SEC-002).
    """
    if step.degradation_note:
        return step.degradation_note
    if step.failure_code:
        return step.failure_code
    return step.label


def _inapplicable_stages(assessment: _AssessmentLike) -> frozenset[AssessmentStage]:
    """Stages this assessment's configuration will never reach.

    Only the passive-depth case is decided here.  Whether ZAP runs also depends on
    whether recon found a web asset, and that is not knowable until recon has run -- so
    those stages stay pending and are resolved by their recorded step, which is the honest
    representation of "we do not know yet".
    """
    if assessment.depth == "passive":
        return _ACTIVE_SCAN_STAGES
    return frozenset()


def _terminal_detail(status: AssessmentStatus) -> str | None:
    if status is AssessmentStatus.CANCELLED:
        return "Cancelled before this stage."
    if status is AssessmentStatus.FAILED:
        return "Not reached: the assessment failed earlier."
    return None


def _stage_or_none(raw: str | None) -> AssessmentStage | None:
    if not raw:
        return None
    try:
        return AssessmentStage(raw)
    except ValueError:
        return None


def _status_or_none(raw: str | None) -> AssessmentStatus | None:
    if not raw:
        return None
    try:
        return AssessmentStatus(raw)
    except ValueError:
        return None


__all__ = [
    "STAGE_LABELS",
    "checklist_percent",
    "percent_for",
    "percent_for_value",
    "stage_checklist",
    "stage_for_status",
]
