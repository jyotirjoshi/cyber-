"""Derived progress and the FR-038 checklist (``app/services/progress.py``).

Three classes of bug this file exists to catch.

**An unlabelled stage is a crash.**  :func:`stage_checklist` indexes
``STAGE_LABELS[stage]`` without a guard, so adding a member to ``AssessmentStage`` and
forgetting the label turns the progress endpoint into a ``KeyError``.  Pinning the map
against the enum makes that a test failure at the moment the member is added.

**Back-filling is the failure FR-038 is written against.**  The tempting implementation
marks every stage before the current one complete.  It reports work that may never have
run -- a stage the graph skipped renders identically to one that finished.  Several tests
below assert the *absence* of that inference, which no amount of reading the code proves.

**The bar and the list must agree.**  A header reading 90% above a checklist with half its
rows pending is the specific incoherence :func:`checklist_percent` prevents, so it is
tested against real checklists rather than hand-made row lists alone.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

from app.db.enums import (
    STAGE_ORDER,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    StepStatus,
)
from app.schemas.agent import ProgressData
from app.schemas.assessment import StageOut
from app.services.progress import (
    STAGE_LABELS,
    checklist_percent,
    percent_for,
    percent_for_value,
    stage_checklist,
    stage_for_status,
)

NOW = dt.datetime(2026, 3, 1, 12, 0, tzinfo=dt.UTC)


@dataclasses.dataclass
class Step:
    """Stand-in for an ``agent_steps`` row, satisfying ``progress._StepLike``.

    A dataclass rather than the ORM model: ``progress`` takes a ``Protocol`` precisely so
    it can be exercised without a database, and constructing a real ``AgentStep`` would
    drag in a run, a session and an organization to test a pure projection.
    """

    stage: str | None = None
    status: str = StepStatus.COMPLETED.value
    label: str | None = None
    degradation_note: str | None = None
    failure_code: str | None = None
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None


@dataclasses.dataclass
class FakeAssessment:
    """Stand-in satisfying ``progress._AssessmentLike``."""

    status: str = AssessmentStatus.SCANNING.value
    current_stage: str = AssessmentStage.SCAN_NMAP.value
    depth: str = AssessmentDepth.STANDARD.value


def _row(rows: list[StageOut], stage: AssessmentStage) -> StageOut:
    """The checklist row for one stage. Fails loudly rather than returning ``None``."""
    for row in rows:
        if row.stage is stage:
            return row
    raise AssertionError(f"no checklist row for {stage}")


# ---------------------------------------------------------------------------
# STAGE_LABELS
# ---------------------------------------------------------------------------


def test_every_stage_has_a_label() -> None:
    """``stage_checklist`` indexes the map unguarded; a gap is a 500, not a blank cell."""
    missing = [stage.name for stage in AssessmentStage if stage not in STAGE_LABELS]
    assert not missing, f"AssessmentStage members without a STAGE_LABELS entry: {missing}"


def test_no_label_describes_a_stage_that_does_not_exist() -> None:
    """A leftover label is a rename that only half happened."""
    extra = [str(key) for key in STAGE_LABELS if key not in set(AssessmentStage)]
    assert not extra, f"STAGE_LABELS entries for unknown stages: {extra}"


@pytest.mark.parametrize("stage", list(AssessmentStage))
def test_labels_are_ui_copy_not_enum_values(stage: AssessmentStage) -> None:
    """Labels are prose, so a pasted ``stage.value`` is a bug worth failing on.

    The distinction matters because the enum value is the database's; rewording a label
    must not need a migration, and ``scanning_nmap`` appearing in a UI is the symptom of
    the two having been conflated.
    """
    label = STAGE_LABELS[stage]
    assert label, f"{stage.name} has an empty label"
    assert label != stage.value
    assert "_" not in label
    assert label[0].isupper()


# ---------------------------------------------------------------------------
# percent_for
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stage", list(AssessmentStage))
def test_percent_is_in_range_for_every_stage(stage: AssessmentStage) -> None:
    """``ProgressData.progress_percent`` is ``ge=0, le=100``; an out-of-range value would
    make the emitter raise inside a node rather than report progress."""
    percent = percent_for(stage)
    assert 0 <= percent <= 100
    ProgressData(stage=stage, progress_percent=percent)


def test_percent_never_decreases_along_stage_order() -> None:
    percents = [percent_for(stage) for stage in STAGE_ORDER]
    assert percents == sorted(percents)


def test_the_first_stage_reports_zero() -> None:
    """Documented behaviour: entering a stage means the ones before it finished, and
    nothing precedes the first one. A bar that starts at 6% overstates the work done."""
    assert percent_for(STAGE_ORDER[0]) == 0


def test_queued_is_zero_and_done_is_one_hundred() -> None:
    assert percent_for(AssessmentStage.QUEUED) == 0
    assert percent_for(AssessmentStage.DONE) == 100


def test_only_done_reports_one_hundred() -> None:
    """Otherwise a run sitting in the last stage looks finished before the report exists."""
    at_hundred = [s.name for s in AssessmentStage if percent_for(s) == 100]
    assert at_hundred == [AssessmentStage.DONE.name]


@pytest.mark.parametrize("raw", [None, "", "not_a_stage", "SCANNING_NMAP"])
def test_unknown_stage_values_report_zero(raw: str | None) -> None:
    """A hand-edited row or a post-downgrade value must not 500 a progress bar.

    ``"SCANNING_NMAP"`` is in the list on purpose: the columns are case-sensitive
    ``varchar``, so the upper-cased spelling is *not* a valid stage.
    """
    assert percent_for_value(raw) == 0


@pytest.mark.parametrize("stage", list(AssessmentStage))
def test_percent_for_value_matches_percent_for(stage: AssessmentStage) -> None:
    assert percent_for_value(stage.value) == percent_for(stage)


# ---------------------------------------------------------------------------
# stage_checklist -- shape
# ---------------------------------------------------------------------------


def test_checklist_is_one_row_per_stage_in_stage_order() -> None:
    rows = stage_checklist(FakeAssessment())
    assert [row.stage for row in rows] == list(STAGE_ORDER)


def test_checklist_rows_are_labelled() -> None:
    rows = stage_checklist(FakeAssessment())
    assert all(row.label == STAGE_LABELS[row.stage] for row in rows)


def test_checklist_excludes_queued_and_done() -> None:
    """They are status decorations, not work: neither has a node that can complete it."""
    stages = {row.stage for row in stage_checklist(FakeAssessment())}
    assert AssessmentStage.QUEUED not in stages
    assert AssessmentStage.DONE not in stages


# ---------------------------------------------------------------------------
# stage_checklist -- the no-back-filling rule
# ---------------------------------------------------------------------------


def test_unrecorded_earlier_stages_stay_pending_mid_run() -> None:
    """The regression this module exists to prevent.

    ``RECON`` is running and nothing has been recorded for the stages before it. Marking
    them complete would be an inference from position alone -- exactly what FR-038 forbids,
    because a stage the graph skipped would then be indistinguishable from one that ran.
    """
    assessment = FakeAssessment(
        status=AssessmentStatus.DISCOVERY.value,
        current_stage=AssessmentStage.RECON.value,
    )
    rows = stage_checklist(assessment)

    assert _row(rows, AssessmentStage.RECON).status is StepStatus.RUNNING
    for earlier in (
        AssessmentStage.UNDERSTANDING,
        AssessmentStage.VALIDATING,
        AssessmentStage.AUTHORIZING,
        AssessmentStage.PLANNING,
    ):
        assert _row(rows, earlier).status is StepStatus.PENDING, earlier


def test_synthesized_rows_carry_no_timestamps() -> None:
    """A row with no step behind it must not show a start time.

    Timestamps come from recorded steps only; inventing one would put a fabricated
    "started 12:04" under a stage that never ran.
    """
    rows = stage_checklist(
        FakeAssessment(
            status=AssessmentStatus.DISCOVERY.value,
            current_stage=AssessmentStage.RECON.value,
        )
    )
    running = _row(rows, AssessmentStage.RECON)
    assert (running.started_at, running.completed_at) == (None, None)


def test_a_recorded_step_supplies_status_and_timestamps() -> None:
    step = Step(
        stage=AssessmentStage.PLANNING.value,
        status=StepStatus.COMPLETED.value,
        started_at=NOW,
        completed_at=NOW + dt.timedelta(seconds=9),
    )
    row = _row(stage_checklist(FakeAssessment(), [step]), AssessmentStage.PLANNING)
    assert row.status is StepStatus.COMPLETED
    assert row.started_at == NOW
    assert row.completed_at == NOW + dt.timedelta(seconds=9)


def test_a_recorded_step_outranks_the_current_stage() -> None:
    """``current_stage`` lags: it is not cleared when a node finishes.

    Without this precedence a completed stage would flip back to "running" for as long as
    the column still names it.
    """
    assessment = FakeAssessment(
        status=AssessmentStatus.DISCOVERY.value,
        current_stage=AssessmentStage.RECON.value,
    )
    step = Step(stage=AssessmentStage.RECON.value, status=StepStatus.COMPLETED.value)
    assert _row(stage_checklist(assessment, [step]), AssessmentStage.RECON).status is (
        StepStatus.COMPLETED
    )


def test_the_current_stage_is_not_running_once_the_assessment_is_terminal() -> None:
    """A failed run leaves ``current_stage`` pointing at where it died.

    Rendering that as RUNNING shows a spinner on a run that stopped hours ago.
    """
    assessment = FakeAssessment(
        status=AssessmentStatus.FAILED.value,
        current_stage=AssessmentStage.SCAN_NUCLEI.value,
    )
    assert _row(stage_checklist(assessment), AssessmentStage.SCAN_NUCLEI).status is not (
        StepStatus.RUNNING
    )


# ---------------------------------------------------------------------------
# stage_checklist -- retries and degradation
# ---------------------------------------------------------------------------


def test_the_most_advanced_step_wins_for_a_retried_stage() -> None:
    """A stage that failed and then succeeded is complete, whatever order the rows came in."""
    failed = Step(stage=AssessmentStage.RECON.value, status=StepStatus.FAILED.value)
    ok = Step(stage=AssessmentStage.RECON.value, status=StepStatus.COMPLETED.value)
    for steps in ([failed, ok], [ok, failed]):
        row = _row(stage_checklist(FakeAssessment(), steps), AssessmentStage.RECON)
        assert row.status is StepStatus.COMPLETED


def test_degraded_outranks_completed() -> None:
    """FR-039: a stage that finished without a dependency must say so.

    ``DEGRADED`` carries strictly more information than ``COMPLETED`` -- the note naming
    what was missing -- so a retry that merely completed must not erase it.
    """
    degraded = Step(
        stage=AssessmentStage.ENRICH.value,
        status=StepStatus.DEGRADED.value,
        degradation_note="KEV unavailable; exploited-in-the-wild flags omitted.",
    )
    completed = Step(stage=AssessmentStage.ENRICH.value, status=StepStatus.COMPLETED.value)
    row = _row(stage_checklist(FakeAssessment(), [completed, degraded]), AssessmentStage.ENRICH)
    assert row.status is StepStatus.DEGRADED
    assert row.detail == "KEV unavailable; exploited-in-the-wild flags omitted."


def test_detail_prefers_the_degradation_note() -> None:
    step = Step(
        stage=AssessmentStage.ENRICH.value,
        status=StepStatus.DEGRADED.value,
        degradation_note="NVD rate limited.",
        failure_code="integration.unavailable",
        label="Threat intelligence",
    )
    row = _row(stage_checklist(FakeAssessment(), [step]), AssessmentStage.ENRICH)
    assert row.detail == "NVD rate limited."


def test_detail_falls_back_to_the_failure_code_then_the_label() -> None:
    """``failure_code`` is a taxonomy code, never an exception message (SEC-002)."""
    coded = Step(
        stage=AssessmentStage.SCAN_ZAP.value,
        status=StepStatus.FAILED.value,
        failure_code="scanner.timeout",
        label="Web application scan",
    )
    plain = Step(
        stage=AssessmentStage.SCAN_ZAP.value,
        status=StepStatus.COMPLETED.value,
        label="Web application scan",
    )
    assert _row(stage_checklist(FakeAssessment(), [coded]), AssessmentStage.SCAN_ZAP).detail == (
        "scanner.timeout"
    )
    assert _row(stage_checklist(FakeAssessment(), [plain]), AssessmentStage.SCAN_ZAP).detail == (
        "Web application scan"
    )


def test_steps_with_no_stage_are_ignored() -> None:
    """The error handler and bare tool calls record no stage.

    Bucketing them somewhere plausible would make a checklist row assert something about a
    stage on evidence that names a different one.
    """
    rows = stage_checklist(
        FakeAssessment(
            status=AssessmentStatus.DISCOVERY.value,
            current_stage=AssessmentStage.RECON.value,
        ),
        [Step(stage=None, status=StepStatus.COMPLETED.value)],
    )
    assert all(
        row.status in (StepStatus.PENDING, StepStatus.RUNNING)
        for row in rows
        if row.stage is not AssessmentStage.RECON
    )


def test_an_unknown_step_status_is_treated_as_pending() -> None:
    """``agent_steps.status`` is ``varchar`` with a CHECK, not a native enum."""
    step = Step(stage=AssessmentStage.RECON.value, status="wat")
    assert _row(stage_checklist(FakeAssessment(), [step]), AssessmentStage.RECON).status is (
        StepStatus.PENDING
    )


def test_an_unknown_assessment_status_does_not_crash_the_checklist() -> None:
    rows = stage_checklist(FakeAssessment(status="MIGRATED", current_stage="who_knows"))
    assert [row.stage for row in rows] == list(STAGE_ORDER)
    assert all(row.status is StepStatus.PENDING for row in rows)


# ---------------------------------------------------------------------------
# stage_checklist -- terminal states
# ---------------------------------------------------------------------------


def test_a_completed_assessment_shows_every_stage_settled() -> None:
    """A finished run with sparse step rows must not render half a checklist.

    Here the inference is sound in a way it is not mid-run: the assessment reached
    ``COMPLETED``, which is only reachable through the report node.
    """
    assessment = FakeAssessment(
        status=AssessmentStatus.COMPLETED.value,
        current_stage=AssessmentStage.DONE.value,
    )
    rows = stage_checklist(assessment, [Step(stage=AssessmentStage.REPORT.value)])
    assert all(
        row.status in (StepStatus.COMPLETED, StepStatus.SKIPPED, StepStatus.DEGRADED)
        for row in rows
    )
    assert checklist_percent(rows) == 100


def test_a_failed_assessment_skips_the_stages_it_never_reached() -> None:
    assessment = FakeAssessment(
        status=AssessmentStatus.FAILED.value,
        current_stage=AssessmentStage.SCAN_NMAP.value,
    )
    rows = stage_checklist(assessment)
    later = STAGE_ORDER[STAGE_ORDER.index(AssessmentStage.SCAN_NMAP) :]
    for stage in later:
        row = _row(rows, stage)
        assert row.status is StepStatus.SKIPPED, stage
        assert row.detail == "Not reached: the assessment failed earlier."


def test_a_cancelled_assessment_says_it_was_cancelled() -> None:
    """The distinction is the whole point: cancelled is a decision, failed is a fault."""
    assessment = FakeAssessment(
        status=AssessmentStatus.CANCELLED.value,
        current_stage=AssessmentStage.APPROVAL.value,
    )
    row = _row(stage_checklist(assessment), AssessmentStage.SCAN_NUCLEI)
    assert row.status is StepStatus.SKIPPED
    assert row.detail == "Cancelled before this stage."


def test_a_terminal_failure_does_not_rewrite_stages_that_did_run() -> None:
    """Recorded evidence outlives the outcome: the stages that completed still say so."""
    assessment = FakeAssessment(
        status=AssessmentStatus.FAILED.value,
        current_stage=AssessmentStage.SCAN_NMAP.value,
    )
    steps = [
        Step(stage=AssessmentStage.RECON.value, status=StepStatus.COMPLETED.value),
        Step(stage=AssessmentStage.ASSET_ANALYSIS.value, status=StepStatus.COMPLETED.value),
    ]
    rows = stage_checklist(assessment, steps)
    assert _row(rows, AssessmentStage.RECON).status is StepStatus.COMPLETED
    assert _row(rows, AssessmentStage.ASSET_ANALYSIS).status is StepStatus.COMPLETED


# ---------------------------------------------------------------------------
# stage_checklist -- depth
# ---------------------------------------------------------------------------


def test_a_passive_assessment_skips_the_scan_stages() -> None:
    """FR-008 passive depth never probes, so three permanently-pending scan rows would
    read as "stuck" rather than "not applicable"."""
    assessment = FakeAssessment(
        status=AssessmentStatus.DISCOVERY.value,
        current_stage=AssessmentStage.RECON.value,
        depth=AssessmentDepth.PASSIVE.value,
    )
    rows = stage_checklist(assessment)
    for stage in (
        AssessmentStage.SCAN_NMAP,
        AssessmentStage.SCAN_NUCLEI,
        AssessmentStage.SCAN_ZAP,
    ):
        row = _row(rows, stage)
        assert row.status is StepStatus.SKIPPED, stage
        assert row.detail == "Not applicable for this assessment depth."


@pytest.mark.parametrize("depth", [AssessmentDepth.STANDARD, AssessmentDepth.DEEP])
def test_an_active_assessment_leaves_the_scan_stages_open(depth: AssessmentDepth) -> None:
    """Whether ZAP runs depends on what recon finds, which is not knowable yet.

    Pending is the honest representation of "we do not know"; pre-emptively skipping the
    stage would be a claim the code cannot support at this point.
    """
    assessment = FakeAssessment(
        status=AssessmentStatus.DISCOVERY.value,
        current_stage=AssessmentStage.RECON.value,
        depth=depth.value,
    )
    rows = stage_checklist(assessment)
    assert _row(rows, AssessmentStage.SCAN_ZAP).status is StepStatus.PENDING


# ---------------------------------------------------------------------------
# checklist_percent
# ---------------------------------------------------------------------------


def test_checklist_percent_of_nothing_is_zero() -> None:
    assert checklist_percent([]) == 0


def test_checklist_percent_counts_settled_rows() -> None:
    rows = stage_checklist(
        FakeAssessment(
            status=AssessmentStatus.DISCOVERY.value,
            current_stage=AssessmentStage.RECON.value,
        ),
        [
            Step(stage=AssessmentStage.UNDERSTANDING.value),
            Step(stage=AssessmentStage.VALIDATING.value),
        ],
    )
    assert checklist_percent(rows) == int(2 * 100 / len(STAGE_ORDER))


def test_a_passive_assessment_is_not_permanently_short_of_a_hundred() -> None:
    """``SKIPPED`` counts as settled, so a run that will never scan can still reach 100."""
    assessment = FakeAssessment(
        status=AssessmentStatus.COMPLETED.value,
        current_stage=AssessmentStage.DONE.value,
        depth=AssessmentDepth.PASSIVE.value,
    )
    assert checklist_percent(stage_checklist(assessment)) == 100


def test_a_running_stage_is_not_counted_as_progress() -> None:
    """Counting the in-flight stage would report work that is still going on as done."""
    rows = stage_checklist(
        FakeAssessment(
            status=AssessmentStatus.DISCOVERY.value,
            current_stage=AssessmentStage.RECON.value,
        )
    )
    assert checklist_percent(rows) == 0


# ---------------------------------------------------------------------------
# stage_for_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", list(AssessmentStatus))
def test_stage_for_status_answers_for_every_status(status: AssessmentStatus) -> None:
    """Called when a status change arrives with no stage -- a cancel, or a failure raised
    before any node set one -- so it must never leave ``current_stage`` unwritten."""
    assert isinstance(stage_for_status(status), AssessmentStage)


def test_waiting_for_approval_maps_to_the_approval_stage() -> None:
    """The mapping an operator reads as "it is waiting on me"."""
    assert stage_for_status(AssessmentStatus.WAITING_FOR_APPROVAL) is AssessmentStage.APPROVAL


def test_completed_maps_to_done() -> None:
    assert stage_for_status(AssessmentStatus.COMPLETED) is AssessmentStage.DONE
