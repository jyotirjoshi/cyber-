"""Node: generate_report -- produce the report and complete the assessment (FR-030, FR-039).

This is the terminal content node.  Everything before it discovered, scanned, imported,
enriched, analyzed, ranked, remediated and actioned; this node turns all of that into the
one artifact the operator asked for -- a stored, downloadable report -- and then moves the
assessment to ``completed``.  It runs during the ``remediating`` status at stage ``report``
and performs the final ``remediating -> completed`` transition at stage ``done``.

**The node is a thin orchestrator; the whole pipeline lives in the service.**
:func:`app.reporting.generate.generate` owns the report end to end -- create the ``pending``
row, mark it ``generating``, build the deterministic context, ask the model for an executive
summary *guarded against invented CVEs/CVSS scores* (FR-024), render HTML (and a PDF when it
can), store the bytes, and settle the row ``ready``.  It commits at each state boundary on
purpose (the documented exception to "services do not commit") so a polling UI can watch the
report being produced.  This node's job is narrow: decide whether a report already exists,
call the service, then complete the assessment and announce it.

**Report *content* degrades inside the service; the node fails only on the two fatal errors
(FR-040).**  An unreachable model or a missing PDF renderer are handled by ``generate`` --
the summary falls back to a computed paragraph, a PDF downgrades to HTML, and both are
recorded as coverage degradations folded into the report itself.  So this node records no
FR-039 degradation of its own.  What ``generate`` does *not* swallow is a broken evidence
chain: :class:`~app.core.errors.StorageError` (the bytes could not be persisted) and
:class:`~app.reporting.render.ReportRenderError` (the report could not be built at all) are
non-degradable, and this node lets them propagate so the runner fails the run -- a report is
the deliverable, and one that cannot be produced or stored is a genuine failure, not a
caveat.

**Reuse makes a resumed run cheap and idempotent.**  A report render is the single most
expensive tail operation (an LLM call plus a PDF), so before generating, the node asks
:func:`app.services.report.latest_report` for an already-``ready`` report.  If the node
crashed after ``generate`` committed the report but before the assessment was completed, the
resumed run reuses that report instead of paying for a second one.  The completion itself is
idempotent too: ``transition`` is a no-op when the assessment is already ``completed`` and
``dispatch`` deduplicates the notification, so re-running this node changes nothing twice.

**Completion and its announcement are one transaction.**  The ``remediating -> completed``
transition, the final :func:`app.services.assessment.refresh_counters` recompute, and the
:func:`app.services.notification.notify_assessment_completed` alert all commit together, so
"the assessment is complete" and "the operator was told" are atomic -- a completed assessment
the owner was never notified about, or an alert for a completion that did not persist, are
both states this avoids.  The run-level bookkeeping (the ``AgentRun`` outcome, the terminal
run event, the *failure* notification) belongs to the runner, not here.

Every log line and step digest carries counts and ids only, never a finding title, a
hostname or a credential (SEC-002).  The target *is* named in the completion alert -- that is
the alert's subject and it is the owner's own asset, which SEC-002 (logs, prompts, errors)
does not govern.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import structlog
from sqlalchemy.orm import selectinload

from app.agent.nodes._common import (
    StepHandle,
    load_assessment,
    principal_from,
    record_step,
)
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.db.enums import AssessmentStage, AssessmentStatus, ReportFormat
from app.db.models.assessment import Assessment
from app.db.session import session_scope
from app.reporting.generate import generate
from app.services.assessment import refresh_counters, transition
from app.services.context import Principal
from app.services.notification import notify_assessment_completed
from app.services.report import latest_report

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "generate_report"

#: The report the agent produces. PDF is the professional deliverable; ``generate`` degrades
#: it to HTML -- and records that as a coverage degradation -- when no PDF renderer is
#: available, so requesting PDF is safe on a host without WeasyPrint. ``technical`` is the
#: fuller of the two audiences: an unattended agent has no operator to ask, so it produces
#: the report that omits the least.
_REPORT_FORMAT = ReportFormat.PDF
_REPORT_AUDIENCE = "technical"

#: Severity buckets for the completion alert, worst first. The alert renders "N critical,
#: N high, ..." and drops the zero buckets, so this is counts-only (SEC-002).
_SEVERITY_FIELDS: tuple[tuple[str, str], ...] = (
    ("critical", "findings_critical"),
    ("high", "findings_high"),
    ("medium", "findings_medium"),
    ("low", "findings_low"),
    ("info", "findings_info"),
)


@dataclass(frozen=True, slots=True)
class _ReportResult:
    """The facts about the produced report the node needs after its loading session closes."""

    report_id: uuid.UUID
    fmt: str
    reused: bool


@dataclass(frozen=True, slots=True)
class _Completion:
    """The facts about the completed assessment, lifted out before its session closes."""

    findings_total: int
    degraded: bool


async def generate_report(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Produce the assessment report, then complete the assessment (FR-030)."""
    await _advance_to_report(state, deps=deps)

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.REPORT,
        label="Building the assessment report",
    ) as step:
        principal = principal_from(state)
        report = await _produce_report(state, deps=deps, principal=principal, step=step)
        completion = await _complete(state, deps=deps, principal=principal, step=step)
        step.record_output(
            {
                "report_id": str(report.report_id),
                "format": report.fmt,
                "reused": report.reused,
                "findings_total": completion.findings_total,
                "degraded": completion.degraded,
            }
        )

    log.info(
        "agent.report.done",
        report_id=str(report.report_id),
        reused=report.reused,
        findings_total=completion.findings_total,
        degraded=completion.degraded,
    )
    return {"stage": AssessmentStage.DONE.value, "report_id": str(report.report_id)}


async def _advance_to_report(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Advance the stage cursor to ``report`` within the ``remediating`` status.

    Idempotent: the remediation and actions nodes already moved the assessment to
    ``remediating``, so this only advances the stage, making the live view show "Building the
    assessment report" while the (multi-second) render runs.  A terminal or cancelling status
    raises :class:`ConflictError`, which correctly refuses to report on an assessment being
    torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await transition(
            session, assessment, AssessmentStatus.REMEDIATING, stage=AssessmentStage.REPORT
        )


async def _produce_report(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal, step: StepHandle
) -> _ReportResult:
    """Reuse an already-``ready`` report if one exists, otherwise generate a fresh one.

    The reuse check is what makes a resumed run cheap: if this node crashed after ``generate``
    committed the report but before the assessment was completed, the ``ready`` row is still
    there and there is no reason to pay for a second render.  ``generate`` runs against the
    bare assessment -- it re-reads every relationship it needs through tenant-scoped queries,
    so no eager load is required here -- and commits internally, so on return the report is
    durable.  A :class:`StorageError` or :class:`ReportRenderError` escaping ``generate`` is
    fatal by design and is left to propagate.
    """
    org_id = state_uuid(state, "organization_id")
    assessment_id = state_uuid(state, "assessment_id")

    async with session_scope(deps.settings) as session:
        existing = await latest_report(
            session, assessment_id, organization_id=org_id, ready_only=True
        )
        reused = (
            _ReportResult(report_id=existing.id, fmt=existing.format, reused=True)
            if existing is not None
            else None
        )

    if reused is not None:
        await step.thinking("A completed report already exists for this assessment; reusing it.")
        return reused

    await step.thinking("Building the assessment report.")
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        report = await generate(
            session,
            assessment,
            fmt=_REPORT_FORMAT,
            audience=_REPORT_AUDIENCE,
            storage=deps.storage,
            settings=deps.settings,
            principal=principal,
        )
        return _ReportResult(report_id=report.id, fmt=report.format, reused=False)


async def _complete(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal, step: StepHandle
) -> _Completion:
    """Move the assessment to ``completed`` and announce it, atomically.

    The transition, the final counter recompute and the completion notification share one
    transaction so the assessment cannot be marked complete without the alert being recorded,
    nor an alert sent for a completion that did not persist.  ``refresh_counters`` is the one
    authoritative writer of the denormalized finding counts, run here so the completed
    assessment's dashboard tiles and the alert's "N critical, N high" line agree with the
    findings table.  The target is named in the alert (its subject) and is loaded eagerly for
    that; it is never logged.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state, selectinload(Assessment.targets))
        await transition(
            session, assessment, AssessmentStatus.COMPLETED, stage=AssessmentStage.DONE
        )
        await refresh_counters(session, assessment)
        counts = _severity_counts(assessment)
        degraded = bool(assessment.degradations)
        findings_total = assessment.findings_total
        await notify_assessment_completed(
            session,
            principal,
            assessment_id=assessment.id,
            target=_target_label(assessment),
            counts=counts,
            settings=deps.settings,
            redis=deps.redis,
            degraded=degraded,
        )

    await step.thinking("Assessment complete.")
    return _Completion(findings_total=findings_total, degraded=degraded)


def _severity_counts(assessment: Assessment) -> dict[str, int]:
    """The denormalized finding counts as a worst-first, name-keyed dict for the alert."""
    return {name: int(getattr(assessment, column)) for name, column in _SEVERITY_FIELDS}


def _target_label(assessment: Assessment) -> str:
    """A concise label for the assessment's target(s), for the completion alert's subject.

    Reads the eager-loaded ``targets``; falls back to the human reference number if a
    targetless assessment somehow reaches here.  This is the owner's own asset named in an
    alert addressed to them, not a leak -- SEC-002 governs logs, prompts and errors.
    """
    targets = assessment.targets
    if not targets:
        return f"assessment #{assessment.reference}"
    first = targets[0].canonical_value
    if len(targets) == 1:
        return first
    return f"{first} and {len(targets) - 1} more"


__all__ = ["generate_report"]
