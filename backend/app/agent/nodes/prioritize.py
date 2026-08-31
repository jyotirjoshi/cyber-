"""Node: prioritize_findings -- deterministic risk scoring and banding (FR-023).

Analysis explained the findings; this node ranks them.  It runs during the ``analyzing`` status at
stage ``risk_prioritization`` and turns the raw pile into an ordered worklist: every finding gets a
numeric ``risk_score`` and a P1..P4 ``priority`` band, computed from six weighted components --
severity, CVSS, KEV membership, EPSS probability, asset criticality and exposure.

**The scoring lives entirely in the service, and that is the point.**
:func:`app.services.finding.prioritize` is deterministic and self-documenting: the six components,
their weights and the exact inputs land in each finding's ``risk_factors`` so the score can be
recomputed by hand from the row, and the weights are module constants precisely so two deployments
cannot produce different P1 sets from the same data.  This node adds no judgement of its own; it
advances the stage, calls the service inside one transaction, and records a counts-only summary of
the resulting distribution.

**No degradation path, by design.**  Unlike enrichment and AI analysis, prioritisation has no
external dependency to lose -- it reads columns already on the findings (the enrichment context was
folded into ``risk_factors`` upstream, and a provider that was down is already recorded as a
degradation on the assessment).  So there is nothing here to catch: the scoring either completes or
a genuine database failure fails the step, which is correct, because an assessment cannot present a
risk order it could not compute.

The service writes its own ``FINDING_PRIORITIZE`` audit row, so this node leaves ``audit_action``
unset to avoid double-auditing.  The summary carries severity/priority labels and counts only --
never a finding title, a hostname, or a CVE (SEC-002).
"""

from __future__ import annotations

import structlog

from app.agent.nodes._common import (
    StepHandle,
    load_assessment,
    record_step,
)
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.db.enums import AssessmentStage, AssessmentStatus
from app.db.session import session_scope
from app.services.assessment import transition
from app.services.finding import findings_for_assessment, prioritize, risk_summary

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "prioritize_findings"


async def prioritize_findings(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Score and band every finding on the assessment by risk (FR-023)."""
    await _advance_to_prioritize(state, deps=deps)

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.PRIORITIZE,
        label="Prioritizing findings by risk",
    ) as step:
        await _prioritize(state, deps=deps, step=step)

    return {"stage": AssessmentStage.PRIORITIZE.value}


async def _advance_to_prioritize(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Advance the stage cursor to ``risk_prioritization`` within the ``analyzing`` status.

    Idempotent: analysis already moved the assessment to ``analyzing``, so this only advances the
    stage; in the passive path where the earlier analysis stages were skipped it also carries
    ``discovery -> analyzing``.  A terminal or cancelling status raises :class:`ConflictError`,
    which correctly refuses to score an assessment that is being torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await transition(
            session, assessment, AssessmentStatus.ANALYZING, stage=AssessmentStage.PRIORITIZE
        )


async def _prioritize(state: AssessmentState, *, deps: AgentDeps, step: StepHandle) -> None:
    """Score every finding, then summarise the resulting distribution for the timeline.

    Order matters against ``lazy="raise_on_sql"``.  :func:`prioritize` loads the findings itself
    with the enrichment relationship eager-loaded, because its scoring reads that relationship; a
    pre-query here would put the same instances in the identity map *without* enrichment and turn
    that eager load into a no-op, so the score would raise.  So the service runs first.  Afterwards
    the findings are flushed and re-read only to build the counts-only digest -- and
    :func:`risk_summary` deliberately reads ``risk_factors`` rather than the enrichment
    relationship, so this second read is safe regardless of how the rows were loaded.
    """
    org_id = state_uuid(state, "organization_id")

    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await prioritize(session, assessment, settings=deps.settings)
        await session.flush()
        findings = await findings_for_assessment(session, assessment.id, organization_id=org_id)
        summary = risk_summary(findings)

    total = int(summary["total"])
    if total == 0:
        await step.thinking("No findings required prioritization.")
    else:
        await step.thinking(f"Scored and ranked {total} finding(s) into P1-P4 risk bands.")

    step.record_output(
        {
            "findings": total,
            "by_priority": summary["by_priority"],
            "by_severity": summary["by_severity"],
            "in_kev": summary["in_kev"],
            "kev_undetermined": summary["kev_undetermined"],
            "intelligence_unavailable": summary["intelligence_unavailable"],
        }
    )


__all__ = ["prioritize_findings"]
