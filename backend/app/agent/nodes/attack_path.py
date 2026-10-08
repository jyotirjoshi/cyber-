"""Node: attack_path — construct realistic kill-chain attack paths (NEW).

This node runs after enrichment and before AI analysis, giving the reasoning model
full attack-surface context when it writes findings. It:

1. Generates up to 3 multi-hop attack paths using the attack path service.
2. Applies SSVC triage to every finding, adding a decision-support outcome to each row.
3. Runs compound-risk correlation to detect multi-finding attack chains and retain
   possible false positives for analyst review without suppressing analysis.
4. Stores all results on the assessment for use in the report and dashboard.

Design choices:

**Non-fatal.** Every sub-task degrades gracefully. A failed attack-path generation
does not fail the assessment — the findings still get analyzed, prioritized and
reported. The attack path context is additive intelligence, not a gate.

**No new DB columns.** Results are stored in existing JSONB columns:
- Attack paths → ``assessment.extra_data`` (new sub-key ``attack_paths``)
- SSVC results → ``finding.risk_factors`` (new sub-key ``ssvc``)
- Compound risks → ``assessment.extra_data`` (new sub-key ``compound_risks``)
- False positive candidates → ``finding.risk_factors`` when confidence is "high"

**Runs before analysis.** SSVC is available to the analysis node; an AI false-positive
suggestion stays advisory, never automatically closes or skips a finding.
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agent.nodes._common import load_assessment, record_step
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.logging_conf import redact_text
from app.db.enums import AssessmentStage
from app.db.models.finding import Finding
from app.db.session import session_scope
from app.services.attack_path import generate_attack_paths
from app.services.correlation import FalsePositiveCandidate, correlate_findings
from app.services.ssvc import evaluate_ssvc

log = structlog.get_logger(__name__)

_NODE = "attack_path"
_LEGACY_CORRELATION_SKIP = "Flagged as likely false positive by cross-scanner correlation analysis."


async def record_false_positive_candidates(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
    candidates: list[FalsePositiveCandidate],
) -> int:
    """Retain high-confidence AI suggestions without altering finding lifecycle or analysis."""
    by_id = {
        candidate.finding_id: candidate
        for candidate in candidates
        if candidate.confidence == "high"
    }
    if not by_id:
        return 0
    rows = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.id.in_(by_id),
                    Finding.organization_id == organization_id,
                    Finding.assessment_id == assessment_id,
                )
            )
        )
        .scalars()
        .all()
    )
    count = 0
    for finding in rows:
        if finding.organization_id != organization_id or finding.assessment_id != assessment_id:
            continue
        candidate = by_id[finding.id]
        factors = dict(finding.risk_factors or {})
        factors["false_positive_candidate"] = {
            "confidence": "high",
            "reason": redact_text(candidate.reason.strip()[:500]),
            "source": "ai_correlation",
        }
        finding.risk_factors = factors
        if finding.ai_skipped_reason == _LEGACY_CORRELATION_SKIP:
            finding.ai_skipped_reason = None
        count += 1
    return count


async def attack_path(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Build attack paths, apply SSVC triage, and correlate findings."""
    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.AI_ANALYSIS,  # runs within the analyzing phase
        label="Mapping attack surface and kill chains",
    ) as step:
        org_id = state_uuid(state, "organization_id")
        assessment_id = state_uuid(state, "assessment_id")

        # ── 1. SSVC triage ─────────────────────────────────────────────────
        ssvc_counts: dict[str, int] = {}
        try:
            async with session_scope(deps.settings) as session:
                findings = await _load_all_findings(session, assessment_id, org_id)
                for finding in findings:
                    enrichment = getattr(finding, "enrichment", None)
                    result = evaluate_ssvc(finding, enrichment)
                    # Merge SSVC outcome into the existing risk_factors dict
                    factors = dict(finding.risk_factors or {})
                    factors["ssvc"] = result.to_dict()
                    finding.risk_factors = factors
                    ssvc_counts[result.outcome.value] = ssvc_counts.get(result.outcome.value, 0) + 1
                log.info(
                    "attack_path.ssvc_applied",
                    assessment_id=str(assessment_id),
                    findings=len(findings),
                    by_outcome=ssvc_counts,
                )
        except Exception as exc:
            log.warning("attack_path.ssvc_failed", error=type(exc).__name__)

        # ── 2. Attack path generation ───────────────────────────────────────
        paths_stored = 0
        try:
            async with session_scope(deps.settings) as session:
                assessment = await load_assessment(session, state)
                paths = await generate_attack_paths(
                    session,
                    assessment,
                    gateway=deps.gateway,
                    settings=deps.settings,
                )
                if paths:
                    meta = dict(assessment.extra_data or {}) if assessment.extra_data else {}
                    meta["attack_paths"] = [p.model_dump() for p in paths]
                    assessment.extra_data = meta
                    paths_stored = len(paths)
                    await step.thinking(
                        f"Identified {len(paths)} realistic attack path(s). "
                        f"Highest-likelihood: {paths[0].crown_jewel!r} via "
                        f"{paths[0].entry_point!r}."
                    )
        except Exception as exc:
            log.warning("attack_path.paths_failed", error=type(exc).__name__)

        # ── 3. Compound-risk correlation ────────────────────────────────────
        compound_count = 0
        fp_flagged = 0
        try:
            async with session_scope(deps.settings) as session:
                assessment = await load_assessment(session, state)
                correlation_result = await correlate_findings(
                    session,
                    assessment,
                    gateway=deps.gateway,
                    settings=deps.settings,
                )

                # Store compound risks on assessment metadata
                if correlation_result.compound_risks:
                    meta = dict(assessment.extra_data or {}) if assessment.extra_data else {}
                    meta["compound_risks"] = [
                        {
                            "finding_ids": [str(fid) for fid in cr.finding_ids],
                            "title": cr.title,
                            "description": cr.description,
                            "effective_severity": cr.effective_severity,
                            "attack_chain": cr.attack_chain,
                        }
                        for cr in correlation_result.compound_risks
                    ]
                    assessment.extra_data = meta
                    compound_count = len(correlation_result.compound_risks)

                # Keep AI-suggested false positives advisory; analysis must still run.
                if correlation_result.false_positives:
                    fp_flagged = await record_false_positive_candidates(
                        session,
                        organization_id=org_id,
                        assessment_id=assessment_id,
                        candidates=correlation_result.false_positives,
                    )

                if correlation_result.coverage_gaps:
                    meta = dict(assessment.extra_data or {}) if assessment.extra_data else {}
                    meta["coverage_gaps"] = correlation_result.coverage_gaps
                    assessment.extra_data = meta

        except Exception as exc:
            log.warning("attack_path.correlation_failed", error=type(exc).__name__)

        step.record_output(
            {
                "ssvc_by_outcome": ssvc_counts,
                "attack_paths": paths_stored,
                "compound_risks": compound_count,
                "false_positives_flagged": fp_flagged,
            }
        )
        if paths_stored:
            await step.thinking(
                f"Attack surface analysis complete: {paths_stored} kill chain(s), "
                f"{compound_count} compound risk(s), {fp_flagged} possible false-positive "
                "candidate(s) retained for analyst review."
            )

    return {"stage": AssessmentStage.AI_ANALYSIS.value}


async def _load_all_findings(session: AsyncSession, assessment_id, org_id):
    from app.db.enums import FindingStatus

    stmt = (
        select(Finding)
        .options(selectinload(Finding.enrichment))
        .where(
            Finding.assessment_id == assessment_id,
            Finding.organization_id == org_id,
            Finding.status.in_([FindingStatus.ACTIVE.value, FindingStatus.VERIFIED.value]),
            Finding.is_duplicate.is_(False),
        )
        .limit(500)
    )
    return list((await session.execute(stmt)).scalars().all())


__all__ = ["attack_path"]
