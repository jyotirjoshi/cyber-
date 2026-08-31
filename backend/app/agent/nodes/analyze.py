"""Node: analyze_findings -- grounded AI analysis of each finding (FR-021, FR-022, FR-024).

With the findings imported and enriched, this node asks the reasoning model to explain each one
in plain language, spell out its business impact, and sketch a realistic attack scenario -- the
paragraphs a human reviewer actually reads.  It runs during the ``analyzing`` status at stage
``ai_analysis``.

**The node is a thin orchestrator; the anti-hallucination rules live in the service.**  Every
load-bearing guarantee -- that the model is handed exactly one set of citable sources, that a
sentence asserting a CVE or CVSS score not present in the evidence is rejected, that an
unreachable knowledge base degrades the analysis instead of being answered from memory (FR-021,
FR-024) -- is enforced inside :func:`app.services.finding.analyze_finding`, which also self-audits
every attempt.  This node's job is narrow: pick the findings worth spending tokens on, resolve the
per-tenant knowledge-base client, and walk the batch.

**A finding at a time, each in its own transaction.**  Analysis is a sequence of individual LLM
calls, so -- unlike the enrichment batch -- the node commits per finding rather than holding one
connection open across the whole run.  That makes ``analyze_finding``'s idempotency real across a
crash: a completed analysis is durable the moment it is written, and a resumed run skips it
(``ai_analyzed_at`` is set) instead of billing the operator for the same paragraph twice.

**A model outage degrades the run; it does not fail it (FR-040).**  ``analyze_finding`` already
swallows content problems -- an unverifiable claim becomes a recorded skip, not an exception.  What
can still escape is infrastructure: :class:`ModelUnavailableError` if the provider is down, or a
per-finding :class:`AIError` (a response too large for the budget, a malformed reply after
retries).  A provider that is down will fail every remaining finding identically, so the node stops
early and records one degradation rather than hammering it N times.  A per-finding error skips just
that finding, with a written reason so a blank row never looks like a bug.  Either way the run
continues, because the next node -- deterministic risk prioritisation -- and the report still
deliver real value without the AI narrative.

Every summary and note is counts-only: never a finding title, a hostname, a CVE's affected product,
or a credential (SEC-002).
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.nodes._common import (
    StepHandle,
    load_assessment,
    principal_from,
    record_step,
)
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.errors import AIError, ModelUnavailableError
from app.db.enums import AssessmentStage, AssessmentStatus, IntegrationKind
from app.db.models.finding import Finding
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.integrations.dify import DifyClient
from app.services.assessment import record_degradation, transition
from app.services.context import Principal
from app.services.finding import analysis_candidates, analyze_finding
from app.services.integration import resolve_settings

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "analyze_findings"

#: Written onto a finding whose analysis raised a per-finding AI error, so the row carries a
#: reason instead of an unexplained blank (SEC-002: no leak, matches ``analysis_candidates``).
_SKIP_REASON = "Automated analysis could not be completed for this finding and was skipped."

_DEGRADE_NOTE = "AI analysis was incomplete: the reasoning model was unavailable."

_IMPACT_MODEL = (
    "The reasoning model could not be reached, so some findings have no AI explanation. Their "
    "deterministic risk ranking is unaffected, but the written analysis is missing."
)


async def analyze_findings(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Generate grounded AI analysis for every candidate finding (FR-021, FR-022, FR-024)."""
    await _advance_to_analysis(state, deps=deps)

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.AI_ANALYSIS,
        label="Analyzing findings with AI",
    ) as step:
        await _analyze(state, deps=deps, step=step)

    return {"stage": AssessmentStage.AI_ANALYSIS.value}


async def _advance_to_analysis(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Advance the stage cursor to ``ai_analysis`` within the ``analyzing`` status.

    Idempotent: enrichment already moved the assessment to ``analyzing`` at the
    ``threat_intelligence`` stage, so this only advances the stage; in the passive path where
    import and enrichment were skipped it also carries ``discovery -> analyzing``.  A terminal or
    cancelling status raises :class:`ConflictError`, which correctly refuses to analyze an
    assessment that is being torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await transition(
            session, assessment, AssessmentStatus.ANALYZING, stage=AssessmentStage.AI_ANALYSIS
        )


async def _analyze(state: AssessmentState, *, deps: AgentDeps, step: StepHandle) -> None:
    """Select the candidates, then analyze each one in its own transaction.

    ``analysis_candidates`` both selects the findings worth analyzing and writes an
    ``ai_skipped_reason`` onto the ones it excludes (below the severity floor, or past the budget);
    committing the selection transaction persists those marks before the long per-finding loop
    begins and releases the connection while the model works.
    """
    principal = principal_from(state)

    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        candidates = await analysis_candidates(session, assessment, settings=deps.settings)
        candidate_ids = [finding.id for finding in candidates]

    if not candidate_ids:
        await step.thinking("No findings met the analysis threshold; nothing to analyze.")
        step.record_output({"candidates": 0, "analyzed": 0})
        return

    dify = await _dify_client(state, deps=deps, principal=principal)
    await step.thinking(f"Analyzing {len(candidate_ids)} finding(s) with the reasoning model.")

    analyzed = 0
    skipped = 0
    model_unavailable = False
    for finding_id in candidate_ids:
        try:
            async with session_scope(deps.settings) as session:
                await analyze_finding(
                    session,
                    principal,
                    finding_id,
                    gateway=deps.gateway,
                    dify=dify,
                    settings=deps.settings,
                )
            analyzed += 1
        except ModelUnavailableError as exc:
            # The provider is down; every remaining finding would fail identically. Stop and
            # degrade rather than issue N doomed calls.
            model_unavailable = True
            log.warning("agent.analyze.model_unavailable", error=exc.code)
            break
        except AIError as exc:
            # A per-finding failure (budget/malformed). Record a reason so the row is not a silent
            # blank, then move on -- one finding must not abort the batch.
            log.warning("agent.analyze.finding_skipped", error=exc.code)
            await _mark_finding_skipped(state, deps=deps, finding_id=finding_id)
            skipped += 1

    if model_unavailable:
        await _degrade(state, deps=deps)
        step.degrade(_DEGRADE_NOTE)

    step.record_output(
        {
            "candidates": len(candidate_ids),
            "analyzed": analyzed,
            "skipped": skipped,
            "model_unavailable": model_unavailable,
        }
    )


async def _dify_client(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal
) -> DifyClient | None:
    """The per-tenant knowledge-base client, or ``None`` when no KB is configured.

    A missing knowledge base is not an error (``require=False``): ``analyze_finding`` treats
    ``None`` as "no KB chunks in the evidence" and grounds its analysis on the scanner observation
    and intelligence enrichment alone (FR-021).
    """
    async with session_scope(deps.settings) as session:
        scoped = await resolve_settings(
            session, principal, IntegrationKind.DIFY, settings=deps.settings
        )
    client = DifyClient(scoped, deps.redis)
    return client if client.configured else None


async def _mark_finding_skipped(
    state: AssessmentState, *, deps: AgentDeps, finding_id: uuid.UUID
) -> None:
    """Record a skip reason on a finding whose analysis raised, in its own transaction.

    The failed analysis transaction rolled back, so ``analyze_finding`` never got to write the
    reason itself; this compensating write keeps the "no analysis without an explanation" invariant
    that :func:`analysis_candidates` relies on.  Best-effort: a failure here must not turn a skipped
    finding into a failed run.  ``except Exception`` leaves a ``CancelledError`` to propagate.
    """
    try:
        async with session_scope(deps.settings) as session:
            finding = await _load_finding(session, state, finding_id)
            if finding is not None and finding.ai_analyzed_at is None:
                finding.ai_skipped_reason = _SKIP_REASON
    except Exception as exc:
        log.warning("agent.analyze.skip_record_failed", error=type(exc).__name__)


async def _load_finding(
    session: AsyncSession, state: AssessmentState, finding_id: uuid.UUID
) -> Finding | None:
    """Load one finding under the run's tenant filter (SEC-003)."""
    org_id = state_uuid(state, "organization_id")
    stmt = tenant_select(Finding, org_id).where(Finding.id == finding_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _degrade(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Record an FR-039 degradation for an unavailable model; never fail the run over it.

    ``record_degradation`` writes its own ASSESSMENT_DEGRADED audit row.  ``except Exception``
    leaves a ``CancelledError`` to propagate untouched (mirrors :mod:`app.agent.nodes.enrich`).
    """
    reason = "The reasoning model was unavailable during analysis; some findings were not analyzed."
    try:
        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            await record_degradation(
                session,
                assessment,
                stage=AssessmentStage.AI_ANALYSIS,
                component="ai_analysis",
                reason=reason,
                impact=_IMPACT_MODEL,
            )
    except Exception as exc:
        log.warning("agent.analyze.degrade_record_failed", error=type(exc).__name__)


__all__ = ["analyze_findings"]
