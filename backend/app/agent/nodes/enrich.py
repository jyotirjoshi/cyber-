"""Node: enrich_intelligence -- threat & vulnerability intelligence enrichment (FR-019, FR-020).

After the findings are imported, this node attaches external context to each one: the NVD CVE
record, whether CISA lists it as known-exploited (KEV), its EPSS exploitation probability, and any
MISP sightings.  That context is what the next two nodes turn into a real risk ranking -- a
medium-severity CVE that is in KEV and has a 0.9 EPSS score outranks a high-severity one that has
neither, and without this step the agent would only have the scanner's own severity to go on.

**The node is a thin orchestrator; the honesty rules live in the service.**  All of the load-
bearing logic -- querying four providers concurrently, and above all recording an unreachable
provider as ``UNAVAILABLE`` rather than as a negative answer -- is in
:mod:`app.services.enrichment`, whose module docstring explains why ``in_kev`` is ``bool | None``.
This node's job is to pick the findings, resolve the per-tenant provider clients, hand the batch
to :func:`app.services.enrichment.enrich_findings`, and translate whatever came back unavailable
into an FR-039 degradation so the report can say what it could not check (FR-020).

**Enrichment never fails the run.**  ``enrich_findings`` is written not to raise for a provider
outage -- the outage becomes an ``UNAVAILABLE`` status on the affected findings.  So this node has
no fatal path of its own: a provider being down degrades the assessment (a caveat in the report),
it does not stop it.  The one transaction wraps the whole batch on purpose, because a commit per
finding would be one database round trip per finding on a large assessment -- the service docstring
names this node as the reason it does not commit internally.

The node runs within the ``analyzing`` status at stage ``threat_intelligence`` and records one
step.  Every summary and degradation note carries provider names and counts only -- never a
hostname, a finding title, a CVE's affected product, or a credential (SEC-002).
"""

from __future__ import annotations

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
from app.db.enums import (
    AssessmentStage,
    AssessmentStatus,
    EnrichmentStatus,
    IntegrationKind,
)
from app.db.models.finding import FindingEnrichment
from app.db.session import session_scope
from app.integrations.epss import EPSSClient
from app.integrations.kev import KEVClient
from app.integrations.misp import MISPClient
from app.integrations.nvd import NVDClient
from app.services.assessment import record_degradation, transition
from app.services.context import Principal
from app.services.enrichment import enrich_findings, unavailable_providers
from app.services.finding import findings_for_assessment
from app.services.integration import resolve_settings

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "enrich_intelligence"

#: Operator-facing provider names for degradation notes (SEC-002: names and counts only).
_PROVIDER_LABELS: dict[str, str] = {
    "nvd": "NVD",
    "cisa_kev": "CISA KEV",
    "epss": "EPSS",
    "misp": "MISP",
}

_IMPACT_PROVIDER = (
    "This intelligence source could not be reached, so affected findings are missing its context "
    "and their risk ranking may be understated."
)


async def enrich_intelligence(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Enrich every open finding with NVD/KEV/EPSS/MISP intelligence (FR-019, FR-020)."""
    await _advance_to_enrich(state, deps=deps)

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.ENRICH,
        label="Enriching findings with threat intelligence",
    ) as step:
        await _enrich(state, deps=deps, step=step)

    return {"stage": AssessmentStage.ENRICH.value}


async def _advance_to_enrich(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Advance the stage cursor to ``threat_intelligence`` within the ``analyzing`` status.

    Idempotent: the importer already moved the assessment to ``analyzing``, so this only advances
    the stage; in the passive path where import was skipped it also carries ``discovery ->
    analyzing``.  A terminal or cancelling status raises :class:`ConflictError`, which correctly
    refuses to enrich an assessment that is being torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await transition(
            session, assessment, AssessmentStatus.ANALYZING, stage=AssessmentStage.ENRICH
        )


async def _enrich(state: AssessmentState, *, deps: AgentDeps, step: StepHandle) -> None:
    """Load the open findings, enrich the batch, and degrade for any unavailable provider.

    The enrichment write shares one transaction (the service's documented contract).  The FR-020
    degradations are recorded afterwards in their own transactions, so a bookkeeping failure there
    cannot roll back the enrichment that succeeded.
    """
    org_id = state_uuid(state, "organization_id")
    assessment_id = state_uuid(state, "assessment_id")
    principal = principal_from(state)

    async with session_scope(deps.settings) as session:
        findings = await findings_for_assessment(
            session, assessment_id, organization_id=org_id, open_only=True
        )
        if not findings:
            await step.thinking("No open findings required threat-intelligence enrichment.")
            step.record_output({"findings": 0, "enriched": 0})
            return

        nvd, kev, epss, misp = await _clients(session, principal, deps)
        await step.thinking(
            f"Enriching {len(findings)} finding(s) against NVD, CISA KEV, EPSS and MISP."
        )
        rows = await enrich_findings(
            session, findings, nvd=nvd, kev=kev, epss=epss, misp=misp, settings=deps.settings
        )

        finding_count = len(findings)
        enriched_count = len(rows)
        complete = sum(1 for row in rows if row.status == EnrichmentStatus.COMPLETE.value)
        in_kev = sum(1 for row in rows if row.in_kev)
        unavailable = _unavailable_across(rows)

    for provider in unavailable:
        await _degrade(state, deps=deps, provider=provider)
    if unavailable:
        step.degrade(_degrade_note(unavailable))

    step.record_output(
        {
            "findings": finding_count,
            "enriched": enriched_count,
            "complete": complete,
            "in_kev": in_kev,
            "unavailable_providers": unavailable,
        }
    )


async def _clients(
    session: AsyncSession, principal: Principal, deps: AgentDeps
) -> tuple[NVDClient, KEVClient, EPSSClient, MISPClient]:
    """Build the four provider clients, overlaying any per-tenant NVD/MISP configuration.

    NVD and MISP can be configured per organization (an API key that lifts NVD's rate limit, a
    private MISP instance), so their settings are resolved through
    :func:`app.services.integration.resolve_settings` -- ``require=False`` because a missing one is
    not an error: NVD works keyless and an unconfigured MISP is simply skipped as not-applicable.
    CISA KEV and EPSS are public feeds with no credential, so they use the deployment settings
    directly.
    """
    nvd_settings = await resolve_settings(
        session, principal, IntegrationKind.NVD, settings=deps.settings
    )
    misp_settings = await resolve_settings(
        session, principal, IntegrationKind.MISP, settings=deps.settings
    )
    return (
        NVDClient(nvd_settings, deps.redis),
        KEVClient(deps.settings, deps.redis),
        EPSSClient(deps.settings, deps.redis),
        MISPClient(misp_settings, deps.redis),
    )


def _unavailable_across(rows: list[FindingEnrichment]) -> list[str]:
    """The union of providers that were unavailable for any finding, for the FR-020 appendix."""
    providers: set[str] = set()
    for row in rows:
        providers.update(unavailable_providers(row))
    return sorted(providers)


async def _degrade(state: AssessmentState, *, deps: AgentDeps, provider: str) -> None:
    """Record an FR-039 degradation for one unavailable provider; never fail the run over it.

    ``record_degradation`` writes its own ASSESSMENT_DEGRADED audit row.  ``except Exception``
    leaves a ``CancelledError`` to propagate untouched (mirrors :mod:`app.agent.nodes.scan`).
    """
    label = _PROVIDER_LABELS.get(provider, provider)
    reason = f"{label} was unavailable during enrichment; affected findings lack its intelligence."
    try:
        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            await record_degradation(
                session,
                assessment,
                stage=AssessmentStage.ENRICH,
                component=provider,
                reason=reason,
                impact=_IMPACT_PROVIDER,
            )
    except Exception as exc:
        log.warning("agent.enrich.degrade_record_failed", error=type(exc).__name__)


def _degrade_note(providers: list[str]) -> str:
    """A user-safe one-line note naming the unavailable providers (SEC-002)."""
    labels = ", ".join(_PROVIDER_LABELS.get(provider, provider) for provider in providers)
    return f"Threat-intelligence enrichment was incomplete: {labels} unavailable."


__all__ = ["enrich_intelligence"]
