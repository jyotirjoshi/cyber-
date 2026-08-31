"""Finding projection, AI analysis and risk prioritization (FR-016 .. FR-024).

Four decisions shape this module.

**DefectDojo owns the vulnerability; this is a projection.**  Deduplication, status
workflow and history live in DefectDojo (FR-018), so :func:`import_from_defectdojo`
never decides whether two findings are the same thing.  It keys on
``(organization_id, defectdojo_finding_id)`` and copies what DefectDojo reports.  A
second dedup rule here would eventually disagree with the system of record, and then
neither number could be trusted.

**Prioritization is arithmetic, not a model call.**  :func:`prioritize` computes a
0-100 score from six named components and records every input in
``Finding.risk_factors``.  An operator who asks "why is this P1?" gets the same answer
every time, and a reviewer can recompute it by hand.  A model asked to rank findings
would give a defensible-sounding but irreproducible order, and prioritization is
exactly where irreproducibility is least acceptable.

**Missing intelligence is neutral, never favourable** (FR-020).  An unavailable KEV
lookup contributes zero to the score -- it does not earn the "not exploited" discount
that a confirmed ``False`` would.  The providers that were unreachable are listed in
``risk_factors["unavailable"]`` so the UI can say the score was computed without them.

**The hallucination guard runs before the analysis is stored** (FR-024), not on the way
out to the user.  Filtering at render time would leave a fabricated CVE sitting in the
database, where the next reader -- a report, a Jira ticket, an export -- would pick it
up unfiltered.  A rejected analysis is recorded as a skip with its reason, never as an
empty success.

No function here commits.  The caller owns the transaction, because a finding update is
only ever meaningful together with the assessment counters or the audit row written
beside it.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import Case, case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import (
    IntegrationError,
    InvalidModelResponseError,
    UnverifiableClaimError,
)
from app.db.enums import (
    AuditOutcome,
    Criticality,
    FindingStatus,
    Permission,
    Priority,
    Severity,
)
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.finding import Finding, FindingEnrichment
from app.db.models.scanner import ScannerJob
from app.db.repository import TenantRepository, tenant_select
from app.integrations.defectdojo import DDFinding, DefectDojoClient
from app.integrations.dify import DifyClient
from app.llm.base import LLMMessage
from app.llm.gateway import LLMGateway
from app.llm.guard import (
    assert_no_invented_cve,
    assert_no_invented_cvss,
    collect_evidence_ids,
    verify_claims,
)
from app.llm.prompts import FINDING_ANALYSIS_SYSTEM, build_evidence_prompt
from app.schemas.common import PaginationParams
from app.schemas.finding import FindingFilter
from app.services import audit as audit_service
from app.services.assessment import refresh_counters
from app.services.context import Principal
from app.services.enrichment import enrichment_evidence, unavailable_providers

log = structlog.get_logger(__name__)

#: Eager-load sets. ``Finding.enrichment``, ``.asset``, ``.remediations`` and ``.tickets``
#: are all ``lazy="raise_on_sql"``, so anything the caller will touch has to be named here.
_LIST_OPTIONS = (selectinload(Finding.asset),)
_DETAIL_OPTIONS = (
    selectinload(Finding.asset),
    selectinload(Finding.enrichment),
    selectinload(Finding.remediations),
    selectinload(Finding.tickets),
)

#: Score ceiling for each component of the risk score. They sum to exactly 100 so the
#: number means something on its own: 72 is "roughly three quarters of the way to the
#: worst thing we can describe", not an arbitrary index that happens to top out somewhere.
_W_SEVERITY = 45.0
_W_KEV = 20.0
_W_EPSS = 12.0
_W_EXPOSURE = 10.0
_W_CRITICALITY = 10.0
_W_RANSOMWARE = 3.0

#: Band edges, highest first, calibrated against the population they actually see rather
#: than against the theoretical maximum.  KEV holds roughly a thousand CVEs and EPSS is
#: below 0.05 for the overwhelming majority, so on a real assessment the exploitation and
#: ransomware components are zero almost every time.  Bands set as though every component
#: fired would push all but a handful of findings into P4 and P5, and a queue where
#: everything is low priority is the same as no queue at all.  These edges are chosen so
#: that CVSS and business context alone can carry a finding into the top three bands.
_PRIORITY_BANDS: tuple[tuple[float, Priority], ...] = (
    (75.0, Priority.P1),
    (55.0, Priority.P2),
    (38.0, Priority.P3),
    (18.0, Priority.P4),
)

#: CVSS is on a 0-10 scale; this converts it into the severity component's 0-45 range.
_CVSS_TO_SEVERITY = _W_SEVERITY / 10.0

#: Fallback when neither the scanner nor NVD gave a CVSS score. Deliberately below the
#: equivalent CVSS band -- ``critical`` scores 38 where CVSS 9.0 scores 40.5 -- because a
#: severity label carries less information than a vector, and inferring a vector from a
#: label would invent precision that is not there.
_SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 38.0,
    Severity.HIGH: 29.0,
    Severity.MEDIUM: 17.0,
    Severity.LOW: 7.0,
    Severity.INFO: 1.0,
}

#: DefectDojo values of ``known_ransomware_campaign_use`` that mean yes.
_RANSOMWARE_YES = frozenset({"known", "true", "yes"})

#: Statuses that are still someone's problem. Analysis and prioritization only run on
#: these; spending model tokens on a risk-accepted finding is spending them twice.
_OPEN_STATUSES = (FindingStatus.ACTIVE.value, FindingStatus.VERIFIED.value)

#: Knowledge-base chunks carried into an analysis prompt (SEC-006).
_MAX_KB_CHUNKS = 4


class _AnalysisOut(BaseModel):
    """Shape the reasoning model must return.

    Internal to this module rather than in ``app/schemas``: it is a prompt contract, not
    a wire type, and the API never accepts or returns it directly.
    """

    explanation: str = Field(min_length=1, max_length=6000)
    business_impact: str = Field(min_length=1, max_length=4000)
    attack_scenario: str = Field(min_length=1, max_length=4000)
    confidence: str = Field(default="medium", max_length=20)
    confidence_reason: str = Field(default="", max_length=1000)
    likely_false_positive: bool = False


_ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["explanation", "business_impact", "attack_scenario", "confidence"],
    "properties": {
        "explanation": {"type": "string", "maxLength": 6000},
        "business_impact": {"type": "string", "maxLength": 4000},
        "attack_scenario": {"type": "string", "maxLength": 4000},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "confidence_reason": {"type": "string", "maxLength": 1000},
        "likely_false_positive": {"type": "boolean"},
    },
}


# ---------------------------------------------------------------------------
# Import (FR-016, FR-017, FR-018)
# ---------------------------------------------------------------------------


async def import_from_defectdojo(
    session: AsyncSession,
    assessment: Assessment,
    *,
    client: DefectDojoClient,
    test_id: int,
) -> list[Finding]:
    """Pull one DefectDojo test's findings into the local projection.

    Upserts on ``(organization_id, defectdojo_finding_id)``.  A finding seen by an earlier
    assessment is re-pointed at this one rather than duplicated: the row is the
    organization's record of that vulnerability, and ``first_seen_at`` is what preserves
    how long it has been open.

    Every status change DefectDojo reports is audited individually (FR-032).  Cynux never
    originates a status change -- DefectDojo does -- but a reader of the audit log still
    needs to see when a finding stopped being active and on whose scan.
    """
    records = await client.list_findings(test_id=test_id)
    now = _now()

    if not records:
        await audit_service.record(
            session,
            action=audit_service.AuditAction.FINDING_IMPORT,
            resource_type="assessment",
            resource_id=assessment.id,
            organization_id=assessment.organization_id,
            detail={"defectdojo_test_id": test_id, "imported": 0, "created": 0},
        )
        log.info(
            "finding.import_empty",
            assessment_id=str(assessment.id),
            defectdojo_test_id=test_id,
        )
        return []

    existing = await _existing_by_dd_id(
        session,
        organization_id=assessment.organization_id,
        dd_ids=[record.id for record in records],
    )
    job = await _job_for_test(session, assessment, test_id=test_id)
    hosts = {host for record in records for host in _hosts_of(record)}
    by_host_port, by_host = await _asset_index(
        session, organization_id=assessment.organization_id, hosts=hosts
    )

    findings: list[Finding] = []
    created = 0
    status_changes: list[dict[str, Any]] = []

    for record in records:
        finding = existing.get(record.id)
        if finding is None:
            finding = Finding(
                organization_id=assessment.organization_id,
                defectdojo_finding_id=record.id,
                title=record.title[:1000] or "(untitled finding)",
                severity=record.severity.value,
                status=FindingStatus.ACTIVE.value,
                first_seen_at=now,
            )
            session.add(finding)
            created += 1

        previous_status = _apply_dd(
            finding,
            record,
            assessment=assessment,
            asset=_match_asset(record, by_host_port=by_host_port, by_host=by_host),
            job=job,
            now=now,
        )
        if previous_status is not None:
            status_changes.append(
                {
                    "defectdojo_finding_id": record.id,
                    "from": previous_status,
                    "to": finding.status,
                }
            )
        findings.append(finding)

    # Flush before the counters: ``refresh_counters`` aggregates in SQL, so rows still
    # pending in the session would be invisible to it and the totals would lag by one
    # import.
    await session.flush()
    await refresh_counters(session, assessment)

    if job is not None:
        job.imported_finding_count = len(findings)
        job.defectdojo_test_id = test_id

    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_IMPORT,
        resource_type="assessment",
        resource_id=assessment.id,
        organization_id=assessment.organization_id,
        detail={
            "defectdojo_test_id": test_id,
            "imported": len(findings),
            "created": created,
            "updated": len(findings) - created,
            "status_changes": len(status_changes),
        },
    )
    for change in status_changes:
        await audit_service.record(
            session,
            action=audit_service.AuditAction.FINDING_STATUS_CHANGE,
            resource_type="finding",
            organization_id=assessment.organization_id,
            detail=change,
            reason="Synchronized from DefectDojo, which owns finding state.",
        )

    log.info(
        "finding.imported",
        assessment_id=str(assessment.id),
        defectdojo_test_id=test_id,
        total=len(findings),
        created=created,
        status_changes=len(status_changes),
    )
    return findings


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def get_finding(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    *,
    detail: bool = True,
) -> Finding:
    """One finding, scoped to the caller's organization.

    A cross-tenant id is a 404 (SEC-003): confirming an id exists somewhere else is
    itself a disclosure.
    """
    principal.require(Permission.FINDING_READ)
    repo: TenantRepository[Finding] = TenantRepository(session, Finding, principal.organization_id)
    options = _DETAIL_OPTIONS if detail else _LIST_OPTIONS
    return await repo.get_or_404(finding_id, *options)


async def list_findings(
    session: AsyncSession,
    principal: Principal,
    *,
    filters: FindingFilter | None = None,
    pagination: PaginationParams | None = None,
) -> tuple[Sequence[Finding], int]:
    """Risk-ordered page of findings. Returns ``(rows, total)``.

    Ordered by priority then risk score rather than by severity: severity is the
    scanner's opinion and putting it first would undo the whole point of FR-023.
    Un-prioritized findings sort last, because a missing priority is not a low one.
    """
    principal.require(Permission.FINDING_READ)
    filters = filters or FindingFilter()
    page = pagination or PaginationParams()
    conditions = _filter_conditions(filters)

    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Finding)
                .where(Finding.organization_id == principal.organization_id, *conditions)
            )
        ).scalar_one()
    )
    stmt = (
        tenant_select(Finding, principal.organization_id, *_LIST_OPTIONS)
        .where(*conditions)
        .order_by(
            Finding.priority.asc().nullslast(),
            Finding.risk_score.desc().nullslast(),
            _severity_order().desc(),
            # ``id`` breaks ties: without it two equally-scored findings can swap places
            # between pages and a reader silently never sees one of them.
            Finding.id,
        )
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return rows, total


async def findings_for_assessment(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    organization_id: uuid.UUID,
    open_only: bool = False,
    with_enrichment: bool = False,
) -> list[Finding]:
    """Every finding an assessment surfaced, risk-ordered.

    No principal: the callers are the enrich, analyze and report nodes, whose authority
    is the assessment they were handed.  ``organization_id`` is still required so the
    query cannot accidentally cross a tenant boundary.
    """
    options: tuple[Any, ...] = _DETAIL_OPTIONS if with_enrichment else _LIST_OPTIONS
    conditions: list[Any] = [
        Finding.assessment_id == assessment_id,
        Finding.organization_id == organization_id,
    ]
    if open_only:
        conditions.extend(
            [
                Finding.status.in_(_OPEN_STATUSES),
                Finding.is_duplicate.is_(False),
                Finding.is_false_positive.is_(False),
            ]
        )
    stmt = (
        select(Finding)
        .options(*options)
        .where(*conditions)
        .order_by(
            Finding.priority.asc().nullslast(),
            Finding.risk_score.desc().nullslast(),
            _severity_order().desc(),
            Finding.id,
        )
    )
    return list((await session.execute(stmt)).scalars().all())


# ---------------------------------------------------------------------------
# Analysis (FR-021, FR-022, FR-024)
# ---------------------------------------------------------------------------


async def analysis_candidates(
    session: AsyncSession,
    assessment: Assessment,
    *,
    settings: Settings,
) -> list[Finding]:
    """The findings worth spending model tokens on, and a written reason for the rest.

    Two limits from ``AgentSettings``: ``analysis_severity_floor`` and
    ``max_findings_analyzed``.  Everything excluded by either one gets an
    ``ai_skipped_reason``, because a finding with no analysis and no explanation looks
    like a bug to whoever reads it and invites a pointless re-run.
    """
    floor = Severity(settings.agent.analysis_severity_floor)
    allowed = [level.value for level in Severity if level.rank >= floor.rank]
    budget = max(0, int(settings.agent.max_findings_analyzed))

    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset), selectinload(Finding.enrichment))
        .where(
            Finding.assessment_id == assessment.id,
            Finding.organization_id == assessment.organization_id,
            Finding.severity.in_(allowed),
            Finding.status.in_(_OPEN_STATUSES),
            Finding.is_duplicate.is_(False),
            Finding.is_false_positive.is_(False),
        )
        .order_by(
            _severity_order().desc(),
            Finding.cvss_score.desc().nullslast(),
            Finding.id,
        )
        .limit(budget)
    )
    rows = list((await session.execute(stmt)).scalars().all())
    selected = {row.id for row in rows}

    await _mark_skipped(
        session,
        assessment,
        reason=(
            f"Severity is below the configured analysis floor ({floor.value}). "
            "Enrichment still applies."
        ),
        extra=[Finding.severity.notin_(allowed)],
    )
    if selected:
        await _mark_skipped(
            session,
            assessment,
            reason=f"Analysis budget of {budget} findings for this assessment was reached.",
            extra=[Finding.severity.in_(allowed), Finding.id.notin_(selected)],
        )

    log.info(
        "finding.analysis_candidates",
        assessment_id=str(assessment.id),
        selected=len(rows),
        floor=floor.value,
        budget=budget,
    )
    return rows


async def analyze_finding(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    *,
    gateway: LLMGateway,
    dify: DifyClient | None = None,
    settings: Settings,
    force: bool = False,
) -> Finding:
    """Generate the plain-language explanation, business impact and attack scenario.

    The model is given exactly one set of citable sources -- the scanner observation, the
    intelligence enrichment, the asset context, and any knowledge-base chunks -- and
    every factual sentence it writes must cite one of them.  Output is checked three ways
    before it is stored (FR-024): no CVE outside the evidence, no CVSS score outside the
    evidence, and no unsupported claim sentence.  A rejected analysis is recorded as a
    skip with its reason rather than raised, so the reason survives in the row the reader
    is looking at and a retry does not loop.

    An unreachable knowledge base degrades the analysis, it does not answer from memory
    (FR-021): the chunks simply are not in the evidence, and the guard then replaces any
    sentence that would have needed them.
    """
    principal.require(Permission.FINDING_ANALYZE)
    finding = await get_finding(session, principal, finding_id, detail=True)

    if finding.ai_analyzed_at is not None and not force:
        # Idempotent by default so a UI retry or a re-run of the analyze node cannot
        # quietly bill an operator twice for the same paragraph.
        return finding

    skip = _analysis_skip_reason(finding, settings=settings, force=force)
    if skip is not None:
        finding.ai_skipped_reason = skip
        # SUCCESS, not FAILURE: declining to analyze a false positive is the correct
        # outcome of the request. ``reason`` carries the why, and ``detail`` marks it as a
        # skip so the audit log can be filtered on it without parsing prose.
        await audit_service.record(
            session,
            action=audit_service.AuditAction.FINDING_ANALYZE,
            principal=principal,
            resource_type="finding",
            resource_id=finding.id,
            outcome=AuditOutcome.SUCCESS,
            reason=skip,
            detail={"skipped": True},
        )
        return finding

    evidence = enrichment_evidence(finding, finding.enrichment)
    if finding.asset is not None:
        evidence[f"asset:{finding.asset.id}"] = _asset_evidence(finding.asset)

    degradations: list[str] = list(unavailable_providers(finding.enrichment))
    chunks = await _knowledge_chunks(finding, dify=dify, degradations=degradations)
    for chunk in chunks:
        evidence[chunk.citation_id] = chunk.evidence()

    provider, model = gateway.resolve("reasoning")
    instruction = _analysis_instruction(finding, evidence=evidence, degradations=degradations)
    messages = [
        LLMMessage(role="system", content=FINDING_ANALYSIS_SYSTEM),
        LLMMessage(role="user", content=instruction),
    ]

    result = await gateway.complete_json(
        "reasoning",
        messages,
        schema=_ANALYSIS_SCHEMA,
        model_cls=_AnalysisOut,
    )
    if not isinstance(result, _AnalysisOut):  # pragma: no cover - gateway contract
        raise InvalidModelResponseError(
            "Finding analysis did not validate against the analysis schema.",
            context={"finding_id": str(finding.id)},
        )

    known_cves = set(finding.cve_ids or []) | _evidence_cves(evidence)
    known_scores = _known_scores(finding)
    combined = "\n".join([result.explanation, result.business_impact, result.attack_scenario])

    try:
        assert_no_invented_cve(combined, known_cves=known_cves)
        assert_no_invented_cvss(combined, known_scores=known_scores)
    except UnverifiableClaimError as exc:
        finding.ai_skipped_reason = (
            "Analysis was rejected because the model asserted facts that are not in the "
            "collected evidence."
        )[:200]
        log.warning(
            "finding.analysis_rejected",
            finding_id=str(finding.id),
            model=f"{provider}/{model}",
            detail=exc.context,
        )
        await audit_service.record(
            session,
            action=audit_service.AuditAction.FINDING_ANALYZE,
            principal=principal,
            resource_type="finding",
            resource_id=finding.id,
            outcome=AuditOutcome.FAILURE,
            reason=exc.user_message,
            detail={"model": f"{provider}/{model}", "guard": exc.context},
        )
        return finding

    explanation = verify_claims(result.explanation, evidence=evidence)
    impact = verify_claims(result.business_impact, evidence=evidence)
    scenario = verify_claims(result.attack_scenario, evidence=evidence)

    finding.ai_explanation = explanation.stripped_text
    finding.ai_business_impact = impact.stripped_text
    finding.ai_attack_scenario = scenario.stripped_text
    finding.ai_evidence = _evidence_trail(
        evidence,
        guarded={
            "explanation": explanation,
            "business_impact": impact,
            "attack_scenario": scenario,
        },
        confidence=result.confidence,
        confidence_reason=result.confidence_reason,
        likely_false_positive=result.likely_false_positive,
        degradations=degradations,
    )
    finding.ai_model = f"{provider}/{model}"[:120]
    finding.ai_analyzed_at = _now()
    finding.ai_skipped_reason = None
    if finding.asset is not None:
        finding.asset_criticality = finding.asset.criticality

    unsupported = len(explanation.unsupported) + len(impact.unsupported) + len(scenario.unsupported)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_ANALYZE,
        principal=principal,
        resource_type="finding",
        resource_id=finding.id,
        detail={
            "model": f"{provider}/{model}",
            "evidence_sources": collect_evidence_ids(evidence),
            "claims_stripped": unsupported,
            "knowledge_chunks": len(chunks),
            "degraded": degradations,
        },
    )
    log.info(
        "finding.analyzed",
        finding_id=str(finding.id),
        model=f"{provider}/{model}",
        sources=len(evidence),
        claims_stripped=unsupported,
        degraded=degradations,
    )
    return finding


# ---------------------------------------------------------------------------
# Prioritization (FR-023)
# ---------------------------------------------------------------------------


async def prioritize(
    session: AsyncSession,
    assessment: Assessment,
    *,
    settings: Settings,
) -> None:
    """Score and band every finding on the assessment.

    Deterministic and self-documenting: the six components, their weights and the inputs
    that produced them all land in ``Finding.risk_factors``, so the score can be
    recomputed by hand from the row.  ``settings`` is accepted for symmetry with the
    other scoring entry points and to keep the signature stable if a future release makes
    the weights configurable; the current weights are module constants precisely so two
    deployments cannot produce different P1 sets from the same data.
    """
    findings = await findings_for_assessment(
        session,
        assessment.id,
        organization_id=assessment.organization_id,
        with_enrichment=True,
    )
    if not findings:
        return

    counts: dict[str, int] = {}
    for finding in findings:
        score, factors = _score(finding)
        priority = _priority_for(score, finding)
        finding.risk_score = score
        finding.priority = priority.value
        finding.risk_factors = {**factors, "score": score, "priority": priority.value}
        if finding.asset is not None:
            finding.asset_criticality = finding.asset.criticality
        counts[priority.value] = counts.get(priority.value, 0) + 1

    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_PRIORITIZE,
        resource_type="assessment",
        resource_id=assessment.id,
        organization_id=assessment.organization_id,
        detail={"findings": len(findings), "by_priority": counts},
    )
    log.info(
        "finding.prioritized",
        assessment_id=str(assessment.id),
        findings=len(findings),
        by_priority=counts,
    )


def risk_summary(findings: Sequence[Finding]) -> dict[str, Any]:
    """Counts a report or dashboard needs, computed once so two callers cannot disagree.

    Reads exploitation state out of ``risk_factors`` rather than off the enrichment
    relationship.  Two reasons: the relationship is ``raise_on_sql``, so touching it would
    make this helper explode on any caller that loaded findings without it; and
    ``risk_factors`` is what the score was actually computed from, so the summary and the
    ordering it describes can never disagree.

    ``intelligence_unavailable`` is deliberately part of the output: a reader who does not
    know that EPSS was down for half of these findings will over-trust the ordering.
    """
    by_severity: dict[str, int] = {level.value: 0 for level in Severity}
    by_priority: dict[str, int] = {level.value: 0 for level in Priority}
    kev = 0
    unknown_kev = 0
    unprioritized = 0
    unavailable: set[str] = set()

    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        if finding.priority:
            by_priority[finding.priority] = by_priority.get(finding.priority, 0) + 1
        else:
            unprioritized += 1

        factors = finding.risk_factors or {}
        inputs = factors.get("inputs") or {}
        state = inputs.get("in_kev")
        if state is True:
            kev += 1
        elif state is None:
            unknown_kev += 1
        for provider in factors.get("unavailable") or []:
            if isinstance(provider, str):
                unavailable.add(provider)

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_priority": by_priority,
        "unprioritized": unprioritized,
        "in_kev": kev,
        "kev_undetermined": unknown_kev,
        "intelligence_unavailable": sorted(unavailable),
    }


# ---------------------------------------------------------------------------
# Internals -- import
# ---------------------------------------------------------------------------


def _apply_dd(
    finding: Finding,
    record: DDFinding,
    *,
    assessment: Assessment,
    asset: Asset | None,
    job: ScannerJob | None,
    now: dt.datetime,
) -> str | None:
    """Copy DefectDojo's view onto the projection.

    Returns the previous status when it changed, so the caller can audit the transition.
    """
    previous = finding.status

    finding.assessment_id = assessment.id
    if asset is not None:
        finding.asset_id = asset.id
        finding.asset_criticality = asset.criticality
    if job is not None:
        finding.scanner_job_id = job.id
        finding.scanner = job.scanner

    finding.defectdojo_test_id = record.test_id
    finding.title = (record.title or "(untitled finding)")[:1000]
    finding.severity = record.severity.value
    raw_severity = record.raw.get("severity")
    finding.severity_raw = str(raw_severity)[:40] if raw_severity else None
    finding.status = _status_for(record).value
    finding.endpoint = _endpoint_of(record)
    finding.component = (record.component_name or None) and record.component_name[:300]
    finding.component_version = (record.component_version or None) and record.component_version[:80]
    finding.cve_ids = list(record.cves)
    # DefectDojo writes CWE 0 for "not set", and a stored 0 would render as "CWE-0".
    finding.cwe = record.cwe if record.cwe else None
    finding.cvss_score = _bounded_cvss(record.cvssv3_score)
    finding.cvss_vector = record.cvssv3[:200] if record.cvssv3 else None
    finding.is_duplicate = bool(record.duplicate)
    finding.is_false_positive = bool(record.false_p)
    finding.synced_at = now
    finding.last_seen_at = now
    if finding.first_seen_at is None:
        finding.first_seen_at = now

    return previous if previous != finding.status else None


def _status_for(record: DDFinding) -> FindingStatus:
    """Collapse DefectDojo's independent boolean flags into one status.

    Order is precedence, and it is the order a triager would read them in: a
    false-positive judgement is the most consequential label on a finding, and an
    out-of-scope or risk-accepted decision outranks the mechanical duplicate flag.
    """
    if record.false_p:
        return FindingStatus.FALSE_POSITIVE
    if record.out_of_scope:
        return FindingStatus.OUT_OF_SCOPE
    if record.risk_accepted:
        return FindingStatus.RISK_ACCEPTED
    if record.duplicate:
        return FindingStatus.DUPLICATE
    if record.is_mitigated:
        return FindingStatus.MITIGATED
    if record.verified:
        return FindingStatus.VERIFIED
    if record.active:
        return FindingStatus.ACTIVE
    # Inactive with no other label: DefectDojo closed it. ``MITIGATED`` is the only
    # closed state we have, and calling it active would keep it in the open counts.
    return FindingStatus.MITIGATED


def _bounded_cvss(value: float | None) -> float | None:
    """Drop a CVSS score outside 0-10 rather than let it fail the ``valid_cvss`` CHECK.

    Scanners occasionally emit a percentage or a -1 sentinel. A rejected INSERT would
    lose the whole import batch over one bad number.
    """
    if value is None:
        return None
    return round(float(value), 1) if 0.0 <= float(value) <= 10.0 else None


def _endpoint_of(record: DDFinding) -> str | None:
    if record.endpoints:
        return str(record.endpoints[0])[:1000]
    if record.file_path:
        location = f"{record.file_path}:{record.line}" if record.line else record.file_path
        return location[:1000]
    return None


def _hosts_of(record: DDFinding) -> list[str]:
    hosts: list[str] = []
    for endpoint in record.endpoints:
        host, _ = _split_endpoint(str(endpoint))
        if host:
            hosts.append(host)
    return hosts


def _split_endpoint(endpoint: str) -> tuple[str | None, int | None]:
    """``host, port`` from a DefectDojo endpoint string.

    Handles ``https://host:8443/path``, ``host:22`` and a bare hostname. Parsed rather
    than regex-matched because a malformed endpoint must yield ``None`` and not a
    plausible-looking wrong host that would attach the finding to the wrong asset.
    """
    text = endpoint.strip()
    if not text:
        return None, None
    if "://" not in text:
        text = f"//{text}"
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").strip().lower() or None
        port = parts.port
    except ValueError:
        return None, None
    if port is None and parts.scheme:
        port = {"http": 80, "https": 443}.get(parts.scheme)
    return host, port


def _match_asset(
    record: DDFinding,
    *,
    by_host_port: dict[tuple[str, int], Asset],
    by_host: dict[str, Asset],
) -> Asset | None:
    """Attach a finding to the asset it was observed on.

    Exact ``(host, port)`` first, then the host on its own.  A miss leaves ``asset_id``
    null: a finding on an unrecognized host is still a real finding, and guessing an
    asset would put it under the wrong criticality and distort its priority.
    """
    for endpoint in record.endpoints:
        host, port = _split_endpoint(str(endpoint))
        if host is None:
            continue
        if port is not None:
            exact = by_host_port.get((host, port))
            if exact is not None:
                return exact
        loose = by_host.get(host)
        if loose is not None:
            return loose
    return None


async def _existing_by_dd_id(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    dd_ids: Sequence[int],
) -> dict[int, Finding]:
    if not dd_ids:
        return {}
    stmt = tenant_select(Finding, organization_id).where(
        Finding.defectdojo_finding_id.in_(list(dd_ids))
    )
    rows = (await session.execute(stmt)).scalars().all()
    return {row.defectdojo_finding_id: row for row in rows}


async def _job_for_test(
    session: AsyncSession,
    assessment: Assessment,
    *,
    test_id: int,
) -> ScannerJob | None:
    """The scanner job whose output produced this DefectDojo test, if we still know.

    Used to stamp ``Finding.scanner``. A missing job is not an error -- a finding can
    arrive from a manual DefectDojo import -- so the scanner name is simply left unset
    rather than guessed from the test's scan type.
    """
    stmt = (
        select(ScannerJob)
        .where(
            ScannerJob.assessment_id == assessment.id,
            ScannerJob.organization_id == assessment.organization_id,
            ScannerJob.defectdojo_test_id == test_id,
        )
        .limit(1)
    )
    return (await session.execute(stmt)).scalars().first()


async def _asset_index(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    hosts: set[str],
) -> tuple[dict[tuple[str, int], Asset], dict[str, Asset]]:
    """Two lookup tables for the hosts this import actually mentions.

    Queried by host name rather than by loading the organization's inventory: a mature
    tenant has tens of thousands of assets and only the handful named in these endpoints
    can possibly match.
    """
    if not hosts:
        return {}, {}
    stmt = tenant_select(Asset, organization_id).where(Asset.name.in_(sorted(hosts)))
    rows = (await session.execute(stmt)).scalars().all()

    by_host_port: dict[tuple[str, int], Asset] = {}
    by_host: dict[str, Asset] = {}
    for asset in rows:
        name = asset.name.strip().lower()
        if asset.port is not None:
            by_host_port.setdefault((name, int(asset.port)), asset)
        # Prefer the port-less row for the loose match: it represents the host itself,
        # where a service row represents one listener on it.
        if name not in by_host or asset.port is None:
            by_host[name] = asset
    return by_host_port, by_host


# ---------------------------------------------------------------------------
# Internals -- filtering and ordering
# ---------------------------------------------------------------------------


def _filter_conditions(filters: FindingFilter) -> list[Any]:
    conditions: list[Any] = []
    if filters.severity is not None:
        conditions.append(Finding.severity == filters.severity.value)
    if filters.priority is not None:
        conditions.append(Finding.priority == filters.priority.value)
    if filters.status is not None:
        conditions.append(Finding.status == filters.status.value)
    if filters.scanner is not None:
        conditions.append(Finding.scanner == filters.scanner.value)
    if filters.assessment_id is not None:
        conditions.append(Finding.assessment_id == filters.assessment_id)
    if filters.asset_id is not None:
        conditions.append(Finding.asset_id == filters.asset_id)
    if filters.cve:
        # ``cve_ids`` is JSONB, so this is the ``@>`` containment operator and not an
        # ARRAY ``ANY`` -- it matches the GIN index and does not scan the table.
        conditions.append(Finding.cve_ids.contains([filters.cve.strip().upper()]))
    if not filters.include_duplicates:
        conditions.append(Finding.is_duplicate.is_(False))
    if not filters.include_false_positives:
        conditions.append(Finding.is_false_positive.is_(False))
    if filters.in_kev is not None:
        # A join would drop findings that have no enrichment row at all, so the filter is
        # expressed as a correlated EXISTS. ``in_kev is False`` means "CISA answered no",
        # which is why the NULL case is excluded rather than folded in.
        exists = select(FindingEnrichment.id).where(
            FindingEnrichment.finding_id == Finding.id,
            FindingEnrichment.in_kev.is_(filters.in_kev),
        )
        conditions.append(exists.exists())
    if filters.q:
        term = f"%{_escape_like(filters.q)}%"
        conditions.append(
            or_(
                Finding.title.ilike(term, escape="\\"),
                Finding.component.ilike(term, escape="\\"),
                Finding.endpoint.ilike(term, escape="\\"),
            )
        )
    return conditions


def _severity_order() -> Case[int]:
    """SQL ordering key for the severity string.

    ``severity`` is stored as text, so ``ORDER BY severity`` would sort alphabetically and
    put ``critical`` below ``info``.
    """
    return case(
        {level.value: level.rank for level in Severity},
        value=Finding.severity,
        else_=0,
    )


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _mark_skipped(
    session: AsyncSession,
    assessment: Assessment,
    *,
    reason: str,
    extra: Sequence[Any],
) -> None:
    """Write ``ai_skipped_reason`` on findings that will not be analyzed.

    A bulk UPDATE rather than per-row assignment: the rows are by definition ones the
    caller did not load, and loading a few thousand findings to set one string on each
    would be the most expensive part of the node.
    """
    stmt = (
        update(Finding)
        .where(
            Finding.assessment_id == assessment.id,
            Finding.organization_id == assessment.organization_id,
            Finding.ai_analyzed_at.is_(None),
            *extra,
        )
        .values(ai_skipped_reason=reason[:200])
        # These rows are outside the caller's working set, so re-synchronizing the
        # identity map would cost an extra SELECT to update nothing anyone is holding.
        .execution_options(synchronize_session=False)
    )
    await session.execute(stmt)


# ---------------------------------------------------------------------------
# Internals -- analysis
# ---------------------------------------------------------------------------


def _analysis_skip_reason(
    finding: Finding,
    *,
    settings: Settings,
    force: bool,
) -> str | None:
    """Why this finding should not be analyzed, or ``None`` to proceed.

    ``force`` overrides the severity floor as well as the already-analyzed check: an
    operator who clicks Analyze on a medium finding is making a deliberate choice, and the
    floor exists to bound *automatic* spend, not to refuse a human.
    """
    if finding.is_false_positive or finding.is_duplicate:
        return "DefectDojo marked this finding a duplicate or a false positive."
    if finding.status not in _OPEN_STATUSES:
        return f"Finding is {finding.status.replace('_', ' ')} and needs no analysis."
    if not force:
        floor = Severity(settings.agent.analysis_severity_floor)
        if finding.severity_enum.rank < floor.rank:
            return (
                f"Severity {finding.severity} is below the configured analysis floor "
                f"({floor.value})."
            )
    return None


async def _knowledge_chunks(
    finding: Finding,
    *,
    dify: DifyClient | None,
    degradations: list[str],
) -> list[Any]:
    """Retrieve internal knowledge for this finding, tolerating an absent Dify.

    An unconfigured knowledge base is a deployment choice and not a degradation; an
    unreachable one is, and it is recorded so the report appendix can say the analysis was
    produced without internal context (FR-020's reasoning applied to FR-021).
    """
    if dify is None or not dify.configured:
        return []
    query = " ".join(
        part
        for part in (
            finding.title,
            finding.component,
            finding.component_version,
            finding.primary_cve,
        )
        if part
    )
    try:
        chunks = await dify.retrieve(query, top_k=_MAX_KB_CHUNKS)
    except IntegrationError as exc:
        degradations.append("knowledge_base")
        log.warning(
            "finding.knowledge_base_unavailable",
            finding_id=str(finding.id),
            reason=exc.user_message,
        )
        return []
    return list(chunks[:_MAX_KB_CHUNKS])


def _asset_evidence(asset: Asset) -> dict[str, Any]:
    """Citable facts about the affected asset.

    "Internet-facing" is a factual claim, not a judgement, so the model needs a source to
    attribute it to. ``criticality_source`` travels with the criticality so a claim about
    business importance cannot silently rest on a keyword guess.
    """
    return {
        "provider": "cynux_inventory",
        "name": asset.name,
        "asset_type": asset.asset_type,
        "port": asset.port,
        "service": asset.service,
        "internet_exposed": asset.internet_exposed,
        "criticality": asset.criticality,
        "criticality_source": asset.criticality_source,
        "criticality_rationale": asset.criticality_rationale,
        "technology": list(asset.technology or []),
        "http_title": asset.http_title,
        "tls_subject": asset.tls_subject,
    }


def _analysis_instruction(
    finding: Finding,
    *,
    evidence: dict[str, dict[str, Any]],
    degradations: Sequence[str],
) -> str:
    lines = [
        "Analyze this security finding for the engineer who has to fix it.",
        f"Finding severity as reported by the scanner: {finding.severity}.",
    ]
    if finding.scanner:
        lines.append(f"Reported by: {finding.scanner}.")
    if degradations:
        lines.append(
            "The following intelligence sources were unavailable for this finding: "
            f"{', '.join(sorted(degradations))}. Do not infer what they would have said."
        )
    lines.append(
        "Cite a source id for every factual claim. The ids you may cite are the EVIDENCE "
        "section headings below and nothing else."
    )
    return build_evidence_prompt("\n".join(lines), evidence=evidence)


def _evidence_cves(evidence: dict[str, dict[str, Any]]) -> set[str]:
    """Every CVE the evidence actually contains, from the keys and the payloads."""
    found: set[str] = set()
    for key, block in evidence.items():
        _, _, tail = key.partition(":")
        if tail.upper().startswith("CVE-"):
            found.add(tail.upper())
        value = block.get("cve_id")
        if isinstance(value, str):
            found.add(value.upper())
        for entry in block.get("cve_ids") or []:
            if isinstance(entry, str):
                found.add(entry.upper())
    return found


def _known_scores(finding: Finding) -> set[float]:
    """CVSS scores the model is permitted to state.

    The enrichment row is read through the loaded relationship; callers of
    :func:`analyze_finding` always eager-load it.
    """
    scores: set[float] = set()
    if finding.cvss_score is not None:
        scores.add(round(float(finding.cvss_score), 1))
    enrichment = finding.enrichment
    if enrichment is not None and enrichment.nvd_cvss_v31_score is not None:
        scores.add(round(float(enrichment.nvd_cvss_v31_score), 1))
    return scores


def _evidence_trail(
    evidence: dict[str, dict[str, Any]],
    *,
    guarded: dict[str, Any],
    confidence: str,
    confidence_reason: str,
    likely_false_positive: bool,
    degradations: Sequence[str],
) -> list[dict[str, Any]]:
    """The FR-024 audit trail stored on the finding.

    One entry per claim the model made, each carrying the source it cited or ``null``
    where the guard stripped it, plus one summary entry.  Storing the stripped claims as
    well as the accepted ones is deliberate: a reviewer asking "what did the model try to
    say?" should not have to read the logs.
    """
    trail: list[dict[str, Any]] = [
        {
            "kind": "summary",
            "available_sources": collect_evidence_ids(evidence),
            "confidence": confidence,
            "confidence_reason": confidence_reason,
            "likely_false_positive": likely_false_positive,
            "unavailable_intelligence": sorted(degradations),
        }
    ]
    for field_name, result in guarded.items():
        for claim in result.claims:
            trail.append(
                {
                    "kind": "claim",
                    "field": field_name,
                    "claim": claim.text[:1000],
                    "source_id": claim.source_id,
                    "supported": claim.source_id is not None,
                }
            )
    return trail


# ---------------------------------------------------------------------------
# Internals -- scoring
# ---------------------------------------------------------------------------


def _score(finding: Finding) -> tuple[float, dict[str, Any]]:
    """The 0-100 risk score and the inputs that produced it.

    Returned together so ``risk_factors`` cannot describe a different calculation than the
    one that ran -- the same reason :func:`app.services.asset._score` pairs them.
    """
    if finding.is_duplicate or finding.is_false_positive:
        # Not scored on its merits: DefectDojo has judged it noise, and leaving it in the
        # ranked queue would push a real finding off the first page.
        return 0.0, {
            "excluded": "DefectDojo marked this finding a duplicate or a false positive.",
            "components": {},
            "weights": _weights(),
        }

    enrichment = finding.enrichment
    components: dict[str, Any] = {}
    inputs: dict[str, Any] = {}

    cvss = finding.cvss_score
    if cvss is None and enrichment is not None:
        cvss = enrichment.nvd_cvss_v31_score
    if cvss is not None:
        components["severity"] = round(min(_W_SEVERITY, float(cvss) * _CVSS_TO_SEVERITY), 2)
        inputs["cvss_score"] = round(float(cvss), 1)
    else:
        components["severity"] = _SEVERITY_POINTS[finding.severity_enum]
        inputs["cvss_score"] = None
        inputs["severity_label"] = finding.severity

    kev_state = _kev_state(finding)
    components["exploitation"] = _W_KEV if kev_state is True else 0.0
    inputs["in_kev"] = kev_state

    epss = enrichment.epss_score if enrichment is not None else None
    components["exploit_probability"] = (
        round(min(_W_EPSS, float(epss) * _W_EPSS), 2) if epss is not None else 0.0
    )
    inputs["epss_score"] = round(float(epss), 4) if epss is not None else None

    exposed = bool(finding.asset.internet_exposed) if finding.asset is not None else False
    components["exposure"] = _W_EXPOSURE if exposed else 0.0
    inputs["internet_exposed"] = exposed if finding.asset is not None else None

    criticality = _criticality_of(finding)
    components["asset_criticality"] = round(_W_CRITICALITY * criticality.weight, 2)
    inputs["asset_criticality"] = criticality.value

    ransomware = _ransomware_use(enrichment)
    components["ransomware"] = _W_RANSOMWARE if ransomware else 0.0
    inputs["ransomware_campaign_use"] = ransomware

    total = round(min(100.0, max(0.0, sum(float(v) for v in components.values()))), 2)
    factors: dict[str, Any] = {
        "components": components,
        "weights": _weights(),
        "inputs": inputs,
        "unavailable": unavailable_providers(enrichment),
    }
    return total, factors


def _priority_for(score: float, finding: Finding) -> Priority:
    """Band the score, with three rules stated outright rather than tuned into existence.

    A weight table can express "exploitation matters a lot"; it cannot express "never bury
    this", and the cases below are the ones where the answer must not depend on arithmetic.

    *Excluded findings are P5.*  A duplicate or false positive is not scored on its merits
    (:func:`_score` returns 0), so it must not be able to reach P1 through an escalation --
    which is exactly what happens if the exploitation rule is applied first, since
    DefectDojo's duplicate flag says nothing about whether the CVE is in KEV.

    *Confirmed exploitation of an internet-facing asset is P1.*  Presence in CISA's
    catalogue means this is being used in attacks now.  No combination of a modest CVSS and
    an unknown EPSS should put it on page two.

    *Confirmed exploitation anywhere is at least P2.*  Internal reach is a delay, not a
    reprieve; an exploited vulnerability behind the perimeter is one lateral move from
    being reachable, and P3 or below reads as "next quarter".
    """
    if finding.is_duplicate or finding.is_false_positive:
        return Priority.P5

    exploited = _kev_state(finding) is True
    if exploited and finding.asset is not None and finding.asset.internet_exposed:
        return Priority.P1

    banded = Priority.P5
    for threshold, priority in _PRIORITY_BANDS:
        if score >= threshold:
            banded = priority
            break
    if exploited and banded.rank > Priority.P2.rank:
        return Priority.P2
    return banded


def _weights() -> dict[str, float]:
    return {
        "severity": _W_SEVERITY,
        "exploitation": _W_KEV,
        "exploit_probability": _W_EPSS,
        "exposure": _W_EXPOSURE,
        "asset_criticality": _W_CRITICALITY,
        "ransomware": _W_RANSOMWARE,
    }


def _kev_state(finding: Finding) -> bool | None:
    """Tri-state KEV membership. ``None`` is "not determined", never "no" (FR-020)."""
    enrichment = finding.enrichment
    return enrichment.in_kev if enrichment is not None else None


def _ransomware_use(enrichment: FindingEnrichment | None) -> bool:
    if enrichment is None or not enrichment.kev_ransomware_use:
        return False
    return enrichment.kev_ransomware_use.strip().lower() in _RANSOMWARE_YES


def _criticality_of(finding: Finding) -> Criticality:
    """Criticality for scoring: the live asset first, then the analysis-time snapshot.

    Falls back to ``UNKNOWN``, whose weight sits between low and normal, so an
    unclassified asset is neither written off nor promoted.
    """
    raw = finding.asset.criticality if finding.asset is not None else finding.asset_criticality
    try:
        return Criticality(raw) if raw else Criticality.UNKNOWN
    except ValueError:
        return Criticality.UNKNOWN


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "analysis_candidates",
    "analyze_finding",
    "findings_for_assessment",
    "get_finding",
    "import_from_defectdojo",
    "list_findings",
    "prioritize",
    "risk_summary",
]
