"""Dashboard aggregates (FR-031).

Every number on the dashboard is computed in SQL, in one pass per metric, and none of them
are cached. Three deliberate choices, each with a cost:

**Aggregate in the database, not in Python.** The alternative -- load the findings and count
them -- turns a dashboard into the most expensive request in the system for exactly the
organizations that need it most. ``COUNT`` with a ``GROUP BY`` over an indexed
``(organization_id, severity)`` is the whole of ``severity_breakdown``.

**Absent is not zero.** ``mean_time_to_remediate_days`` is ``None`` when nothing has been
remediated, because ``0.0`` reads as instantaneous remediation -- the most flattering
possible misreading of an empty dataset. ``kev_findings`` counts only ``in_kev IS TRUE``,
never ``IS NOT TRUE``: a finding whose KEV lookup failed is unknown, and folding it into the
"not exploited" bucket is precisely the FR-020 failure mode of scoring an outage as good
news.

**No caching.** A dashboard read is a handful of indexed counts, and a stale
awaiting-approval badge is worse than a slow one: FR-011 makes that badge the only signal
that a run is blocked on a human. If these queries become slow the fix is a materialized
view with an explicit refresh, not a TTL that silently lies for sixty seconds.

The severity and priority breakdowns are always fully keyed -- every ``Severity`` member
present even at zero -- so a chart does not change shape between refreshes.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence

import structlog
from sqlalchemy import Select, and_, case, exists, func, literal, or_, select, text, union_all
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.projections import assessment_out
from app.core.config import Settings
from app.db.enums import (
    AssessmentStatus,
    AssetStatus,
    Criticality,
    FindingStatus,
    Permission,
    Priority,
    Severity,
)
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.audit import AuditEvent
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding, FindingEnrichment
from app.db.models.report import Report
from app.db.repository import tenant_select
from app.schemas.assessment import AssessmentOut
from app.schemas.dashboard import (
    ActivityOut,
    AssetGroupRiskOut,
    DashboardFindingOut,
    DashboardOut,
    RiskTrendOut,
    RiskTrendPointOut,
    TeamDashboardOut,
)
from app.services.canonical_metrics import RESOLVED_STATUSES, remediation_timestamp
from app.services.context import Principal
from app.services.integration import integration_health

log = structlog.get_logger(__name__)

#: Statuses that mean "this finding is somebody's problem right now". Mitigated and
#: risk-accepted findings are deliberately excluded: a dashboard that counts accepted risk
#: as open makes the number unusable as a work queue.
OPEN_STATUSES: tuple[str, ...] = (FindingStatus.ACTIVE.value, FindingStatus.VERIFIED.value)

#: Statuses that count as work in progress for ``assessments_active``. ``CANCELLING`` is in
#: here on purpose -- a cancelling assessment still holds a scanner slot.
ACTIVE_STATUSES: tuple[str, ...] = (
    AssessmentStatus.CREATED.value,
    AssessmentStatus.PLANNING.value,
    AssessmentStatus.DISCOVERY.value,
    AssessmentStatus.WAITING_FOR_APPROVAL.value,
    AssessmentStatus.SCANNING.value,
    AssessmentStatus.ANALYZING.value,
    AssessmentStatus.REMEDIATING.value,
    AssessmentStatus.CANCELLING.value,
)

_RECENT_ASSESSMENTS = 5
_TOP_FINDINGS = 10
_ACTIVITY_ROWS = 15

#: Audit verbs worth showing a non-specialist. The activity feed is a *readable slice* of
#: the trail, not the trail: ``GET /audit`` serves that, gated on ``audit:read``, and
#: mixing every token refresh into the dashboard would bury the events that matter.
_ACTIVITY_ACTIONS: tuple[str, ...] = (
    "assessment.create",
    "assessment.cancel",
    "approval.requested",
    "approval.granted",
    "approval.rejected",
    "approval.expired",
    "scanner.complete",
    "scanner.fail",
    "finding.import",
    "external_alert.triage",
    "ticket.create",
    "report.generate",
    "integration.configure",
    "membership.invite",
)

#: One-line renderings for the activity feed. A dotted verb is precise and unreadable; the
#: mapping lives here rather than in the frontend so the API is self-describing and a new
#: verb degrades to the raw action rather than to a blank row.
_ACTION_PHRASES: dict[str, str] = {
    "assessment.create": "started an assessment",
    "assessment.cancel": "cancelled an assessment",
    "approval.requested": "requested approval to scan",
    "approval.granted": "approved a scan",
    "approval.rejected": "rejected a scan",
    "approval.expired": "let an approval expire",
    "scanner.complete": "completed a scan",
    "scanner.fail": "had a scan fail",
    "finding.import": "imported findings",
    "external_alert.triage": "triaged an external alert",
    "ticket.create": "filed a ticket",
    "report.generate": "generated a report",
    "integration.configure": "changed an integration",
    "membership.invite": "invited a member",
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _open_findings(organization_id: uuid.UUID) -> Select[tuple[Finding]]:
    """The base predicate every finding metric shares.

    Factored out so the counts on the dashboard cannot drift apart from each other -- a
    ``findings_open`` total that disagrees with the sum of ``severity_breakdown`` is the
    kind of inconsistency that costs more trust than the whole panel is worth.
    """
    return tenant_select(Finding, organization_id).where(
        Finding.status.in_(OPEN_STATUSES),
        Finding.is_false_positive.is_(False),
        Finding.is_duplicate.is_(False),
    )


def _unified_open_exposures(organization_id: uuid.UUID):
    """Canonical exposures plus legacy rows that have not been projected yet."""
    represented = exists(
        select(FindingObservation.id).where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.provider == "defectdojo",
            FindingObservation.source_record_id == Finding.id,
            FindingObservation.source_status != "superseded",
        )
    )
    canonical_kev_text = CanonicalFinding.risk_factors["inputs"]["in_kev"].astext
    canonical_kev = case(
        (canonical_kev_text == "true", True),
        (canonical_kev_text == "false", False),
        else_=None,
    )
    canonical_exploited = canonical_kev.is_(True)
    canonical_priority = case(
        (and_(canonical_exploited, Asset.internet_exposed.is_(True)), Priority.P1.value),
        (CanonicalFinding.risk_score >= 75, Priority.P1.value),
        (or_(canonical_exploited, CanonicalFinding.risk_score >= 55), Priority.P2.value),
        (CanonicalFinding.risk_score >= 38, Priority.P3.value),
        (CanonicalFinding.risk_score >= 18, Priority.P4.value),
        else_=Priority.P5.value,
    )
    canonical = (
        select(
            CanonicalFinding.id.label("finding_id"),
            literal("canonical").label("source_kind"),
            Asset.owner_team.label("team"),
            CanonicalFinding.title.label("title"),
            CanonicalFinding.severity.label("severity"),
            canonical_priority.label("priority"),
            canonical_kev.label("in_kev"),
            CanonicalFinding.risk_score.label("risk_score"),
            CanonicalFinding.risk_factors.label("risk_factors"),
            CanonicalFinding.first_seen_at.label("first_seen_at"),
        )
        .select_from(CanonicalFinding)
        .join(
            Asset,
            and_(
                Asset.id == CanonicalFinding.asset_id,
                Asset.organization_id == CanonicalFinding.organization_id,
            ),
        )
        .where(
            CanonicalFinding.organization_id == organization_id,
            CanonicalFinding.status.in_(("new", "open", "reopened")),
            Asset.status != AssetStatus.OUT_OF_SCOPE.value,
        )
    )
    legacy = (
        select(
            Finding.id.label("finding_id"),
            literal("legacy").label("source_kind"),
            Asset.owner_team.label("team"),
            Finding.title.label("title"),
            Finding.severity.label("severity"),
            Finding.priority.label("priority"),
            FindingEnrichment.in_kev.label("in_kev"),
            Finding.risk_score.label("risk_score"),
            Finding.risk_factors.label("risk_factors"),
            func.coalesce(Finding.first_seen_at, Finding.created_at).label("first_seen_at"),
        )
        .select_from(Finding)
        .join(
            Asset,
            and_(Asset.id == Finding.asset_id, Asset.organization_id == Finding.organization_id),
        )
        .outerjoin(FindingEnrichment, FindingEnrichment.finding_id == Finding.id)
        .where(
            Finding.organization_id == organization_id,
            Finding.status.in_(OPEN_STATUSES),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
            ~represented,
            Asset.status != AssetStatus.OUT_OF_SCOPE.value,
        )
    )
    return union_all(canonical, legacy).subquery("unified_open_exposures")


async def _count(
    session: AsyncSession, stmt: Select[tuple[Finding]] | Select[tuple[Assessment]]
) -> int:
    total = await session.scalar(select(func.count()).select_from(stmt.subquery()))
    return int(total or 0)


async def _severity_breakdown(session: AsyncSession, organization_id: uuid.UUID) -> dict[str, int]:
    exposures = _unified_open_exposures(organization_id)
    stmt = (
        select(exposures.c.severity, func.count())
        .select_from(exposures)
        .group_by(exposures.c.severity)
    )
    counts = {severity.value: 0 for severity in Severity}
    for severity, count in (await session.execute(stmt)).all():
        # A severity the database holds but the enum does not is a data defect, not a
        # reason to drop the row: it is surfaced under its own key so somebody notices.
        counts[str(severity)] = int(count)
    return counts


async def _priority_breakdown(session: AsyncSession, organization_id: uuid.UUID) -> dict[str, int]:
    exposures = _unified_open_exposures(organization_id)
    stmt = (
        select(exposures.c.priority, func.count())
        .select_from(exposures)
        .where(exposures.c.priority.is_not(None))
        .group_by(exposures.c.priority)
    )
    counts = {priority.value: 0 for priority in Priority}
    for priority, count in (await session.execute(stmt)).all():
        counts[str(priority)] = int(count)
    return counts


async def _kev_count(session: AsyncSession, organization_id: uuid.UUID) -> int:
    """Findings *confirmed* to be in CISA KEV.

    ``in_kev.is_(True)`` and not ``is_not(False)``. See the module docstring: a NULL means
    the lookup did not complete, and counting it either way asserts something Cynux does
    not know (FR-020).
    """
    exposures = _unified_open_exposures(organization_id)
    stmt = select(func.count()).select_from(exposures).where(exposures.c.in_kev.is_(True))
    return int(await session.scalar(stmt) or 0)


async def _external_alert_counts(
    session: AsyncSession, organization_id: uuid.UUID
) -> tuple[int, int]:
    """Actionable and new provider alerts, counted without mixing them into findings."""
    source_open = ExternalSecurityAlert.status == "open"
    stmt = select(
        func.count().filter(
            and_(
                source_open,
                ExternalSecurityAlert.triage_status.notin_(
                    ("closed", "false_positive", "risk_accepted")
                ),
            )
        ),
        func.count().filter(and_(source_open, ExternalSecurityAlert.triage_status == "new")),
    ).where(ExternalSecurityAlert.organization_id == organization_id)
    actionable, awaiting = (await session.execute(stmt)).one()
    return int(actionable or 0), int(awaiting or 0)


async def _mttr_days(session: AsyncSession, organization_id: uuid.UUID) -> float | None:
    """Mean days from first observation to mitigation, or ``None``.

    Measured from ``first_seen_at`` rather than ``created_at``: a finding imported today
    that a scanner first saw three months ago was open for three months, and crediting
    Cynux's import date would make every backlog import look like a fast fix.

    Canonical records use lifecycle history and count once across scanners.
    Unprojected legacy records retain their updated_at proxy; they are excluded
    as soon as a canonical observation represents them.
    """
    delta = func.extract("epoch", Finding.updated_at - Finding.first_seen_at)  # seconds, as a float
    represented = exists(
        select(FindingObservation.id).where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.source_record_id == Finding.id,
            FindingObservation.provider == "defectdojo",
            FindingObservation.source_status != "superseded",
        )
    )
    legacy = select(func.greatest(0, delta).label("seconds")).where(
        Finding.organization_id == organization_id,
        Finding.status == FindingStatus.MITIGATED.value,
        Finding.first_seen_at.is_not(None),
        Finding.is_false_positive.is_(False),
        Finding.is_duplicate.is_(False),
        ~represented,
    )
    resolved_at = remediation_timestamp()
    canonical = select(
        func.greatest(
            0, func.extract("epoch", resolved_at - CanonicalFinding.first_seen_at)
        ).label("seconds")
    ).where(
        CanonicalFinding.organization_id == organization_id,
        CanonicalFinding.status.in_(RESOLVED_STATUSES),
        resolved_at.is_not(None),
    )
    durations = union_all(canonical, legacy).subquery()
    seconds = await session.scalar(select(func.avg(durations.c.seconds)))
    if seconds is None:
        return None
    days = float(seconds) / 86_400.0
    # Clamped at zero rather than returned negative: a clock skew or a backdated
    # ``first_seen_at`` would otherwise render as "-2.4 days to remediate".
    return round(max(days, 0.0), 2)


async def _recent_assessments(
    session: AsyncSession, organization_id: uuid.UUID
) -> Sequence[Assessment]:
    stmt = (
        tenant_select(Assessment, organization_id)
        .options(
            selectinload(Assessment.targets),
            selectinload(Assessment.created_by),
        )
        .order_by(Assessment.created_at.desc())
        .limit(_RECENT_ASSESSMENTS)
    )
    return (await session.execute(stmt)).scalars().all()


def _project_recent_assessments(rows: Sequence[Assessment]) -> list[AssessmentOut]:
    """Use the canonical assessment wire projection for relationship-backed fields."""
    return [assessment_out(row) for row in rows]


async def _top_findings(
    session: AsyncSession, organization_id: uuid.UUID
) -> list[DashboardFindingOut]:
    """Highest-risk canonical exposures plus only unprojected legacy rows.

    ``source_kind`` lets the UI route to the correct detail model instead of
    pretending a canonical UUID is a DefectDojo finding UUID.
    """
    exposures = _unified_open_exposures(organization_id)
    stmt = (
        select(
            exposures.c.finding_id.label("id"),
            exposures.c.source_kind,
            exposures.c.title,
            exposures.c.severity,
            exposures.c.priority,
            exposures.c.risk_score,
            exposures.c.risk_factors,
            exposures.c.in_kev,
            exposures.c.first_seen_at,
        )
        .order_by(
            exposures.c.risk_score.desc().nullslast(),
            exposures.c.first_seen_at.desc(),
            exposures.c.finding_id,
        )
        .limit(_TOP_FINDINGS)
    )
    return [DashboardFindingOut.model_validate(row) for row in (await session.execute(stmt)).mappings()]


def _summarize(event: AuditEvent) -> str:
    """One readable line for an audit row.

    Falls back to the dotted verb rather than to nothing, so an action added to
    :class:`~app.services.audit.AuditAction` without a phrase here still renders.
    """
    who = event.actor_email or event.actor_type or "system"
    phrase = _ACTION_PHRASES.get(event.action, event.action)
    return f"{who} {phrase}"


async def _activity(session: AsyncSession, organization_id: uuid.UUID) -> list[ActivityOut]:
    stmt = (
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == organization_id,
            AuditEvent.action.in_(_ACTIVITY_ACTIONS),
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(_ACTIVITY_ROWS)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        ActivityOut(
            id=event.id,
            at=event.created_at,
            actor=event.actor_email,
            actor_type=event.actor_type,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            outcome=event.outcome_enum,
            summary=_summarize(event),
        )
        for event in rows
    ]


async def build_dashboard(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
) -> DashboardOut:
    """Assemble the dashboard for one organization (FR-031).

    Sequential rather than gathered. Every query runs on the same ``AsyncSession``, and a
    session is not safe for concurrent use -- ``asyncio.gather`` over these would
    interleave statements on one connection and produce either a corrupted result or an
    ``InterfaceError``, depending on timing. Each query is an indexed count; the round
    trips are cheap and the correctness is not negotiable.
    """
    # ``ORG_READ`` rather than a dashboard-specific permission: the panel is entirely
    # aggregate counts over data the same role can already read one row at a time, and a
    # separate permission would let a role see a finding but not the number of findings.
    principal.require(Permission.ORG_READ)
    org = principal.organization_id

    assessments_total = await _count(session, tenant_select(Assessment, org))
    assessments_active = await _count(
        session, tenant_select(Assessment, org).where(Assessment.status.in_(ACTIVE_STATUSES))
    )
    awaiting_approval = await _count(
        session,
        tenant_select(Assessment, org).where(
            Assessment.status == AssessmentStatus.WAITING_FOR_APPROVAL.value
        ),
    )

    open_exposures = _unified_open_exposures(org)
    findings_open = int(
        await session.scalar(select(func.count()).select_from(open_exposures)) or 0
    )
    external_alerts_actionable, external_alerts_awaiting_triage = await _external_alert_counts(
        session, org
    )
    severity_breakdown = await _severity_breakdown(session, org)
    priority_breakdown = await _priority_breakdown(session, org)

    assets_total = await _count_assets(session, org)
    assets_critical = await _count_assets(session, org, critical_only=True)

    kev_findings = await _kev_count(session, org)
    mttr = await _mttr_days(session, org)

    health = await integration_health(session, principal)

    return DashboardOut(
        assessments_total=assessments_total,
        assessments_active=assessments_active,
        assessments_awaiting_approval=awaiting_approval,
        findings_open=findings_open,
        external_alerts_actionable=external_alerts_actionable,
        external_alerts_awaiting_triage=external_alerts_awaiting_triage,
        severity_breakdown=severity_breakdown,
        priority_breakdown=priority_breakdown,
        assets_total=assets_total,
        assets_critical=assets_critical,
        kev_findings=kev_findings,
        mean_time_to_remediate_days=mttr,
        recent_assessments=_project_recent_assessments(await _recent_assessments(session, org)),
        top_findings=await _top_findings(session, org),
        activity=await _activity(session, org),
        integration_health=list(health),
        generated_at=_now(),
    )


async def _count_assets(
    session: AsyncSession, organization_id: uuid.UUID, *, critical_only: bool = False
) -> int:
    """Live assets, optionally only the business-critical ones.

    Out-of-scope assets are excluded: an operator who marked a host out of scope has said
    it is not part of the estate under assessment, and continuing to count it inflates
    coverage figures.
    """
    stmt = (
        select(func.count())
        .select_from(Asset)
        .where(
            Asset.organization_id == organization_id,
            Asset.status != AssetStatus.OUT_OF_SCOPE.value,
        )
    )
    if critical_only:
        stmt = stmt.where(Asset.criticality == Criticality.CRITICAL.value)
    return int(await session.scalar(stmt) or 0)


async def team_dashboards(
    session: AsyncSession, principal: Principal
) -> list[TeamDashboardOut]:
    """Return team rollups over the canonical inventory and unprojected legacy rows.

    The asset owns team attribution. Canonical findings are the primary exposure
    record; a DefectDojo row is included only until its source observation has
    been projected, preventing both omissions and double counting.
    """
    principal.require(Permission.ORG_READ)
    org = principal.organization_id
    asset_scope = and_(
        Asset.organization_id == org,
        Asset.owner_team.is_not(None),
        Asset.owner_team != "",
        Asset.status != AssetStatus.OUT_OF_SCOPE.value,
    )
    exposures = _unified_open_exposures(org)
    scoped_exposures = (
        select(exposures)
        .where(
            exposures.c.team.is_not(None),
            exposures.c.team != "",
        )
        .subquery("team_exposures")
    )
    exposure_totals = (
        select(
            scoped_exposures.c.team,
            func.count(scoped_exposures.c.finding_id).label("findings_open"),
            func.count(scoped_exposures.c.finding_id)
            .filter(scoped_exposures.c.in_kev.is_(True))
            .label("kev_findings"),
            func.max(scoped_exposures.c.risk_score).label("highest_risk_score"),
        )
        .group_by(scoped_exposures.c.team)
        .subquery("team_exposure_totals")
    )
    asset_totals = (
        select(
            Asset.owner_team.label("team"),
            func.count(Asset.id).label("assets_total"),
            func.count(Asset.id)
            .filter(Asset.criticality == Criticality.CRITICAL.value)
            .label("assets_critical"),
        )
        .where(asset_scope)
        .group_by(Asset.owner_team)
        .subquery("team_asset_totals")
    )
    totals = (
        await session.execute(
            select(
                asset_totals.c.team,
                asset_totals.c.assets_total,
                asset_totals.c.assets_critical,
                func.coalesce(exposure_totals.c.findings_open, 0),
                func.coalesce(exposure_totals.c.kev_findings, 0),
                exposure_totals.c.highest_risk_score,
            )
            .outerjoin(exposure_totals, exposure_totals.c.team == asset_totals.c.team)
            .order_by(exposure_totals.c.highest_risk_score.desc().nullslast(), asset_totals.c.team)
            .limit(100)
        )
    ).all()
    teams = [str(row[0]) for row in totals]
    if not teams:
        return []
    severity_rows = (
        await session.execute(
            select(
                scoped_exposures.c.team,
                scoped_exposures.c.severity,
                func.count(scoped_exposures.c.finding_id),
            )
            .where(scoped_exposures.c.team.in_(teams))
            .group_by(scoped_exposures.c.team, scoped_exposures.c.severity)
        )
    ).all()
    priority_rows = (
        await session.execute(
            select(
                scoped_exposures.c.team,
                scoped_exposures.c.priority,
                func.count(scoped_exposures.c.finding_id),
            )
            .where(
                scoped_exposures.c.team.in_(teams),
                scoped_exposures.c.priority.is_not(None),
            )
            .group_by(scoped_exposures.c.team, scoped_exposures.c.priority)
        )
    ).all()
    severity_by_team = {team: {item.value: 0 for item in Severity} for team in teams}
    priority_by_team = {team: {item.value: 0 for item in Priority} for team in teams}
    for team, severity, count in severity_rows:
        severity_by_team[str(team)][str(severity)] = int(count)
    for team, priority, count in priority_rows:
        priority_by_team[str(team)][str(priority)] = int(count)
    return [
        TeamDashboardOut(
            team_name=str(team),
            assets_total=int(asset_count or 0),
            assets_critical=int(critical_assets or 0),
            findings_open=int(open_count or 0),
            kev_findings=int(kev_count or 0),
            highest_risk_score=float(highest_risk) if highest_risk is not None else None,
            severity_breakdown=severity_by_team[str(team)],
            priority_breakdown=priority_by_team[str(team)],
        )
        for team, asset_count, critical_assets, open_count, kev_count, highest_risk in totals
    ]


async def risk_trend(
    session: AsyncSession, principal: Principal, *, limit: int = 24
) -> RiskTrendOut:
    """Return a chronological trend from frozen, completed-assessment reports.

    A report snapshot is the only safe historical source: using current canonical
    finding scores would rewrite the past whenever enrichment or remediation changes.
    Only the latest ready report per assessment is selected, which prevents a PDF/HTML
    re-render from creating a duplicate point.
    """
    principal.require(Permission.ORG_READ)
    if limit < 2 or limit > 100:
        raise ValueError("risk trend limit must be between 2 and 100")
    rows = (
        await session.execute(
            select(Report.assessment_id, Report.generated_at, Report.content_digest)
            .where(
                Report.organization_id == principal.organization_id,
                Report.status == "ready",
                Report.generated_at.is_not(None),
            )
            .order_by(Report.generated_at.desc(), Report.id.desc())
            .limit(limit * 8)
        )
    ).all()
    selected: list[tuple[uuid.UUID, dt.datetime, dict[object, object]]] = []
    seen_assessments: set[uuid.UUID] = set()
    for assessment_id, generated_at, digest in rows:
        if assessment_id in seen_assessments or generated_at is None or not isinstance(digest, dict):
            continue
        metrics = digest.get("operational_metrics")
        score = metrics.get("exposure_score") if isinstance(metrics, dict) else None
        if not isinstance(score, int | float):
            continue
        seen_assessments.add(assessment_id)
        selected.append((assessment_id, generated_at, digest))
        if len(selected) == limit:
            break
    selected.reverse()
    references = {
        assessment_id: reference
        for assessment_id, reference in (
            await session.execute(
                select(Assessment.id, Assessment.reference).where(
                    Assessment.organization_id == principal.organization_id,
                    Assessment.id.in_([item[0] for item in selected]),
                )
            )
        ).all()
    } if selected else {}
    points: list[RiskTrendPointOut] = []
    for assessment_id, generated_at, digest in selected:
        metrics = digest.get("operational_metrics")
        metrics = metrics if isinstance(metrics, dict) else {}
        summary = digest.get("summary")
        summary = summary if isinstance(summary, dict) else {}
        points.append(
            RiskTrendPointOut(
                assessment_id=assessment_id,
                assessment_reference=references.get(assessment_id),
                measured_at=generated_at,
                exposure_score=round(float(metrics.get("exposure_score", 0.0)), 2),
                findings_total=max(0, int(digest.get("findings_total") or summary.get("total") or 0)),
                assets_total=max(0, int(digest.get("asset_count") or 0)),
                new_findings=max(0, int(metrics.get("new_findings") or 0)),
                resolved_findings=max(0, int(metrics.get("resolved_findings") or 0)),
            )
        )
    return RiskTrendOut(points=points)


async def asset_group_risks(
    session: AsyncSession, principal: Principal, *, limit: int = 100
) -> list[AssetGroupRiskOut]:
    """Rank explicitly curated asset groups by their canonical exposure.

    ``assets.groups`` is JSONB because a single asset may belong to several business
    services. Expanding it in PostgreSQL keeps the aggregation set-based and ensures a
    multi-source canonical finding is counted once for each business group it affects.
    """
    principal.require(Permission.ORG_READ)
    if not 1 <= limit <= 200:
        raise ValueError("asset group limit must be between 1 and 200")
    rows = (
        await session.execute(
            text(
                """
                SELECT
                    group_value AS group_name,
                    COUNT(DISTINCT a.id) AS assets_total,
                    COUNT(DISTINCT a.id) FILTER (WHERE a.internet_exposed) AS internet_exposed_assets,
                    COUNT(cf.id) FILTER (
                        WHERE cf.status IN ('new', 'open', 'reopened')
                    ) AS findings_open,
                    COUNT(cf.id) FILTER (
                        WHERE cf.status IN ('new', 'open', 'reopened')
                          AND cf.severity IN ('critical', 'high')
                    ) AS critical_or_high_findings,
                    MAX(cf.risk_score) FILTER (
                        WHERE cf.status IN ('new', 'open', 'reopened')
                    ) AS highest_risk_score,
                    COALESCE(SUM(cf.risk_score) FILTER (
                        WHERE cf.status IN ('new', 'open', 'reopened')
                    ), 0) AS aggregate_risk_score
                FROM assets AS a
                CROSS JOIN LATERAL jsonb_array_elements_text(a.groups) AS asset_group(group_value)
                LEFT JOIN canonical_findings AS cf
                  ON cf.asset_id = a.id AND cf.organization_id = a.organization_id
                WHERE a.organization_id = :organization_id
                  AND a.status <> 'out_of_scope'
                GROUP BY group_value
                ORDER BY aggregate_risk_score DESC, highest_risk_score DESC NULLS LAST, group_value
                LIMIT :limit
                """
            ),
            {"organization_id": principal.organization_id, "limit": limit},
        )
    ).mappings().all()
    return [
        AssetGroupRiskOut(
            group_name=str(row["group_name"]),
            assets_total=int(row["assets_total"] or 0),
            internet_exposed_assets=int(row["internet_exposed_assets"] or 0),
            findings_open=int(row["findings_open"] or 0),
            critical_or_high_findings=int(row["critical_or_high_findings"] or 0),
            highest_risk_score=(
                float(row["highest_risk_score"])
                if row["highest_risk_score"] is not None
                else None
            ),
            aggregate_risk_score=round(float(row["aggregate_risk_score"] or 0), 2),
        )
        for row in rows
    ]


__all__ = [
    "ACTIVE_STATUSES",
    "OPEN_STATUSES",
    "build_dashboard",
    "asset_group_risks",
    "risk_trend",
    "team_dashboards",
]
