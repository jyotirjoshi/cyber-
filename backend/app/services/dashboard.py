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
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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
from app.db.models.finding import Finding, FindingEnrichment
from app.db.repository import tenant_select
from app.schemas.assessment import AssessmentOut
from app.schemas.dashboard import ActivityOut, DashboardOut
from app.schemas.finding import FindingOut
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


async def _count(
    session: AsyncSession, stmt: Select[tuple[Finding]] | Select[tuple[Assessment]]
) -> int:
    total = await session.scalar(select(func.count()).select_from(stmt.subquery()))
    return int(total or 0)


async def _severity_breakdown(session: AsyncSession, organization_id: uuid.UUID) -> dict[str, int]:
    stmt = (
        select(Finding.severity, func.count())
        .where(
            Finding.organization_id == organization_id,
            Finding.status.in_(OPEN_STATUSES),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
        )
        .group_by(Finding.severity)
    )
    counts = {severity.value: 0 for severity in Severity}
    for severity, count in (await session.execute(stmt)).all():
        # A severity the database holds but the enum does not is a data defect, not a
        # reason to drop the row: it is surfaced under its own key so somebody notices.
        counts[str(severity)] = int(count)
    return counts


async def _priority_breakdown(session: AsyncSession, organization_id: uuid.UUID) -> dict[str, int]:
    stmt = (
        select(Finding.priority, func.count())
        .where(
            Finding.organization_id == organization_id,
            Finding.status.in_(OPEN_STATUSES),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
            Finding.priority.is_not(None),
        )
        .group_by(Finding.priority)
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
    stmt = (
        select(func.count())
        .select_from(Finding)
        .join(FindingEnrichment, FindingEnrichment.finding_id == Finding.id)
        .where(
            Finding.organization_id == organization_id,
            Finding.status.in_(OPEN_STATUSES),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
            FindingEnrichment.in_kev.is_(True),
        )
    )
    return int(await session.scalar(stmt) or 0)


async def _mttr_days(session: AsyncSession, organization_id: uuid.UUID) -> float | None:
    """Mean days from first observation to mitigation, or ``None``.

    Measured from ``first_seen_at`` rather than ``created_at``: a finding imported today
    that a scanner first saw three months ago was open for three months, and crediting
    Cynux's import date would make every backlog import look like a fast fix.

    ``updated_at`` stands in for a mitigation timestamp. DefectDojo owns the status
    transition and does not hand us the moment it happened, so this is the closest honest
    proxy -- and it is why the field is a *mean over mitigated findings* rather than a
    headline SLA number.
    """
    delta = func.extract("epoch", Finding.updated_at - Finding.first_seen_at)  # seconds, as a float
    stmt = select(func.avg(delta)).where(
        Finding.organization_id == organization_id,
        Finding.status == FindingStatus.MITIGATED.value,
        Finding.first_seen_at.is_not(None),
        Finding.is_false_positive.is_(False),
        Finding.is_duplicate.is_(False),
    )
    seconds = await session.scalar(stmt)
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
        .options(selectinload(Assessment.created_by))
        .order_by(Assessment.created_at.desc())
        .limit(_RECENT_ASSESSMENTS)
    )
    return (await session.execute(stmt)).scalars().all()


async def _top_findings(session: AsyncSession, organization_id: uuid.UUID) -> Sequence[Finding]:
    """Highest-priority open findings by Cynux risk score (FR-023).

    Ordered by ``risk_score`` and not by ``severity``, because the whole point of FR-023 is
    that a medium on an internet-facing crown-jewel asset outranks a critical on a
    decommissioned staging box. ``nullslast`` keeps un-scored findings from taking the top
    slots on a fresh install.
    """
    stmt = (
        _open_findings(organization_id)
        .options(selectinload(Finding.asset), selectinload(Finding.enrichment))
        .order_by(Finding.risk_score.desc().nullslast(), Finding.created_at.desc())
        .limit(_TOP_FINDINGS)
    )
    return (await session.execute(stmt)).scalars().all()


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

    findings_open = await _count(session, _open_findings(org))
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
        severity_breakdown=severity_breakdown,
        priority_breakdown=priority_breakdown,
        assets_total=assets_total,
        assets_critical=assets_critical,
        kev_findings=kev_findings,
        mean_time_to_remediate_days=mttr,
        recent_assessments=[
            AssessmentOut.model_validate(a) for a in await _recent_assessments(session, org)
        ],
        top_findings=[FindingOut.model_validate(f) for f in await _top_findings(session, org)],
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


__all__ = [
    "ACTIVE_STATUSES",
    "OPEN_STATUSES",
    "build_dashboard",
]
