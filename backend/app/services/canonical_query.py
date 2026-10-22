"""Tenant-scoped reads for canonical findings and their evidence history."""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import (
    CanonicalFinding,
    FindingHistory,
    FindingObservation,
    RetestRequest,
    RiskAcceptance,
    SlaEscalation,
)
from app.db.models.finding import TicketLink
from app.db.repository import TenantRepository, tenant_select
from app.schemas.canonical import FieldProvenanceOut
from app.schemas.common import PaginationParams
from app.services.context import Principal
from app.services.remediation_convergence import (
    RemediationConvergence,
    derive_remediation_convergence,
)


def _intel_sources(value: Any) -> set[str]:
    sources: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"source", "provider"} and isinstance(item, str) and item.strip():
                sources.add(item.strip()[:80])
            else:
                sources.update(_intel_sources(item))
    elif isinstance(value, list):
        for item in value:
            sources.update(_intel_sources(item))
    return sources


def build_field_provenance(
    finding: CanonicalFinding,
    observations: list[FindingObservation],
) -> list[FieldProvenanceOut]:
    """Explain each canonical field using only persisted source observations."""
    active = [
        observation
        for observation in observations
        if observation.source_status not in {"absent", "superseded"}
    ]
    total = max(1, len(active))

    def observed_field(field: str, value: Any) -> FieldProvenanceOut:
        normalized_value = str(value or "").strip().casefold()
        supporting = [
            observation
            for observation in active
            if str(getattr(observation, field, "") or "").strip().casefold()
            == normalized_value
        ]
        distinct = {
            str(getattr(observation, field, "") or "").strip().casefold()
            for observation in active
            if str(getattr(observation, field, "") or "").strip()
        }
        return FieldProvenanceOut(
            field=field,
            value=value,
            sources=sorted({observation.provider for observation in supporting}),
            observation_ids=sorted((observation.id for observation in supporting), key=str),
            confidence=round(len(supporting) / total, 4),
            conflicts=len(distinct) > 1,
        )

    cve_set = {str(cve).upper() for cve in (finding.cve_ids or [])}
    cve_support = [
        observation
        for observation in active
        if str(observation.cve_id or "").upper() in cve_set
    ]
    sources = sorted({"cynux:risk_engine", *_intel_sources(finding.intel_evidence or {})})
    all_sources = sorted({observation.provider for observation in active})
    all_ids = sorted((observation.id for observation in active), key=str)
    return [
        observed_field("title", finding.title),
        observed_field("severity", finding.severity),
        FieldProvenanceOut(
            field="cve_ids",
            value=list(finding.cve_ids or []),
            sources=sorted({observation.provider for observation in cve_support}),
            observation_ids=sorted((observation.id for observation in cve_support), key=str),
            confidence=round(len(cve_support) / total, 4) if cve_set else 1.0,
            conflicts=bool(
                cve_set
                and {
                    str(observation.cve_id).upper()
                    for observation in active
                    if observation.cve_id
                }
                - cve_set
            ),
        ),
        FieldProvenanceOut(
            field="status",
            value=finding.status,
            sources=["cynux:lifecycle"],
            observation_ids=[],
            confidence=1.0,
        ),
        FieldProvenanceOut(
            field="risk_score",
            value=finding.risk_score,
            sources=sources,
            observation_ids=all_ids,
            confidence=1.0 if finding.risk_score is not None else 0.0,
        ),
        FieldProvenanceOut(
            field="first_seen_at",
            value=finding.first_seen_at,
            sources=all_sources,
            observation_ids=all_ids,
            confidence=1.0 if active else 0.0,
        ),
        FieldProvenanceOut(
            field="last_seen_at",
            value=finding.last_seen_at,
            sources=all_sources,
            observation_ids=all_ids,
            confidence=1.0 if active else 0.0,
        ),
    ]


async def list_canonical_findings(
    session: AsyncSession,
    principal: Principal,
    pagination: PaginationParams,
    *,
    mine: bool = False,
    overdue: bool = False,
    severity: str | None = None,
    status: str | None = None,
    q: str | None = None,
    query: str | None = None,
) -> tuple[list[CanonicalFinding], int]:
    principal.require(Permission.FINDING_READ)
    conditions = [CanonicalFinding.organization_id == principal.organization_id]
    if mine:
        conditions.append(CanonicalFinding.assignee_user_id == principal.user_id)
    if overdue:
        conditions.extend(
            (
                CanonicalFinding.due_at < utcnow(),
                CanonicalFinding.status.not_in(("closed", "false_positive", "accepted_risk")),
            )
        )
    if severity:
        conditions.append(CanonicalFinding.severity == severity)
    if status:
        conditions.append(CanonicalFinding.status == status)
    if q:
        escaped = re.sub(r"([%_\\])", r"\\\1", q.strip())
        text_match = CanonicalFinding.title.ilike(f"%{escaped}%", escape="\\")
        cve = q.strip().upper()
        conditions.append(
            or_(
                text_match,
                CanonicalFinding.cve_ids.contains([cve])
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve)
                else False,
            )
        )
    if query:
        from app.services.query_language import compile_query

        conditions.append(
            compile_query(
                query,
                resource="findings",
                organization_id=principal.organization_id,
                user_id=principal.user_id,
            )
        )
    statement = select(CanonicalFinding).where(*conditions)
    total = int(
        (
            await session.execute(
                select(func.count()).select_from(CanonicalFinding).where(*conditions)
            )
        ).scalar_one()
    )
    rows = (
        (
            await session.execute(
                statement.order_by(
                    CanonicalFinding.risk_score.desc(),
                    CanonicalFinding.last_seen_at.desc(),
                    CanonicalFinding.id,
                )
                .limit(pagination.limit)
                .offset(pagination.offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_canonical_finding(
    session: AsyncSession, principal: Principal, finding_id: uuid.UUID
) -> tuple[CanonicalFinding, list[FindingObservation], list[FindingHistory]]:
    principal.require(Permission.FINDING_READ)
    finding = await TenantRepository(
        session, CanonicalFinding, principal.organization_id
    ).get_or_404(finding_id)
    observations = (
        (
            await session.execute(
                tenant_select(FindingObservation, principal.organization_id)
                .where(FindingObservation.canonical_finding_id == finding.id)
                .order_by(
                    FindingObservation.provider,
                    FindingObservation.external_id,
                    FindingObservation.cve_id,
                )
            )
        )
        .scalars()
        .all()
    )
    history = (
        (
            await session.execute(
                tenant_select(FindingHistory, principal.organization_id)
                .where(FindingHistory.canonical_finding_id == finding.id)
                .order_by(FindingHistory.occurred_at.desc(), FindingHistory.id.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    return finding, list(observations), list(history)


async def list_remediation_operations(
    session: AsyncSession,
    principal: Principal,
    pagination: PaginationParams,
    *,
    mine: bool = False,
    overdue: bool = False,
    attention_only: bool = False,
    asset_group: str | None = None,
    remediation_group: str | None = None,
) -> tuple[
    list[
        tuple[
            CanonicalFinding,
            list[TicketLink],
            RiskAcceptance | None,
            RetestRequest | None,
            str,
            list[str],
            int,
            int,
            RemediationConvergence,
        ]
    ],
    int,
]:
    """Return a compact, tenant-scoped remediation work queue.

    The page-sized finding read is followed by bounded batched reads.  This
    avoids a per-row query for ticket and governance state while keeping each source
    of truth independent and auditable.
    """
    principal.require(Permission.FINDING_READ)
    inactive = ("closed", "false_positive")
    conditions = [CanonicalFinding.organization_id == principal.organization_id]
    if mine:
        conditions.append(CanonicalFinding.assignee_user_id == principal.user_id)
    if overdue:
        conditions.extend((CanonicalFinding.due_at < utcnow(), CanonicalFinding.status.not_in(inactive)))
    if attention_only:
        conditions.append(CanonicalFinding.status.not_in((*inactive, "accepted_risk")))

    normalized_group = asset_group.strip() if asset_group is not None else None
    if asset_group is not None and not normalized_group:
        raise ValueError("asset_group cannot be blank")
    if normalized_group is not None:
        conditions.append(Asset.groups.contains([normalized_group]))
    normalized_remediation_group = remediation_group.strip() if remediation_group is not None else None
    if remediation_group is not None and not normalized_remediation_group:
        raise ValueError("remediation_group cannot be blank")
    if normalized_remediation_group is not None:
        conditions.append(
            CanonicalFinding.remediation_group_key == normalized_remediation_group.lower()
        )

    base_statement = select(CanonicalFinding)
    count_statement = select(func.count()).select_from(CanonicalFinding)
    if normalized_group is not None:
        asset_join = (Asset.id == CanonicalFinding.asset_id) & (
            Asset.organization_id == CanonicalFinding.organization_id
        )
        base_statement = base_statement.join(Asset, asset_join)
        count_statement = count_statement.join(Asset, asset_join)
    statement = base_statement.where(*conditions)
    total = int((await session.execute(count_statement.where(*conditions))).scalar_one())
    findings = list(
        (
            await session.execute(
                statement.order_by(
                    CanonicalFinding.risk_score.desc(),
                    CanonicalFinding.due_at.asc().nulls_last(),
                    CanonicalFinding.last_seen_at.desc(),
                    CanonicalFinding.id,
                )
                .limit(pagination.limit)
                .offset(pagination.offset)
            )
        ).scalars().all()
    )
    if not findings:
        return [], total

    finding_ids = [finding.id for finding in findings]
    tickets = list(
        (
            await session.execute(
                tenant_select(TicketLink, principal.organization_id)
                .where(TicketLink.canonical_finding_id.in_(finding_ids))
                .order_by(TicketLink.created_at.desc(), TicketLink.id)
            )
        ).scalars().all()
    )
    acceptances = list(
        (
            await session.execute(
                tenant_select(RiskAcceptance, principal.organization_id)
                .where(RiskAcceptance.canonical_finding_id.in_(finding_ids))
                .order_by(RiskAcceptance.created_at.desc(), RiskAcceptance.id)
            )
        ).scalars().all()
    )
    retests = list(
        (
            await session.execute(
                tenant_select(RetestRequest, principal.organization_id)
                .where(RetestRequest.canonical_finding_id.in_(finding_ids))
                .order_by(RetestRequest.created_at.desc(), RetestRequest.id)
            )
        ).scalars().all()
    )
    observation_counts = {
        finding_id: int(count)
        for finding_id, count in (
            await session.execute(
                select(FindingObservation.canonical_finding_id, func.count())
                .where(
                    FindingObservation.organization_id == principal.organization_id,
                    FindingObservation.canonical_finding_id.in_(finding_ids),
                    FindingObservation.source_status.not_in(("absent", "superseded")),
                )
                .group_by(FindingObservation.canonical_finding_id)
            )
        ).all()
    }
    escalation_levels = {
        finding_id: int(level)
        for finding_id, level in (
            await session.execute(
                select(SlaEscalation.canonical_finding_id, func.max(SlaEscalation.level))
                .where(
                    SlaEscalation.organization_id == principal.organization_id,
                    SlaEscalation.canonical_finding_id.in_(finding_ids),
                )
                .group_by(SlaEscalation.canonical_finding_id)
            )
        ).all()
    }
    tickets_by_finding: dict[uuid.UUID, list[TicketLink]] = {}
    for ticket in tickets:
        if ticket.canonical_finding_id is not None:
            tickets_by_finding.setdefault(ticket.canonical_finding_id, []).append(ticket)
    latest_acceptance: dict[uuid.UUID, RiskAcceptance] = {}
    for acceptance in acceptances:
        latest_acceptance.setdefault(acceptance.canonical_finding_id, acceptance)
    latest_retest: dict[uuid.UUID, RetestRequest] = {}
    for retest in retests:
        latest_retest.setdefault(retest.canonical_finding_id, retest)

    now = utcnow()

    def next_action(finding: CanonicalFinding, retest: RetestRequest | None) -> str:
        if finding.due_at is not None and finding.due_at < now and finding.status not in inactive:
            return "Resolve overdue remediation"
        if finding.assignee_user_id is None:
            return "Assign an owner"
        if not finding.remediation_plan:
            return "Add a remediation plan"
        if retest is not None and retest.status in {"requested", "scheduled", "running"}:
            return "Complete retest verification"
        return "Review remediation progress"

    def priority_reasons(
        finding: CanonicalFinding, retest: RetestRequest | None, source_observations: int
    ) -> list[str]:
        """Translate the stored scoring snapshot into concise, auditable fix-first reasons."""
        factors = finding.risk_factors if isinstance(finding.risk_factors, dict) else {}
        inputs = factors.get("inputs") if isinstance(factors.get("inputs"), dict) else {}
        reasons: list[str] = []
        if finding.due_at is not None and finding.due_at < now and finding.status not in inactive:
            reasons.append("Remediation due date has passed.")
        if finding.risk_score >= 80:
            reasons.append(f"Composite risk is {finding.risk_score:.1f}/100.")
        elif finding.severity in {"critical", "high"}:
            reasons.append(f"{finding.severity.capitalize()} severity increases impact.")
        if inputs.get("in_kev") is True:
            reasons.append("CISA KEV identifies known exploitation.")
        elif inputs.get("observed_in_the_wild") is True:
            reasons.append("Exploitation has been observed in the wild.")
        elif inputs.get("exploit_available") is True:
            reasons.append("Public exploit evidence is available.")
        if inputs.get("ransomware_use") is True:
            reasons.append("Associated with ransomware activity.")
        if inputs.get("internet_exposed") is True:
            reasons.append("Affected asset is internet exposed.")
        if inputs.get("asset_criticality") in {"critical", "high"}:
            reasons.append("Affected asset has high business criticality.")
        if source_observations > 1:
            reasons.append(f"Corroborated by {source_observations} active source observations.")
        epss = inputs.get("epss_score")
        if isinstance(epss, int | float) and not isinstance(epss, bool) and epss >= 0.5:
            reasons.append(f"EPSS exploitation probability is {epss:.0%}.")
        if retest is not None and retest.status in {"requested", "scheduled", "running"}:
            reasons.append("Fix verification evidence is still pending.")
        return reasons[:4] or ["Composite risk score is the current prioritization signal."]

    return [
        (
            finding,
            tickets_by_finding.get(finding.id, []),
            latest_acceptance.get(finding.id),
            latest_retest.get(finding.id),
            next_action(finding, latest_retest.get(finding.id)),
            priority_reasons(
                finding,
                latest_retest.get(finding.id),
                observation_counts.get(finding.id, 0),
            ),
            observation_counts.get(finding.id, 0),
            escalation_levels.get(finding.id, 0),
            derive_remediation_convergence(
                finding_status=finding.status,
                ticket_statuses=[
                    ticket.external_status
                    for ticket in tickets_by_finding.get(finding.id, [])
                ],
                retest_status=(
                    latest_retest[finding.id].status if finding.id in latest_retest else None
                ),
                retest_evidence=(
                    latest_retest[finding.id].evidence if finding.id in latest_retest else None
                ),
            ),
        )
        for finding in findings
    ], total


async def list_remediation_groups(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 100,
) -> list[tuple[str, int, int, float, dt.datetime]]:
    """Return active patch campaigns without grouping or exposing source observations."""
    principal.require(Permission.FINDING_READ)
    if not 1 <= limit <= 100:
        raise ValueError("remediation group limit must be between 1 and 100")
    inactive = ("closed", "false_positive")
    rows = await session.execute(
        select(
            func.min(CanonicalFinding.remediation_group),
            func.count(),
            func.count().filter(CanonicalFinding.due_at < utcnow()),
            func.max(CanonicalFinding.risk_score),
            func.max(CanonicalFinding.last_seen_at),
        )
        .where(
            CanonicalFinding.organization_id == principal.organization_id,
            CanonicalFinding.remediation_group_key.is_not(None),
            CanonicalFinding.status.not_in(inactive),
        )
        .group_by(CanonicalFinding.remediation_group_key)
        .order_by(func.max(CanonicalFinding.risk_score).desc(), CanonicalFinding.remediation_group_key)
        .limit(limit)
    )
    return [
        (str(name), int(active), int(overdue), float(highest), last_seen)
        for name, active, overdue, highest, last_seen in rows.all()
        if name is not None and isinstance(last_seen, dt.datetime)
    ]
