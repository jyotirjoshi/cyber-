"""Tenant-scoped reads for canonical findings and their evidence history."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.canonical import CanonicalFinding, FindingHistory, FindingObservation
from app.db.repository import TenantRepository, tenant_select
from app.schemas.common import PaginationParams
from app.services.context import Principal


async def list_canonical_findings(
    session: AsyncSession,
    principal: Principal,
    pagination: PaginationParams,
    *,
    mine: bool = False,
    overdue: bool = False,
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
