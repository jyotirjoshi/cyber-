"""Tenant-scoped read view across native findings and connector alerts.

This deliberately preserves each source record. A shared CVE or similar title is
not sufficient evidence to merge two exposures or close either source record.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, literal, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import Permission
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding
from app.schemas.common import PaginationParams
from app.services.context import Principal


async def list_exposures(
    session: AsyncSession,
    principal: Principal,
    *,
    pagination: PaginationParams | None = None,
    source: str | None = None,
    severity: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return one ordered page with a true total; never conflate source statuses."""
    principal.require(Permission.FINDING_READ)
    page = pagination or PaginationParams()
    findings = select(
        Finding.id.label("id"),
        literal("defectdojo").label("source"),
        Finding.title.label("title"),
        Finding.severity.label("severity"),
        Finding.status.label("status"),
        func.coalesce(Finding.endpoint, Finding.component).label("resource"),
        func.coalesce(Finding.last_seen_at, Finding.created_at).label("seen_at"),
    ).where(Finding.organization_id == principal.organization_id)
    alerts = select(
        ExternalSecurityAlert.id.label("id"),
        ExternalSecurityAlert.provider.label("source"),
        ExternalSecurityAlert.title.label("title"),
        ExternalSecurityAlert.severity.label("severity"),
        ExternalSecurityAlert.status.label("status"),
        ExternalSecurityAlert.resource.label("resource"),
        func.coalesce(ExternalSecurityAlert.last_seen_at, ExternalSecurityAlert.created_at).label(
            "seen_at"
        ),
    ).where(ExternalSecurityAlert.organization_id == principal.organization_id)
    exposures = union_all(findings, alerts).subquery("exposures")
    conditions = []
    if source:
        conditions.append(exposures.c.source == source)
    if severity:
        conditions.append(exposures.c.severity == severity)

    total = int(
        (
            await session.execute(select(func.count()).select_from(exposures).where(*conditions))
        ).scalar_one()
    )
    statement = (
        select(exposures)
        .where(*conditions)
        .order_by(exposures.c.seen_at.desc().nullslast(), exposures.c.source, exposures.c.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(statement)).mappings().all()
    return [dict(row) for row in rows], total
