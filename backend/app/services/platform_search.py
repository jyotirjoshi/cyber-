"""Permission-aware, tenant-scoped search across primary operational records."""

from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import Permission
from app.db.models.agent import AgentSession
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.db.models.finding import TicketLink
from app.db.models.report import Report
from app.db.models.soc import SocIncidentCase
from app.db.repository import tenant_select
from app.schemas.platform import PlatformSearchResultOut
from app.services.context import Principal


def search_pattern(value: str) -> str:
    """Return a SQL LIKE pattern with user-supplied wildcards treated literally."""
    cleaned = value.strip()
    escaped = cleaned.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


async def global_search(
    session: AsyncSession,
    principal: Principal,
    *,
    query: str,
    limit_per_kind: int = 5,
) -> list[PlatformSearchResultOut]:
    """Search only resource families the caller can already read."""
    if len(query.strip()) < 2:
        return []
    pattern = search_pattern(query)
    org_id = principal.organization_id
    results: list[PlatformSearchResultOut] = []

    async def rows(statement: object) -> list[object]:
        return list((await session.scalars(statement)).all())  # type: ignore[arg-type]

    if principal.has(Permission.ASSET_READ):
        assets = await rows(
            tenant_select(Asset, org_id)
            .where(
                or_(
                    Asset.name.ilike(pattern, escape="\\"),
                    Asset.ip_address.ilike(pattern, escape="\\"),
                    Asset.service.ilike(pattern, escape="\\"),
                )
            )
            .order_by(Asset.risk_score.desc(), Asset.updated_at.desc())
            .limit(limit_per_kind)
        )
        results.extend(
            PlatformSearchResultOut(
                kind="asset",
                id=item.id,
                title=item.name,
                subtitle=f"{item.asset_type} · {item.environment} · risk {item.risk_score:.0f}",
                href=f"/assets/{item.id}",
            )
            for item in assets
        )

    if principal.has(Permission.FINDING_READ):
        findings = await rows(
            tenant_select(CanonicalFinding, org_id)
            .where(CanonicalFinding.title.ilike(pattern, escape="\\"))
            .order_by(CanonicalFinding.risk_score.desc(), CanonicalFinding.updated_at.desc())
            .limit(limit_per_kind)
        )
        results.extend(
            PlatformSearchResultOut(
                kind="finding",
                id=item.id,
                title=item.title,
                subtitle=f"{item.severity} · {item.status} · risk {item.risk_score:.1f}",
                href=f"/findings/canonical/{item.id}",
            )
            for item in findings
        )
        cases = await rows(
            tenant_select(SocIncidentCase, org_id)
            .where(
                or_(
                    SocIncidentCase.title.ilike(pattern, escape="\\"),
                    SocIncidentCase.case_key.ilike(pattern, escape="\\"),
                    SocIncidentCase.summary.ilike(pattern, escape="\\"),
                )
            )
            .order_by(SocIncidentCase.priority.desc(), SocIncidentCase.updated_at.desc())
            .limit(limit_per_kind)
        )
        results.extend(
            PlatformSearchResultOut(
                kind="case",
                id=item.id,
                title=item.title,
                subtitle=f"{item.case_key} · {item.severity} · {item.status}",
                href="/control-plane",
            )
            for item in cases
        )
        tickets = await rows(
            tenant_select(TicketLink, org_id)
            .where(
                or_(
                    TicketLink.external_key.ilike(pattern, escape="\\"),
                    TicketLink.project_key.ilike(pattern, escape="\\"),
                    TicketLink.external_status.ilike(pattern, escape="\\"),
                )
            )
            .order_by(TicketLink.updated_at.desc())
            .limit(limit_per_kind)
        )
        results.extend(
            PlatformSearchResultOut(
                kind="ticket",
                id=item.id,
                title=f"{item.provider}: {item.external_key}",
                subtitle=item.external_status or "Status not synchronized",
                href="/remediation",
            )
            for item in tickets
        )

    if principal.has(Permission.AGENT_CHAT):
        sessions = await rows(
            tenant_select(AgentSession, org_id)
            .where(AgentSession.title.ilike(pattern, escape="\\"))
            .order_by(AgentSession.last_activity_at.desc().nulls_last())
            .limit(limit_per_kind)
        )
        results.extend(
            PlatformSearchResultOut(
                kind="agent",
                id=item.id,
                title=item.title,
                subtitle=f"Agent workspace · {item.message_count} messages",
                href=f"/agent/{item.id}",
            )
            for item in sessions
        )

    if principal.has(Permission.REPORT_READ):
        reports = await rows(
            tenant_select(Report, org_id)
            .where(Report.title.ilike(pattern, escape="\\"))
            .order_by(Report.created_at.desc())
            .limit(limit_per_kind)
        )
        results.extend(
            PlatformSearchResultOut(
                kind="report",
                id=item.id,
                title=item.title,
                subtitle=f"{item.audience} · {item.format} · {item.status}",
                href="/reports",
            )
            for item in reports
        )

    return results


__all__ = ["global_search", "search_pattern"]
