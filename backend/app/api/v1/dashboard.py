"""Dashboard endpoint (FR-031).

One aggregate view of an organization's security posture: assessment and finding counts,
severity and priority breakdowns, confirmed-KEV exposure, mean time to remediate, the most
recent assessments, the highest-risk open findings, a readable activity slice and integration
health. Every number is computed in SQL by :func:`app.services.dashboard.build_dashboard`; this
module is only the transport.

Read-only, so there is no commit. ``ORG_READ`` -- not a dashboard-specific permission -- is
enforced in the service: the panel is aggregate counts over data the same role can already read
one row at a time.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Response, status

from app.api.deps import DbSession, PrincipalDep, SettingsDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.platform import DashboardLayout
from app.db.repository import tenant_select
from app.schemas.dashboard import AssetGroupRiskOut, DashboardOut, RiskTrendOut, TeamDashboardOut
from app.schemas.dashboard_layout import DashboardLayoutIn, DashboardLayoutOut
from app.services.audit import AuditAction, record
from app.services import dashboard as dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/layouts", response_model=list[DashboardLayoutOut])
async def list_dashboard_layouts(principal: PrincipalDep, session: DbSession) -> list[DashboardLayout]:
    principal.require(Permission.ORG_READ)
    return list((await session.scalars(
        tenant_select(DashboardLayout, principal.organization_id)
        .order_by(DashboardLayout.is_default.desc(), DashboardLayout.name).limit(100)
    )).all())


@router.post("/layouts", response_model=DashboardLayoutOut, status_code=status.HTTP_201_CREATED)
async def create_dashboard_layout(
    payload: DashboardLayoutIn, principal: PrincipalDep, session: DbSession
) -> DashboardLayout:
    principal.require(Permission.ORG_MANAGE)
    if payload.is_default:
        for existing in (await session.scalars(
            tenant_select(DashboardLayout, principal.organization_id).where(DashboardLayout.audience == payload.audience, DashboardLayout.is_default.is_(True)).with_for_update()
        )).all():
            existing.is_default = False
    layout = DashboardLayout(
        organization_id=principal.organization_id, created_by_id=principal.user_id,
        name=payload.name.strip(), audience=payload.audience,
        widgets=[{"key": widget} for widget in payload.widgets], is_default=payload.is_default,
    )
    session.add(layout)
    await session.flush()
    await record(session, action=AuditAction.DASHBOARD_LAYOUT_CREATE, principal=principal,
                 resource_type="dashboard_layout", resource_id=layout.id,
                 detail={"audience": layout.audience, "widget_count": len(layout.widgets)})
    await session.commit()
    return layout


@router.put("/layouts/{layout_id}", response_model=DashboardLayoutOut)
async def update_dashboard_layout(
    layout_id: uuid.UUID, payload: DashboardLayoutIn, principal: PrincipalDep, session: DbSession
) -> DashboardLayout:
    principal.require(Permission.ORG_MANAGE)
    layout = (await session.execute(
        tenant_select(DashboardLayout, principal.organization_id).where(DashboardLayout.id == layout_id).with_for_update()
    )).scalar_one_or_none()
    if layout is None:
        raise ResourceNotFoundError("Dashboard layout not found")
    if payload.is_default:
        for existing in (await session.scalars(
            tenant_select(DashboardLayout, principal.organization_id).where(DashboardLayout.audience == payload.audience, DashboardLayout.is_default.is_(True), DashboardLayout.id != layout.id).with_for_update()
        )).all():
            existing.is_default = False
    layout.name, layout.audience, layout.widgets, layout.is_default = (
        payload.name.strip(), payload.audience, [{"key": widget} for widget in payload.widgets], payload.is_default,
    )
    await record(session, action=AuditAction.DASHBOARD_LAYOUT_UPDATE, principal=principal,
                 resource_type="dashboard_layout", resource_id=layout.id,
                 detail={"audience": layout.audience, "widget_count": len(layout.widgets)})
    await session.commit()
    return layout


@router.delete(
    "/layouts/{layout_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_dashboard_layout(
    layout_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> Response:
    """Remove one tenant-owned declarative layout; dashboard data is never affected."""
    principal.require(Permission.ORG_MANAGE)
    layout = (await session.execute(
        tenant_select(DashboardLayout, principal.organization_id)
        .where(DashboardLayout.id == layout_id)
        .with_for_update()
    )).scalar_one_or_none()
    if layout is None:
        raise ResourceNotFoundError("Dashboard layout not found")
    await record(
        session, action=AuditAction.DASHBOARD_LAYOUT_DELETE, principal=principal,
        resource_type="dashboard_layout", resource_id=layout.id,
        detail={"audience": layout.audience, "widget_count": len(layout.widgets)},
    )
    await session.delete(layout)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("", response_model=DashboardOut)
async def get_dashboard(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> DashboardOut:
    """The organization's dashboard aggregates (FR-031)."""
    return await dashboard_service.build_dashboard(session, principal, settings=settings)


@router.get("/teams", response_model=list[TeamDashboardOut])
async def get_team_dashboards(
    principal: PrincipalDep, session: DbSession
) -> list[TeamDashboardOut]:
    """Live team-level exposure rollups based on asset ownership."""
    return await dashboard_service.team_dashboards(session, principal)


@router.get("/asset-groups", response_model=list[AssetGroupRiskOut])
async def get_asset_group_risks(
    principal: PrincipalDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[AssetGroupRiskOut]:
    """Business-service exposure ranked from the canonical finding inventory."""
    return await dashboard_service.asset_group_risks(session, principal, limit=limit)


@router.get("/risk-trend", response_model=RiskTrendOut)
async def get_risk_trend(
    principal: PrincipalDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=2, le=100)] = 24,
) -> RiskTrendOut:
    """Exposure trend based on immutable, completed assessment report snapshots."""
    return await dashboard_service.risk_trend(session, principal, limit=limit)


__all__ = ["router"]
