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

from fastapi import APIRouter

from app.api.deps import DbSession, PrincipalDep, SettingsDep
from app.schemas.dashboard import DashboardOut
from app.services import dashboard as dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardOut)
async def get_dashboard(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> DashboardOut:
    """The organization's dashboard aggregates (FR-031)."""
    return await dashboard_service.build_dashboard(session, principal, settings=settings)


__all__ = ["router"]
