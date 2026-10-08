"""Application-level exposure and repeated repository patterns."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PrincipalDep
from app.schemas.application_risk import ApplicationPatternsOut, ApplicationRiskPageOut
from app.services import application_risk as application_risk_service

router = APIRouter(prefix="/applications", tags=["applications"])


@router.get("/risks", response_model=ApplicationRiskPageOut)
async def list_application_risks(
    principal: PrincipalDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ApplicationRiskPageOut:
    return await application_risk_service.list_application_risks(
        session,
        principal,
        limit=limit,
        offset=offset,
    )


@router.get("/patterns", response_model=ApplicationPatternsOut)
async def get_application_patterns(
    application: Annotated[str, Query(min_length=1, max_length=120, pattern=r"^[^\x00-\x1f]+$")],
    principal: PrincipalDep,
    session: DbSession,
) -> ApplicationPatternsOut:
    return await application_risk_service.get_application_patterns(
        session,
        principal,
        application,
    )
