"""Business-service dependency and quantitative exposure API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import DbSession, PrincipalDep
from app.schemas.business_risk import (
    AssetServiceLinkIn,
    AssetServiceLinkOut,
    BusinessRiskScenarioIn,
    BusinessRiskScenarioOut,
    BusinessServiceCreateIn,
    BusinessServiceExposureOut,
    BusinessServiceOut,
)
from app.services import business_risk as service

router = APIRouter(prefix="/business-risk", tags=["business-risk"])


@router.get("/services", response_model=list[BusinessServiceOut])
async def list_business_services(
    principal: PrincipalDep, session: DbSession
) -> list[BusinessServiceOut]:
    return [
        BusinessServiceOut.model_validate(row)
        for row in await service.list_services(session, principal)
    ]


@router.post(
    "/services", response_model=BusinessServiceOut, status_code=status.HTTP_201_CREATED
)
async def create_business_service(
    payload: BusinessServiceCreateIn, principal: PrincipalDep, session: DbSession
) -> BusinessServiceOut:
    row = await service.create_service(session, principal, payload)
    await session.commit()
    return BusinessServiceOut.model_validate(row)


@router.get("/services/{service_id}", response_model=BusinessServiceOut)
async def get_business_service(
    service_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> BusinessServiceOut:
    return BusinessServiceOut.model_validate(
        await service.get_service(session, principal, service_id)
    )


@router.post(
    "/services/{service_id}/assets",
    response_model=AssetServiceLinkOut,
    status_code=status.HTTP_201_CREATED,
)
async def link_business_service_asset(
    service_id: uuid.UUID,
    payload: AssetServiceLinkIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AssetServiceLinkOut:
    row = await service.link_asset(session, principal, service_id, payload)
    await session.commit()
    return AssetServiceLinkOut.model_validate(row)


@router.get("/services/{service_id}/assets", response_model=list[AssetServiceLinkOut])
async def list_business_service_assets(
    service_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[AssetServiceLinkOut]:
    return [
        AssetServiceLinkOut.model_validate(row)
        for row in await service.list_links(session, principal, service_id)
    ]


@router.post(
    "/services/{service_id}/scenarios",
    response_model=BusinessRiskScenarioOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_business_risk_scenario(
    service_id: uuid.UUID,
    payload: BusinessRiskScenarioIn,
    principal: PrincipalDep,
    session: DbSession,
) -> BusinessRiskScenarioOut:
    row = await service.create_scenario(session, principal, service_id, payload)
    await session.commit()
    return BusinessRiskScenarioOut.model_validate(row)


@router.get(
    "/services/{service_id}/scenarios", response_model=list[BusinessRiskScenarioOut]
)
async def list_business_risk_scenarios(
    service_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[BusinessRiskScenarioOut]:
    return [
        BusinessRiskScenarioOut.model_validate(row)
        for row in await service.list_scenarios(session, principal, service_id)
    ]


@router.get("/services/{service_id}/exposure", response_model=BusinessServiceExposureOut)
async def get_business_service_exposure(
    service_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> BusinessServiceExposureOut:
    return BusinessServiceExposureOut.model_validate(
        await service.exposure_summary(session, principal, service_id)
    )


__all__ = ["router"]
