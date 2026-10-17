from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import DbSession, PrincipalDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.custom_connector import CustomConnector, CustomConnectorRun
from app.db.repository import tenant_select
from app.schemas.custom_connector import (
    CustomConnectorIn,
    CustomConnectorOut,
    CustomConnectorRunIn,
    CustomConnectorRunOut,
)
from app.services.custom_connector import create_connector, reserve_connector_run

router = APIRouter(prefix="/custom-connectors", tags=["custom-connectors"])


@router.get("", response_model=list[CustomConnectorOut])
async def list_connectors(principal: PrincipalDep, session: DbSession) -> list[CustomConnectorOut]:
    principal.require(Permission.INTEGRATION_READ)
    rows = await session.scalars(tenant_select(CustomConnector, principal.organization_id).order_by(CustomConnector.name))
    return [CustomConnectorOut.model_validate(row) for row in rows.all()]


@router.post("", response_model=CustomConnectorOut, status_code=status.HTTP_201_CREATED)
async def add_connector(payload: CustomConnectorIn, principal: PrincipalDep, session: DbSession) -> CustomConnectorOut:
    row = await create_connector(session, principal, payload)
    await session.commit()
    return CustomConnectorOut.model_validate(row)


@router.get("/{connector_id}/runs", response_model=list[CustomConnectorRunOut])
async def connector_runs(connector_id: uuid.UUID, principal: PrincipalDep, session: DbSession) -> list[CustomConnectorRunOut]:
    principal.require(Permission.INTEGRATION_READ)
    connector = await session.scalar(tenant_select(CustomConnector, principal.organization_id).where(CustomConnector.id == connector_id))
    if connector is None:
        raise ResourceNotFoundError("Custom connector not found")
    rows = await session.scalars(tenant_select(CustomConnectorRun, principal.organization_id).where(CustomConnectorRun.connector_id == connector_id).order_by(CustomConnectorRun.created_at.desc()).limit(100))
    return [CustomConnectorRunOut.model_validate(row) for row in rows.all()]


@router.post("/{connector_id}/runs", response_model=CustomConnectorRunOut, status_code=status.HTTP_202_ACCEPTED)
async def run_connector(connector_id: uuid.UUID, payload: CustomConnectorRunIn, principal: PrincipalDep, session: DbSession) -> CustomConnectorRunOut:
    connector = await session.scalar(tenant_select(CustomConnector, principal.organization_id).where(CustomConnector.id == connector_id))
    if connector is None:
        raise ResourceNotFoundError("Custom connector not found")
    row, _ = await reserve_connector_run(
        session, principal, connector, idempotency_key=payload.idempotency_key
    )
    await session.commit()
    return CustomConnectorRunOut.model_validate(row)


__all__ = ["router"]
