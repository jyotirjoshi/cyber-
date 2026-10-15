"""Attack Surface Management — continuous passive discovery surfaces (ASM)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import DbSession, PrincipalDep, SettingsDep
from app.schemas.asm import AsmSurfaceCreateIn, AsmSurfaceOut, AsmSurfaceUpdateIn
from app.services import asm_discovery as asm_service

router = APIRouter(prefix="/asm/surfaces", tags=["asm"])


@router.get("", response_model=list[AsmSurfaceOut])
async def list_surfaces(
    principal: PrincipalDep,
    session: DbSession,
) -> list[AsmSurfaceOut]:
    rows = await asm_service.list_surfaces(session, principal)
    return [AsmSurfaceOut.model_validate(row) for row in rows]


@router.post("", response_model=AsmSurfaceOut, status_code=201)
async def create_surface(
    payload: AsmSurfaceCreateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> AsmSurfaceOut:
    surface = await asm_service.create_surface(session, principal, payload, settings)
    await session.commit()
    surface = await asm_service.get_surface(session, principal, surface.id)
    return AsmSurfaceOut.model_validate(surface)


@router.get("/{surface_id}", response_model=AsmSurfaceOut)
async def get_surface(
    surface_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AsmSurfaceOut:
    surface = await asm_service.get_surface(session, principal, surface_id)
    return AsmSurfaceOut.model_validate(surface)


@router.patch("/{surface_id}", response_model=AsmSurfaceOut)
async def update_surface(
    surface_id: uuid.UUID,
    payload: AsmSurfaceUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> AsmSurfaceOut:
    surface = await asm_service.update_surface(session, principal, surface_id, payload, settings)
    await session.commit()
    surface = await asm_service.get_surface(session, principal, surface_id)
    return AsmSurfaceOut.model_validate(surface)


@router.delete("/{surface_id}", status_code=204, response_class=Response)
async def delete_surface(
    surface_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> Response:
    await asm_service.delete_surface(session, principal, surface_id)
    await session.commit()
    return Response(status_code=204)
