"""Write-only authenticated scan profile management."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import DbSession, PrincipalDep, SettingsDep
from app.schemas.scan_auth import ScanAuthProfileIn, ScanAuthProfileOut
from app.services import scan_auth as service

router = APIRouter(prefix="/scan-auth", tags=["scan-auth"])


@router.get("", response_model=list[ScanAuthProfileOut])
async def list_profiles(principal: PrincipalDep, session: DbSession) -> list[ScanAuthProfileOut]:
    return [ScanAuthProfileOut.model_validate(row) for row in await service.list_profiles(session, principal)]


@router.post("", response_model=ScanAuthProfileOut, status_code=201)
async def create_profile(body: ScanAuthProfileIn, principal: PrincipalDep, session: DbSession, settings: SettingsDep) -> ScanAuthProfileOut:
    row = await service.create_profile(session, principal, body, settings)
    await session.commit()
    await session.refresh(row)
    return ScanAuthProfileOut.model_validate(row)


@router.delete("/{profile_id}", status_code=204, response_class=Response)
async def delete_profile(profile_id: uuid.UUID, principal: PrincipalDep, session: DbSession) -> Response:
    await service.delete_profile(session, principal, profile_id)
    await session.commit()
    return Response(status_code=204)


__all__ = ["router"]
