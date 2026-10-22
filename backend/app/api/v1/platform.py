"""Public platform credential endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession, PrincipalDep, StorageDep
from app.db.enums import Permission
from app.db.models.platform import PlatformApiKey
from app.db.repository import tenant_select
from app.schemas.platform import (
    DemoWorkspaceOut,
    PlatformApiKeyCreateIn,
    PlatformApiKeyIssuedOut,
    PlatformApiKeyOut,
    PlatformOnboardingOut,
    PlatformReadinessOut,
    PlatformSearchResultOut,
)
from app.services.audit import AuditAction, record
from app.services.demo_workspace import create_demo_workspace
from app.services.platform_api_key import create_platform_api_key, revoke_platform_api_key
from app.services.platform_onboarding import get_onboarding
from app.services.platform_readiness import get_readiness
from app.services.platform_search import global_search

router = APIRouter(prefix="/platform", tags=["platform"])


@router.get("/onboarding", response_model=PlatformOnboardingOut)
async def platform_onboarding(principal: PrincipalDep, session: DbSession) -> PlatformOnboardingOut:
    return await get_onboarding(session, principal)


@router.get("/readiness", response_model=PlatformReadinessOut)
async def platform_readiness(principal: PrincipalDep, session: DbSession) -> PlatformReadinessOut:
    return await get_readiness(session, principal)


@router.get("/search", response_model=list[PlatformSearchResultOut])
async def platform_search(
    principal: PrincipalDep,
    session: DbSession,
    q: str = Query(min_length=2, max_length=200),
    limit_per_kind: int = Query(default=5, ge=1, le=10),
) -> list[PlatformSearchResultOut]:
    """Search records without widening the caller's existing permissions."""
    return await global_search(session, principal, query=q, limit_per_kind=limit_per_kind)


@router.post(
    "/demo-workspace", response_model=DemoWorkspaceOut, status_code=status.HTTP_201_CREATED
)
async def provision_demo_workspace(
    principal: PrincipalDep, session: DbSession, storage: StorageDep
) -> DemoWorkspaceOut:
    """Create a labeled synthetic company without network or provider side effects."""
    result = await create_demo_workspace(session, principal, storage=storage)
    await session.commit()
    return result


@router.get("/api-keys", response_model=list[PlatformApiKeyOut])
async def list_platform_api_keys(
    principal: PrincipalDep, session: DbSession
) -> list[PlatformApiKey]:
    """Return non-secret metadata for the caller's organization only."""
    principal.require(Permission.ORG_MANAGE)
    return list(
        (
            await session.scalars(
                tenant_select(PlatformApiKey, principal.organization_id)
                .order_by(PlatformApiKey.created_at.desc())
                .limit(200)
            )
        ).all()
    )


@router.post(
    "/api-keys", response_model=PlatformApiKeyIssuedOut, status_code=status.HTTP_201_CREATED
)
async def issue_platform_api_key(
    payload: PlatformApiKeyCreateIn, principal: PrincipalDep, session: DbSession
) -> PlatformApiKeyIssuedOut:
    issued = await create_platform_api_key(session, principal, payload)
    await record(
        session,
        action=AuditAction.PLATFORM_API_KEY_CREATE,
        principal=principal,
        resource_type="platform_api_key",
        resource_id=issued.key.id,
        detail={"key_prefix": issued.key.key_prefix, "scopes": issued.key.scopes},
    )
    await session.commit()
    return PlatformApiKeyIssuedOut(
        id=issued.key.id,
        name=issued.key.name,
        key_prefix=issued.key.key_prefix,
        scopes=issued.key.scopes,
        expires_at=issued.key.expires_at,
        secret=issued.secret,
    )


@router.post("/api-keys/{key_id}/revoke", response_model=PlatformApiKeyOut)
async def revoke_platform_key(
    key_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> PlatformApiKeyOut:
    key = await revoke_platform_api_key(session, principal, key_id)
    await record(
        session,
        action=AuditAction.PLATFORM_API_KEY_REVOKE,
        principal=principal,
        resource_type="platform_api_key",
        resource_id=key.id,
        detail={"key_prefix": key.key_prefix},
    )
    await session.commit()
    return PlatformApiKeyOut.model_validate(key)


__all__ = ["router"]
