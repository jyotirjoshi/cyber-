"""Issuance and lifecycle operations for public platform API credentials."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import select

from app.core.errors import AuthenticationError, ResourceNotFoundError
from app.core.security import generate_api_key, verify_password
from app.db.enums import Permission
from app.db.models.platform import PlatformApiKey
from app.schemas.platform import PlatformApiKeyCreateIn
from app.services.context import Principal


@dataclass(frozen=True, slots=True)
class IssuedPlatformApiKey:
    key: PlatformApiKey
    secret: str


async def create_platform_api_key(
    session, principal: Principal, payload: PlatformApiKeyCreateIn
) -> IssuedPlatformApiKey:
    """Create a tenant-local machine credential and expose its secret exactly once."""
    principal.require(Permission.ORG_MANAGE)
    plaintext, secret_hash = generate_api_key()
    key = PlatformApiKey(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        key_prefix=plaintext[:16],
        secret_hash=secret_hash,
        scopes=payload.scopes,
        expires_at=payload.expires_at,
    )
    session.add(key)
    await session.flush()
    return IssuedPlatformApiKey(key=key, secret=plaintext)


async def revoke_platform_api_key(session, principal: Principal, key_id: uuid.UUID) -> PlatformApiKey:
    """Revoke one tenant-owned machine credential without deleting its audit history."""
    from app.db.repository import tenant_select

    principal.require(Permission.ORG_MANAGE)
    key = (
        await session.execute(
            tenant_select(PlatformApiKey, principal.organization_id)
            .where(PlatformApiKey.id == key_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if key is None:
        raise ResourceNotFoundError("Platform API key not found")
    if key.revoked_at is None:
        key.revoked_at = dt.datetime.now(dt.UTC)
    return key


async def authenticate_platform_api_key(session, secret: str) -> PlatformApiKey:
    """Resolve a machine credential without treating an invalid key as a tenant oracle."""
    if not secret.startswith("cynux_") or len(secret) < 17:
        raise AuthenticationError("invalid platform API key")
    key = (
        await session.execute(
            select(PlatformApiKey).where(PlatformApiKey.key_prefix == secret[:16])
        )
    ).scalar_one_or_none()
    now = dt.datetime.now(dt.UTC)
    if (
        key is None
        or key.revoked_at is not None
        or (key.expires_at is not None and key.expires_at <= now)
        or not verify_password(secret, key.secret_hash)
    ):
        raise AuthenticationError("invalid platform API key")
    key.last_used_at = now
    return key


__all__ = [
    "IssuedPlatformApiKey",
    "authenticate_platform_api_key",
    "create_platform_api_key",
    "revoke_platform_api_key",
]
