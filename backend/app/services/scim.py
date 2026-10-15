"""Lifecycle operations for tenant-scoped SCIM provisioning credentials."""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from dataclasses import dataclass

from sqlalchemy import select

from app.core.errors import AuthenticationError, ResourceNotFoundError
from app.core.security import hash_password, verify_password
from app.db.base import utcnow
from app.db.enums import Permission, Role
from app.db.models.identity import Membership, ScimProvisioningToken, User
from app.db.repository import tenant_select
from app.schemas.scim import ScimProvisioningTokenCreateIn
from app.services.context import Principal


@dataclass(frozen=True, slots=True)
class IssuedScimProvisioningToken:
    token: ScimProvisioningToken
    secret: str


def _generate_provisioning_secret() -> str:
    return f"cynux_scim_{secrets.token_urlsafe(32)}"


async def issue_provisioning_token(
    session, principal: Principal, payload: ScimProvisioningTokenCreateIn
) -> IssuedScimProvisioningToken:
    """Issue a provisioning-only bearer secret and expose it exactly once."""
    principal.require(Permission.ORG_MANAGE)
    secret = _generate_provisioning_secret()
    token = ScimProvisioningToken(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name.strip(),
        key_prefix=secret[:24],
        secret_hash=hash_password(secret),
        expires_at=payload.expires_at,
    )
    session.add(token)
    await session.flush()
    return IssuedScimProvisioningToken(token=token, secret=secret)


async def revoke_provisioning_token(
    session, principal: Principal, token_id: uuid.UUID
) -> ScimProvisioningToken:
    """Revoke one tenant-owned credential while retaining its audit history."""
    principal.require(Permission.ORG_MANAGE)
    token = (
        await session.execute(
            tenant_select(ScimProvisioningToken, principal.organization_id)
            .where(ScimProvisioningToken.id == token_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if token is None:
        raise ResourceNotFoundError("SCIM provisioning token not found")
    if token.revoked_at is None:
        token.revoked_at = dt.datetime.now(dt.UTC)
    return token


async def authenticate_provisioning_token(session, secret: str) -> ScimProvisioningToken:
    """Resolve an active SCIM bearer token without exposing tenant existence.

    A SCIM endpoint calls this before it accepts any provisioning request.  The
    prefix narrows the indexed lookup, while Argon2 verifies the entire secret.
    Both revoked and expired credentials intentionally produce the same generic
    authentication error as an unknown token.
    """
    if not secret.startswith("cynux_scim_") or len(secret) < 24:
        raise AuthenticationError("invalid SCIM provisioning token")
    token = (
        await session.execute(
            select(ScimProvisioningToken).where(ScimProvisioningToken.key_prefix == secret[:24])
        )
    ).scalar_one_or_none()
    now = dt.datetime.now(dt.UTC)
    if (
        token is None
        or token.revoked_at is not None
        or (token.expires_at is not None and token.expires_at <= now)
        or not verify_password(secret, token.secret_hash)
    ):
        raise AuthenticationError("invalid SCIM provisioning token")
    token.last_used_at = now
    return token


async def provision_user(
    session,
    token: ScimProvisioningToken,
    *,
    email: str,
    full_name: str | None,
    active: bool,
) -> tuple[Membership, User]:
    """Create or reactivate an organization-local SCIM membership.

    Users are global while memberships are tenant-owned.  Therefore a SCIM
    deprovision event must never disable the global ``User`` record: it would lock a
    consultant or customer out of every other organization they belong to.
    """
    normalized_email = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == normalized_email))).scalar_one_or_none()
    if user is None:
        user = User(
            email=normalized_email,
            full_name=full_name,
            password_hash=hash_password(secrets.token_urlsafe(48)),
            # ``User`` is global; a tenant's IdP must never deactivate another
            # organization's account. Membership deletion below is the tenant-local
            # deprovisioning operation.
            is_active=True,
            is_email_verified=True,
        )
        session.add(user)
        await session.flush()
    elif full_name:
        user.full_name = full_name

    membership = (
        await session.execute(
            select(Membership).where(
                Membership.organization_id == token.organization_id,
                Membership.user_id == user.id,
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        membership = Membership(
            organization_id=token.organization_id,
            user_id=user.id,
            role=Role.VIEWER.value,
            accepted_at=utcnow(),
        )
        session.add(membership)
        await session.flush()
    if not active:
        await session.delete(membership)
    return membership, user


__all__ = [
    "IssuedScimProvisioningToken",
    "authenticate_provisioning_token",
    "issue_provisioning_token",
    "provision_user",
    "revoke_provisioning_token",
]
