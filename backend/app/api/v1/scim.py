"""A deliberately narrow SCIM 2.0 user-provisioning surface.

The SCIM credential identifies exactly one customer organization.  All user queries
therefore join through that organization rather than trusting an IdP-supplied tenant
identifier.  This keeps provisioning as isolated as the rest of the product.
"""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Query, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSession
from app.core.errors import AuthenticationError, ResourceNotFoundError
from app.db.models.identity import Membership, ScimProvisioningToken, User
from app.services.scim import authenticate_provisioning_token, provision_user

router = APIRouter(prefix="/scim/v2", tags=["scim"])
_USER_NAME_EQ_FILTER = re.compile(r'^\s*userName\s+eq\s+"([^"\\]+)"\s*$', re.IGNORECASE)


class ScimNameIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    formatted: str | None = Field(default=None, max_length=200)


class ScimUserIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    userName: EmailStr
    name: ScimNameIn | None = None
    active: bool = True

    @model_validator(mode="after")
    def require_active_user(self) -> ScimUserIn:
        """Creation is an add operation; use DELETE to deprovision a member."""
        if not self.active:
            raise ValueError("SCIM create accepts active users only; use DELETE to deprovision")
        return self


class ScimPatchOperationIn(BaseModel):
    """The SCIM PatchOp subset Cynux can apply without changing access roles."""

    model_config = ConfigDict(extra="forbid")

    op: Literal["replace"]
    path: Literal["active", "name.formatted"]
    value: bool | str


class ScimPatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemas: list[str] = Field(default_factory=list)
    Operations: list[ScimPatchOperationIn] = Field(min_length=1, max_length=10)


async def scim_token(
    session: DbSession, authorization: Annotated[str | None, Header()] = None
) -> ScimProvisioningToken:
    """Authenticate RFC 7644 bearer credentials without accepting other schemes."""
    scheme, _, secret = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secret:
        raise AuthenticationError("missing SCIM bearer token")
    return await authenticate_provisioning_token(session, secret)


ScimTokenDep = Annotated[ScimProvisioningToken, Depends(scim_token)]


def parse_user_name_filter(filter_expression: str) -> str:
    """Accept the portable exact-email SCIM filter and reject ambiguous predicates."""
    matched = _USER_NAME_EQ_FILTER.fullmatch(filter_expression)
    if matched is None:
        raise ValueError('Only SCIM filter userName eq "email@example.com" is supported')
    return matched.group(1).strip().lower()


def _resource(membership: Membership, user: User) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(membership.id),
        "userName": user.email,
        "name": {"formatted": user.full_name} if user.full_name else {},
        "active": True,
        "meta": {"resourceType": "User"},
    }


@router.get("/Users")
async def list_users(
    token: ScimTokenDep,
    session: DbSession,
    filter_expression: Annotated[str | None, Query(alias="filter", max_length=500)] = None,
    start_index: Annotated[int, Query(alias="startIndex", ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=200)] = 100,
) -> dict[str, Any]:
    """Return the active tenant's members in the SCIM ListResponse envelope."""
    statement = select(Membership).where(Membership.organization_id == token.organization_id)
    total_statement = select(func.count()).select_from(Membership).where(
        Membership.organization_id == token.organization_id
    )
    if filter_expression:
        email = parse_user_name_filter(filter_expression)
        statement = statement.join(User, Membership.user_id == User.id).where(func.lower(User.email) == email)
        total_statement = total_statement.join(User, Membership.user_id == User.id).where(
            func.lower(User.email) == email
        )
    total = int((await session.scalar(total_statement)) or 0)
    memberships = list(
        (
            await session.scalars(
                statement.options(selectinload(Membership.user))
                .order_by(Membership.created_at.asc())
                .offset(start_index - 1)
                .limit(count)
            )
        ).all()
    )
    await session.commit()  # persist the credential's last-used timestamp
    resources = [_resource(membership, membership.user) for membership in memberships]
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: ScimUserIn, token: ScimTokenDep, session: DbSession
) -> dict[str, Any]:
    """JIT-provision a viewer membership for this tenant only."""
    membership, user = await provision_user(
        session,
        token,
        email=str(payload.userName),
        full_name=payload.name.formatted if payload.name else None,
        active=payload.active,
    )
    await session.commit()
    return _resource(membership, user)


@router.get("/Users/{membership_id}")
async def get_user(
    membership_id: uuid.UUID, token: ScimTokenDep, session: DbSession
) -> dict[str, Any]:
    """Resolve exactly one user inside the credential's organization."""
    membership = (
        await session.execute(
            select(Membership)
            .where(
                Membership.id == membership_id,
                Membership.organization_id == token.organization_id,
            )
            .options(selectinload(Membership.user))
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ResourceNotFoundError("SCIM user not found")
    await session.commit()  # persist the SCIM credential's last-used timestamp
    return _resource(membership, membership.user)


@router.patch("/Users/{membership_id}", response_model=None)
async def patch_user(
    membership_id: uuid.UUID, payload: ScimPatchIn, token: ScimTokenDep, session: DbSession
) -> dict[str, Any] | Response:
    """Apply an IdP lifecycle/name update to exactly one tenant membership.

    SCIM may deactivate the membership but is never allowed to alter the global
    account or assign a Cynux role.  Role changes remain an owner-controlled RBAC
    operation, which prevents an IdP attribute mapping from granting privileges.
    """
    membership = (
        await session.execute(
            select(Membership)
            .where(
                Membership.id == membership_id,
                Membership.organization_id == token.organization_id,
            )
            .options(selectinload(Membership.user))
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ResourceNotFoundError("SCIM user not found")

    deactivate = False
    for operation in payload.Operations:
        if operation.path == "active":
            if not isinstance(operation.value, bool):
                raise ValueError("SCIM active patch value must be a boolean")
            deactivate = not operation.value
        elif not isinstance(operation.value, str):
            raise ValueError("SCIM name.formatted patch value must be a string")
        else:
            membership.user.full_name = operation.value.strip()[:200] or None

    if deactivate:
        await session.delete(membership)
        await session.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    await session.commit()
    return _resource(membership, membership.user)


@router.delete("/Users/{membership_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    membership_id: uuid.UUID, token: ScimTokenDep, session: DbSession
) -> Response:
    """Deprovision exactly one tenant membership; the global account is preserved."""
    membership = (
        await session.execute(
            select(Membership).where(
                Membership.id == membership_id,
                Membership.organization_id == token.organization_id,
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ResourceNotFoundError("SCIM user not found")
    await session.delete(membership)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


__all__ = ["router"]
