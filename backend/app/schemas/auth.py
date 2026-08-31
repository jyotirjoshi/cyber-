"""Authentication wire types (FR-001).

Password *length* bounds are enforced here so an obviously-bad password is a 422 before
any hashing work happens.  The full policy -- which is configurable via
``CYNUX_SECURITY__MIN_PASSWORD_LENGTH`` and includes a common-password check -- lives in
:func:`app.core.security.validate_password_strength` and is applied by the auth service.
Duplicating a configurable rule as a schema constant would let the two drift, so the
constant here is only the floor the schema can guarantee without reading settings.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.db.enums import Role
from app.schemas.organization import MembershipOut

#: Absolute floor. The configured minimum may be higher, never lower.
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 1024


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    full_name: str | None = Field(default=None, max_length=200)
    #: Registering creates the user's first organization and makes them its owner.
    organization_name: str = Field(min_length=2, max_length=200)


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class TokenPairOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    #: Access-token lifetime in seconds, so a client can schedule a refresh instead of
    #: waiting for a 401.
    expires_in: int


class RefreshIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=4096)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str | None = None
    is_active: bool
    is_email_verified: bool
    created_at: dt.datetime
    last_login_at: dt.datetime | None = None


class MeOut(BaseModel):
    """The bootstrap payload for a signed-in session.

    ``permissions`` is the resolved permission set for ``active_organization_id`` --
    already flattened from the role -- so the UI never re-implements the role table and
    cannot drift from the server's answer.  It is a convenience for rendering, not a
    security boundary: every route re-checks server-side.
    """

    model_config = ConfigDict(from_attributes=True)

    user: UserOut
    organizations: list[MembershipOut] = Field(default_factory=list)
    active_organization_id: uuid.UUID | None = None
    active_role: Role | None = None
    permissions: list[str] = Field(default_factory=list)


class PasswordResetRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class PasswordResetConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class ChangePasswordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class LogoutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Optional: revoke the refresh token too, not just the access token.
    refresh_token: str | None = Field(default=None, max_length=4096)


class SwitchOrganizationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: uuid.UUID


__all__ = [
    "PASSWORD_MAX_LENGTH",
    "PASSWORD_MIN_LENGTH",
    "ChangePasswordIn",
    "LoginIn",
    "LogoutIn",
    "MeOut",
    "PasswordResetConfirmIn",
    "PasswordResetRequestIn",
    "RefreshIn",
    "RegisterIn",
    "SwitchOrganizationIn",
    "TokenPairOut",
    "UserOut",
]
