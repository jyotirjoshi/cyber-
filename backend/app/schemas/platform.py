"""Public platform API credential contracts."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.enums import Permission


class PlatformApiKeyCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    scopes: list[str] = Field(min_length=1, max_length=32)
    expires_at: dt.datetime | None = None

    @field_validator("scopes")
    @classmethod
    def require_known_unique_scopes(cls, scopes: list[str]) -> list[str]:
        known = {permission.value for permission in Permission}
        if len(set(scopes)) != len(scopes) or any(scope not in known for scope in scopes):
            raise ValueError("scopes must be unique known platform permissions")
        return scopes


class PlatformApiKeyIssuedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: dt.datetime | None
    secret: str


class PlatformApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None
    last_used_at: dt.datetime | None
    created_at: dt.datetime


__all__ = ["PlatformApiKeyCreateIn", "PlatformApiKeyIssuedOut", "PlatformApiKeyOut"]
