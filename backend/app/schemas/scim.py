"""SCIM provisioning credential wire contracts.

SCIM bearer tokens are shown only on creation.  Responses after that point expose
metadata suitable for an administrator audit screen, never credential material.
"""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict, Field


class ScimProvisioningTokenCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    expires_at: dt.datetime | None = None


class ScimProvisioningTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None
    last_used_at: dt.datetime | None
    created_at: dt.datetime


class ScimProvisioningTokenIssuedOut(ScimProvisioningTokenOut):
    secret: str


__all__ = [
    "ScimProvisioningTokenCreateIn",
    "ScimProvisioningTokenIssuedOut",
    "ScimProvisioningTokenOut",
]
