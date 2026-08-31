"""Integration configuration wire types (FR-020, SEC-001, SEC-002).

No type in this module can carry a credential outward.  :class:`IntegrationOut` exposes
only a ``fingerprint`` (a short non-reversible digest, enough to answer "is this the same
key I put in?") and a ``hint`` (last few characters, enough to tell two keys apart in a
list).  The ciphertext never leaves the database and the plaintext exists only inside
``app.core.crypto`` and the outbound HTTP client.

Credentials are therefore write-only across this boundary: :class:`IntegrationUpsertIn`
accepts them, nothing returns them, and omitting a key from ``credentials`` on update
leaves the stored value alone rather than clearing it -- a PATCH that silently
de-provisioned an integration would be a very quiet outage.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import IntegrationKind, IntegrationStatus


class CredentialOut(BaseModel):
    """Metadata about a stored secret. Never the secret."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    #: Truncated digest of the plaintext. Lets an operator confirm a rotation took
    #: effect without ever seeing the value.
    fingerprint: str | None = None
    #: Last few characters only, e.g. "…a91f".
    hint: str | None = None
    key_version: int
    expires_at: dt.datetime | None = None
    last_used_at: dt.datetime | None = None
    rotated_at: dt.datetime | None = None
    created_at: dt.datetime


class IntegrationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: IntegrationKind
    name: str
    status: IntegrationStatus
    is_enabled: bool
    base_url: str | None = None
    #: Non-secret settings only: project keys, default issue types, channel names.
    #: The service strips anything that looks like a secret before it lands here.
    config: dict[str, Any] = Field(default_factory=dict)
    credentials: list[CredentialOut] = Field(default_factory=list)
    last_verified_at: dt.datetime | None = None
    #: User-safe text. Provider response bodies are logged, never echoed (SEC-002).
    last_error: str | None = None
    last_error_at: dt.datetime | None = None
    failure_count: int = 0
    created_at: dt.datetime


class IntegrationUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: IntegrationKind
    name: str | None = Field(default=None, max_length=120)
    base_url: str | None = Field(default=None, max_length=1000)
    is_enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    #: Write-only. ``{"api_key": "..."} `` -- encrypted on receipt, never returned.
    #: Keys absent here keep their current stored value; see the module docstring.
    credentials: dict[str, str] = Field(default_factory=dict)


class IntegrationTestOut(BaseModel):
    """Result of a live connectivity probe."""

    model_config = ConfigDict(from_attributes=True)

    kind: IntegrationKind
    healthy: bool
    #: User-safe summary, e.g. "authenticated as cynux-bot" or "401 from provider".
    detail: str | None = None
    latency_ms: int | None = None
    #: Provider-reported version where available -- useful when a DefectDojo upgrade
    #: changes the import API.
    version: str | None = None
    checked_at: dt.datetime | None = None


class IntegrationHealthOut(BaseModel):
    """Dashboard row (FR-031)."""

    model_config = ConfigDict(from_attributes=True)

    kind: IntegrationKind
    name: str
    status: IntegrationStatus
    is_enabled: bool
    last_verified_at: dt.datetime | None = None
    failure_count: int = 0
    #: True while the circuit breaker is open, i.e. calls are being short-circuited
    #: rather than attempted (FR-020).
    circuit_open: bool = False


__all__ = [
    "CredentialOut",
    "IntegrationHealthOut",
    "IntegrationOut",
    "IntegrationTestOut",
    "IntegrationUpsertIn",
]
