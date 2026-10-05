"""Asset inventory wire types (FR-009, FR-010).

``evidence`` is carried outward deliberately.  Every attribute an asset claims -- that a
port is open, that a technology is present, that the host is internet-facing -- was
asserted by some tool, and FR-024 forbids presenting an unsourced claim.  The map is
``{attribute: {"source": ..., "observed_at": ..., "detail": ...}}`` so the UI can show
*why* an asset was tagged critical and scanned, not merely that it was.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.db.enums import AssetEnvironment, AssetStatus, Criticality, CriticalitySource


class AssetTagOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key: str
    value: str | None = None
    #: True when a human applied it. Operator tags outrank inferred ones when the agent
    #: decides criticality, so the provenance has to survive to the UI.
    is_operator_applied: bool
    applied_by_id: uuid.UUID | None = None
    created_at: dt.datetime


class AssetTagIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=60)
    value: str | None = Field(default=None, max_length=200)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID | None = None
    name: str
    asset_type: str
    ip_address: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    technology: list[str] = Field(default_factory=list)
    status: AssetStatus
    internet_exposed: bool
    http_title: str | None = None
    http_status_code: int | None = None
    tls_subject: str | None = None

    criticality: Criticality
    criticality_source: CriticalitySource
    criticality_rationale: str | None = None
    owner_user_id: uuid.UUID | None = None
    owner_team: str | None = None
    environment: AssetEnvironment = AssetEnvironment.UNKNOWN
    groups: list[str] = Field(default_factory=list)
    #: 0.0-1.0. Drives the risk-based scope selection of FR-010.
    risk_score: float = Field(ge=0.0, le=1.0)
    selected_for_scanning: bool
    selection_rationale: str | None = None

    #: Per-attribute provenance. See the module docstring.
    evidence: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: dt.datetime | None = None
    last_seen_at: dt.datetime | None = None
    seen_in_assessments: list[str] = Field(default_factory=list)
    tags: list[AssetTagOut] = Field(default_factory=list)
    created_at: dt.datetime

    @property
    def endpoint(self) -> str:
        return f"{self.name}:{self.port}" if self.port else self.name


class AssetCriticalityIn(BaseModel):
    """Operator override of inferred criticality (FR-009).

    ``rationale`` is requested rather than optional-by-convention because the value is
    written into the audit trail and shown next to the agent's own reasoning; an
    unexplained override is indistinguishable from a mistake.
    """

    model_config = ConfigDict(extra="forbid")

    criticality: Criticality
    rationale: str | None = Field(default=None, max_length=2000)


class AssetContextIn(BaseModel):
    """Partial, audited update of curated asset business context."""

    model_config = ConfigDict(extra="forbid")

    owner_user_id: uuid.UUID | None = None
    owner_team: str | None = Field(default=None, max_length=120)
    environment: AssetEnvironment | None = None
    groups: list[str] | None = Field(default=None, max_length=30)

    @field_validator("owner_team")
    @classmethod
    def normalize_team(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("owner_team cannot be blank")
        return value

    @field_validator("groups")
    @classmethod
    def normalize_groups(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        normalized = [value.strip() for value in values]
        if any(not value or len(value) > 60 for value in normalized):
            raise ValueError("groups must have names of 1 to 60 characters")
        if len({value.casefold() for value in normalized}) != len(normalized):
            raise ValueError("groups must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_partial_update(self) -> AssetContextIn:
        if not self.model_fields_set:
            raise ValueError("at least one context field is required")
        if "environment" in self.model_fields_set and self.environment is None:
            raise ValueError("environment cannot be null")
        if "groups" in self.model_fields_set and self.groups is None:
            raise ValueError("groups cannot be null")
        return self


class AssetFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    criticality: Criticality | None = None
    environment: AssetEnvironment | None = None
    selected: bool | None = None
    internet_exposed: bool | None = None
    status: AssetStatus | None = None
    assessment_id: uuid.UUID | None = None
    #: Free-text match against name, IP and service.
    q: str | None = Field(default=None, max_length=200)


class DiscoveredAssetOut(BaseModel):
    """A recon result before it becomes an inventory row.

    Returned by the recon stage so the agent chat can show discovery streaming in while
    deduplication against the existing inventory is still pending.
    """

    model_config = ConfigDict(from_attributes=True)

    name: str
    asset_type: str
    ip_address: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    technology: list[str] = Field(default_factory=list)
    http_title: str | None = None
    http_status_code: int | None = None
    tls_subject: str | None = None
    source: str = Field(description="Which recon output file or tool asserted this.")


__all__ = [
    "AssetContextIn",
    "AssetCriticalityIn",
    "AssetFilter",
    "AssetOut",
    "AssetTagIn",
    "AssetTagOut",
    "DiscoveredAssetOut",
]
