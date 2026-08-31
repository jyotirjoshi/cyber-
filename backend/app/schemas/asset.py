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

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import AssetStatus, Criticality, CriticalitySource


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


class AssetFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    criticality: Criticality | None = None
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
    "AssetCriticalityIn",
    "AssetFilter",
    "AssetOut",
    "AssetTagIn",
    "AssetTagOut",
    "DiscoveredAssetOut",
]
