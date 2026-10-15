"""Read models for the platform vulnerability intelligence catalog."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class VulnerabilityIntelligenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    snapshot: dict[str, Any]
    refreshed_at: dt.datetime
    expires_at: dt.datetime


class ThreatWatchlistCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    entity_key: str = Field(min_length=1, max_length=512)
    label: str | None = Field(default=None, max_length=255)

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if normalized not in {"cve", "product", "actor", "domain", "brand"}:
            raise ValueError("unsupported watchlist entity type")
        return normalized


class ThreatWatchlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entity_type: str
    entity_key: str
    label: str | None
    is_active: bool
    last_matched_at: dt.datetime | None
    created_at: dt.datetime


class ThreatWatchlistMatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    watchlist_id: uuid.UUID
    observation_id: uuid.UUID
    canonical_finding_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    match_key: str
    matched_at: dt.datetime


__all__ = [
    "ThreatWatchlistCreateIn",
    "ThreatWatchlistMatchOut",
    "ThreatWatchlistOut",
    "VulnerabilityIntelligenceOut",
]
