"""Tenant-scoped inventory change feed."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AssetChangeOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    asset_id: uuid.UUID
    assessment_id: uuid.UUID | None
    asset_name: str
    change_type: Literal["discovered", "changed", "unreachable"]
    changes: dict[str, Any]
    created_at: dt.datetime


class AssetChangePageOut(BaseModel):
    items: list[AssetChangeOut]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
