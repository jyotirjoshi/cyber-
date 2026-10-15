"""Pydantic schemas for Attack Surface Management surfaces."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class AsmSurfaceCreateIn(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=160)]
    seeds: Annotated[list[str], Field(min_length=1, max_length=50)]
    cron_expression: Annotated[str, Field(min_length=9, max_length=120)]
    timezone: Annotated[str, Field(default="UTC", max_length=100)]
    authorization_text: Annotated[str, Field(min_length=10, max_length=2000)]
    authorization_confirmed: bool
    authorization_expires_at: dt.datetime

    @field_validator("seeds")
    @classmethod
    def validate_seeds(cls, v: list[str]) -> list[str]:
        cleaned = []
        for seed in v:
            seed = seed.strip()
            if not seed or len(seed) > 512:
                raise ValueError("each seed must be 1-512 characters")
            if any(ord(c) < 32 for c in seed):
                raise ValueError("seeds must not contain control characters")
            cleaned.append(seed)
        return cleaned


class AsmSurfaceUpdateIn(BaseModel):
    name: Annotated[str | None, Field(min_length=1, max_length=160)] = None
    seeds: Annotated[list[str] | None, Field(max_length=50)] = None
    cron_expression: Annotated[str | None, Field(min_length=9, max_length=120)] = None
    enabled: bool | None = None
    authorization_text: Annotated[str | None, Field(min_length=10, max_length=2000)] = None
    authorization_expires_at: dt.datetime | None = None


class AsmSurfaceOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    seeds: list[str]
    cron_expression: str
    timezone: str
    authorization_expires_at: dt.datetime
    enabled: bool
    next_run_at: dt.datetime
    last_run_at: dt.datetime | None = None
    last_asset_count: int
    last_new_count: int
    last_error_code: str | None = None
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = {"from_attributes": True}


__all__ = ["AsmSurfaceCreateIn", "AsmSurfaceOut", "AsmSurfaceUpdateIn"]
