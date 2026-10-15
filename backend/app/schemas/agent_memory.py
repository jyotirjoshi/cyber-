"""Bounded, curated tenant memory schemas for the AI worker."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentMemoryUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    category: Literal["operational", "architecture", "remediation", "scope", "preference"] = "operational"
    content: str = Field(min_length=3, max_length=2000)
    expires_at: dt.datetime | None = None

    @field_validator("content")
    @classmethod
    def clean_content(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("memory content cannot be blank")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: dt.datetime | None) -> dt.datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("expires_at must include a timezone")
        if value is not None and value <= dt.datetime.now(dt.UTC):
            raise ValueError("expires_at must be in the future")
        return value


class AgentMemoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key: str
    category: str
    content: str
    source: str
    created_by_id: uuid.UUID | None = None
    expires_at: dt.datetime | None = None
    is_active: bool
    created_at: dt.datetime
    updated_at: dt.datetime


__all__ = ["AgentMemoryOut", "AgentMemoryUpsertIn"]
