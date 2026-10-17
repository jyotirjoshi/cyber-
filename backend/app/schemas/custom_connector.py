from __future__ import annotations
import datetime as dt
import uuid
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class CustomConnectorIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    base_url: str = Field(min_length=9, max_length=1024)
    routes: list[dict[str, Any]] = Field(min_length=1, max_length=20)
    pagination: dict[str, Any] = Field(default_factory=dict)
    field_mapping: dict[str, str] = Field(min_length=1, max_length=100)
    output_type: Literal["external_alert", "canonical_finding"]
    credential_integration_id: uuid.UUID | None = None
    rate_limit_per_minute: int = Field(default=60, ge=1, le=600)


class CustomConnectorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    base_url: str
    routes: list[dict[str, Any]]
    pagination: dict[str, Any]
    field_mapping: dict[str, Any]
    output_type: str
    credential_integration_id: uuid.UUID | None
    rate_limit_per_minute: int
    is_enabled: bool
    created_at: dt.datetime


class CustomConnectorRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    connector_id: uuid.UUID
    status: str
    checkpoint: dict[str, Any]
    result: dict[str, Any]
    records_read: int
    records_written: int
    error_code: str | None
    started_at: dt.datetime
    completed_at: dt.datetime | None


class CustomConnectorRunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=1, max_length=160)


__all__ = [
    "CustomConnectorIn",
    "CustomConnectorOut",
    "CustomConnectorRunIn",
    "CustomConnectorRunOut",
]
