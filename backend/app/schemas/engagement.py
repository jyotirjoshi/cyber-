"""Validated PTaaS engagement API contracts."""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class EngagementCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20_000)
    assessment_id: uuid.UUID | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    starts_at: dt.datetime | None = None
    ends_at: dt.datetime | None = None
    client_visible: bool = True

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("title cannot be blank")
        return value.strip()

    @field_validator("scope")
    @classmethod
    def bounded_scope(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 50:
            raise ValueError("scope contains too many fields")
        if len(str(value)) > 50_000:
            raise ValueError("scope is too large")
        return value

    @model_validator(mode="after")
    def valid_dates(self) -> EngagementCreateIn:
        if self.starts_at and self.ends_at and self.ends_at < self.starts_at:
            raise ValueError("ends_at must not precede starts_at")
        return self


class EngagementStatusUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["draft", "scoping", "active", "retesting", "completed", "cancelled"]
    expected_version: int = Field(gt=0)


class EngagementParticipantCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: uuid.UUID | None = None
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=200)
    role: Literal["lead_tester", "tester", "client_manager", "client_observer"]


class EngagementMilestoneCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=10_000)
    due_at: dt.datetime | None = None
    sort_order: int = Field(default=0, ge=0, le=10_000)


class EngagementTimeEntryCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    minutes: int = Field(gt=0, le=1440)
    work_date: dt.date
    note: str | None = Field(default=None, max_length=1000)
    billable: bool = True


class EngagementDocumentCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=300)
    kind: Literal["scope", "authorization", "evidence", "report", "deliverable", "other"]
    storage_key: str = Field(min_length=1, max_length=1000)
    content_type: str = Field(min_length=1, max_length=160)
    size_bytes: int = Field(ge=0, le=5_000_000_000)
    sha256: str
    client_visible: bool = False

    @field_validator("sha256")
    @classmethod
    def valid_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("sha256 must be a hexadecimal SHA-256 digest")
        return normalized


class EngagementRetestRoundCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: uuid.UUID | None = None
    note: str | None = Field(default=None, max_length=10_000)


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    assessment_id: uuid.UUID | None
    title: str
    description: str | None
    status: str
    scope: dict[str, Any]
    starts_at: dt.datetime | None
    ends_at: dt.datetime | None
    client_visible: bool
    created_by_id: uuid.UUID | None
    version: int
    created_at: dt.datetime
    updated_at: dt.datetime


class EngagementParticipantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    engagement_id: uuid.UUID
    user_id: uuid.UUID | None
    email: str
    display_name: str | None
    role: str
    status: str
    created_at: dt.datetime


class EngagementMilestoneOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    engagement_id: uuid.UUID
    title: str
    description: str | None
    status: str
    due_at: dt.datetime | None
    completed_at: dt.datetime | None
    sort_order: int
    created_at: dt.datetime


class EngagementTimeEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    engagement_id: uuid.UUID
    user_id: uuid.UUID | None
    minutes: int
    work_date: dt.date
    note: str | None
    billable: bool
    created_at: dt.datetime


class EngagementDocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    engagement_id: uuid.UUID
    uploaded_by_id: uuid.UUID | None
    title: str
    kind: str
    content_type: str
    size_bytes: int
    sha256: str
    client_visible: bool
    created_at: dt.datetime


class EngagementRetestRoundOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    engagement_id: uuid.UUID
    assessment_id: uuid.UUID | None
    ordinal: int
    status: str
    requested_by_id: uuid.UUID | None
    note: str | None
    requested_at: dt.datetime
    completed_at: dt.datetime | None
    created_at: dt.datetime


__all__ = [name for name in globals() if name.startswith("Engagement")]
