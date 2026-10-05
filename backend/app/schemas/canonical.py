"""Public, source-preserving canonical finding projections."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.finding import TicketLinkOut


class CanonicalFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    severity: str
    status: str
    cve_ids: list[str]
    risk_score: float = Field(ge=0, le=100)
    risk_factors: dict[str, Any]
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    closed_at: dt.datetime | None
    status_version: int
    assignee_user_id: uuid.UUID | None = None
    due_at: dt.datetime | None = None
    remediation_plan: str | None = None


class FindingObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    provider: str
    external_id: str
    cve_id: str
    title: str
    severity: str
    source_status: str
    source_url: str | None
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class FindingHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    previous_status: str | None
    new_status: str
    reason: str
    actor_user_id: uuid.UUID | None
    occurred_at: dt.datetime


class CanonicalFindingDetailOut(CanonicalFindingOut):
    observations: list[FindingObservationOut]
    history: list[FindingHistoryOut]
    tickets: list[TicketLinkOut] = Field(default_factory=list)


class CanonicalStatusDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["open", "accepted_risk", "false_positive"]
    reason: str = Field(min_length=1, max_length=2000)
    expected_version: int = Field(ge=0)


class CanonicalWorkIn(BaseModel):
    """Partial, version-checked remediation work update; null explicitly clears a field."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=0)
    assignee_user_id: uuid.UUID | None = None
    due_at: dt.datetime | None = None
    remediation_plan: str | None = Field(default=None, max_length=4000)

    @field_validator("remediation_plan")
    @classmethod
    def clean_plan(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("remediation plan cannot be blank; use null to clear it")
        return value.strip() if value is not None else None

    @field_validator("due_at")
    @classmethod
    def require_timezone(cls, value: dt.datetime | None) -> dt.datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("due_at must include a timezone")
        return value

    @model_validator(mode="after")
    def require_change(self) -> CanonicalWorkIn:
        if not (self.model_fields_set - {"expected_version"}):
            raise ValueError("provide at least one remediation work field")
        return self
