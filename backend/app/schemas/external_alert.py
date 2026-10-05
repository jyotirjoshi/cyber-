"""Safe browser projection of externally ingested security alerts."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TriageStatus = Literal["new", "investigating", "risk_accepted", "false_positive", "closed"]


class ExternalAlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    provider: str
    category: str
    title: str
    severity: str
    status: str
    resource: str | None
    cve_ids: list[str]
    first_seen_at: dt.datetime | None
    last_seen_at: dt.datetime | None
    missing_sync_count: int = 0
    triage_status: TriageStatus


class ExternalAlertDetailOut(ExternalAlertOut):
    external_id: str
    source_url: str | None
    triage_note: str | None
    triage_version: int
    triaged_at: dt.datetime | None

    @field_validator("source_url", mode="before")
    @classmethod
    def safe_source_url(cls, value: object) -> str | None:
        if not isinstance(value, str) or not value or value != value.strip():
            return None
        if any(ord(char) < 32 for char in value) or "\\" in value:
            return None
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return None
            if parsed.username or parsed.password:
                return None
            _ = parsed.port  # Reject malformed ports before exposing an href.
        except ValueError:
            return None
        return value


class ExternalAlertTriageIn(BaseModel):
    status: TriageStatus
    note: str | None = Field(default=None, max_length=2000)
    expected_version: int = Field(ge=0)

    @model_validator(mode="after")
    def require_terminal_rationale(self) -> ExternalAlertTriageIn:
        self.note = self.note.strip() if self.note else None
        if self.status in {"risk_accepted", "false_positive", "closed"} and not self.note:
            raise ValueError("A rationale is required for this triage decision.")
        return self


class ExternalAlertSourceActionIn(BaseModel):
    """Explicit provider-side decision, separate from Cynux's local triage."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["dismiss", "reopen"]
    reason: str | None = Field(default=None, max_length=100)
    comment: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_decision(self) -> ExternalAlertSourceActionIn:
        self.comment = self.comment.strip() if self.comment else None
        if self.decision == "dismiss" and (not self.reason or not self.comment):
            raise ValueError("A provider reason and rationale are required.")
        if self.decision == "reopen" and (self.reason is not None or self.comment is not None):
            raise ValueError("Reopening does not take a dismissal reason or comment.")
        return self


class RelatedFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    severity: str
    status: str
    cve_ids: list[str]
    priority: str | None
    risk_score: float | None


__all__ = [
    "ExternalAlertDetailOut",
    "ExternalAlertOut",
    "ExternalAlertTriageIn",
    "ExternalAlertSourceActionIn",
    "RelatedFindingOut",
    "TriageStatus",
]
