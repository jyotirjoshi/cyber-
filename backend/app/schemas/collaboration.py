"""Schemas for the canonical-finding PTaaS collaboration feed."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FindingCollaborationCommentCreateIn(BaseModel):
    """A bounded, non-secret collaboration entry for one canonical finding."""

    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=4000)
    kind: Literal["note", "evidence", "remediation", "retest", "status_update"] = "note"
    evidence_reference: str | None = Field(default=None, max_length=2048)
    visible_to_client: bool = False

    @field_validator("body")
    @classmethod
    def clean_body(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("comment body cannot be blank")
        return value

    @field_validator("evidence_reference")
    @classmethod
    def clean_evidence_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        return value


class FindingCollaborationCommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canonical_finding_id: uuid.UUID
    author_user_id: uuid.UUID | None = None
    kind: str
    body: str
    evidence_reference: str | None = None
    visible_to_client: bool
    created_at: dt.datetime
    updated_at: dt.datetime


__all__ = ["FindingCollaborationCommentCreateIn", "FindingCollaborationCommentOut"]
