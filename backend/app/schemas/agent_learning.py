"""Bounded proposals and explicit review decisions for organizational learning."""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.agent_memory import AgentMemoryUpsertIn


class MemoryEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["run", "knowledge_chunk"]
    id: uuid.UUID


class MemoryCandidateCreateIn(AgentMemoryUpsertIn):
    confidence: float = Field(ge=0, le=1)
    evidence: list[MemoryEvidence] = Field(min_length=1, max_length=10)
    agent_version_id: uuid.UUID | None = None


class MemoryCandidateApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str | None = Field(default=None, min_length=3, max_length=2000)
    expires_at: dt.datetime | None = None
    rationale: str | None = Field(default=None, max_length=2000)

    @field_validator("content")
    @classmethod
    def clean_content(cls, value: str | None) -> str | None:
        return AgentMemoryUpsertIn.clean_content(value) if value is not None else None

    @field_validator("expires_at")
    @classmethod
    def valid_expiry(cls, value: dt.datetime | None) -> dt.datetime | None:
        return AgentMemoryUpsertIn.validate_expiry(value)


class MemoryCandidateRejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    rationale: str = Field(min_length=3, max_length=2000)


class MemoryCandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    key: str
    category: str
    content: str
    confidence: float
    evidence: list[MemoryEvidence]
    agent_version_id: uuid.UUID | None
    expires_at: dt.datetime | None
    status: str
    reviewed_by_id: uuid.UUID | None
    decision_rationale: str | None
    approved_memory_id: uuid.UUID | None
    created_at: dt.datetime
