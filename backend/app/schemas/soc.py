"""Strict contracts for SOC cases and tenant-owned detection engineering."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
CaseStatus = Literal["open", "investigating", "contained", "resolved", "dismissed"]


class DetectionCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["event", "metrics", "evidence"]
    path: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.-]+$")
    operator: Literal["eq", "ne", "in", "contains", "gte", "lte", "exists"]
    value: Any = None


class DetectionRuleCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_key: str = Field(min_length=1, max_length=160, pattern=r"^[a-z0-9][a-z0-9_.:-]*$")
    name: str = Field(min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=4000)
    severity: Severity
    minimum_event_severity: Severity = "info"
    categories: list[str] = Field(default_factory=list, max_length=12)
    event_types: list[str] = Field(default_factory=list, max_length=50)
    conditions: list[DetectionCondition] = Field(default_factory=list, max_length=20)
    group_by: list[str] = Field(default_factory=list, max_length=5)
    status: Literal["draft", "active", "disabled"] = "draft"
    auto_create_case: bool = True


class DetectionRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_key: str
    name: str
    description: str | None
    status: str
    severity: str
    minimum_event_severity: str
    categories: list[str]
    event_types: list[str]
    conditions: list[dict[str, Any]]
    group_by: list[str]
    auto_create_case: bool
    version: int
    last_matched_at: dt.datetime | None
    created_at: dt.datetime
    updated_at: dt.datetime


class DetectionDryRunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    limit: int = Field(default=100, ge=1, le=500)


class DetectionEvaluationOut(BaseModel):
    event_id: uuid.UUID
    matched: bool
    matched_conditions: int
    total_conditions: int
    reason_codes: list[str]


class DetectionDryRunOut(BaseModel):
    rule_id: uuid.UUID
    evaluated: int
    matched: int
    evaluations: list[DetectionEvaluationOut]


class SocCaseCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_key: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=8000)
    severity: Severity
    priority: int = Field(default=50, ge=0, le=100)
    owner_team: str | None = Field(default=None, max_length=120)
    assigned_user_id: uuid.UUID | None = None
    event_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    asset_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    finding_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list, max_length=200)


class SocCaseTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: CaseStatus
    note: str = Field(min_length=1, max_length=4000)
    resolution: str | None = Field(default=None, max_length=8000)


class SocCaseTaskCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    assigned_user_id: uuid.UUID | None = None
    due_at: dt.datetime | None = None
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


class SocCaseTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    title: str
    description: str | None
    status: str
    assigned_user_id: uuid.UUID | None
    due_at: dt.datetime | None
    completed_at: dt.datetime | None
    evidence_refs: list[dict[str, Any]]
    created_at: dt.datetime


class SocCaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_key: str
    title: str
    summary: str
    severity: str
    status: str
    priority: int
    threat_story_id: uuid.UUID | None
    assigned_user_id: uuid.UUID | None
    owner_team: str | None
    event_ids: list[str]
    asset_ids: list[str]
    finding_ids: list[str]
    evidence_refs: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    resolution: str | None
    opened_at: dt.datetime
    contained_at: dt.datetime | None
    resolved_at: dt.datetime | None
    created_at: dt.datetime
    updated_at: dt.datetime

