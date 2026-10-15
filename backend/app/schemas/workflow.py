"""Typed, non-executable automation workflow contracts."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

WorkflowNodeType = Literal[
    "trigger", "condition", "enrichment", "action", "branch", "delay", "approval"
]


class WorkflowNodeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    type: WorkflowNodeType
    config: dict[str, Any] = Field(default_factory=dict)


class WorkflowEdgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    source: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    target: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    branch: Literal["true", "false", "always"] | None = None


class WorkflowDefinitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1_000)
    nodes: list[WorkflowNodeIn] = Field(min_length=1, max_length=100)
    edges: list[WorkflowEdgeIn] = Field(default_factory=list, max_length=300)
    is_enabled: bool = True
    dry_run: bool = False

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("workflow name cannot be blank")
        return cleaned


class WorkflowDefinitionOut(WorkflowDefinitionIn):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    version: int
    created_by_id: uuid.UUID | None
    created_at: dt.datetime
    updated_at: dt.datetime
    next_run_at: dt.datetime | None


class WorkflowStartIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_key: str = Field(min_length=1, max_length=240)
    context: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool | None = None


class WorkflowStepOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    node_id: str
    node_type: str
    status: str
    attempt: int
    max_attempts: int
    output: dict[str, Any]
    error_code: str | None
    available_at: dt.datetime | None
    started_at: dt.datetime | None
    completed_at: dt.datetime | None


class WorkflowRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workflow_id: uuid.UUID
    organization_id: uuid.UUID
    definition_version: int
    event_key: str
    trigger: str
    context: dict[str, Any]
    status: str
    dry_run: bool
    attempts: int
    next_resume_at: dt.datetime | None
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    error_code: str | None
    created_at: dt.datetime
    updated_at: dt.datetime


class WorkflowRunDetailOut(WorkflowRunOut):
    steps: list[WorkflowStepOut] = Field(default_factory=list)


__all__ = [
    "WorkflowDefinitionIn",
    "WorkflowDefinitionOut",
    "WorkflowEdgeIn",
    "WorkflowNodeIn",
    "WorkflowNodeType",
    "WorkflowRunDetailOut",
    "WorkflowRunOut",
    "WorkflowStartIn",
    "WorkflowStepOut",
]
