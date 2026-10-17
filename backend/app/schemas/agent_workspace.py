"""Validated public contracts for durable agent workspaces."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentWorkspaceCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    max_bytes: int = Field(default=1_073_741_824, ge=1_048_576, le=10_737_418_240)
    ttl_hours: int = Field(default=24, ge=1, le=168)


class AgentWorkspaceStatusUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["active", "suspended", "closed"]
    expected_version: int = Field(ge=1)


class WorkspaceCredentialReferenceCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    integration_id: uuid.UUID
    label: str = Field(min_length=1, max_length=160)
    allowed_tools: list[str] = Field(min_length=1, max_length=25)
    expires_at: dt.datetime | None = None

    @field_validator("allowed_tools")
    @classmethod
    def clean_tools(cls, value: list[str]) -> list[str]:
        tools = list(dict.fromkeys(item.strip() for item in value if item.strip()))
        if not tools or any(len(item) > 120 for item in tools):
            raise ValueError("allowed_tools contains an invalid tool name")
        return tools


class WorkspaceRecordPutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_.-]+$")
    key: str = Field(min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9_.:/-]+$")
    value: dict[str, Any]
    expected_version: int | None = Field(default=None, ge=1)
    updated_by_task_id: uuid.UUID | None = None

    @field_validator("value")
    @classmethod
    def bounded_value(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(str(value)) > 65_536:
            raise ValueError("workspace record exceeds 64 KiB")
        return value


class WorkspaceExecutionCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: uuid.UUID
    approval_id: uuid.UUID
    execution_kind: Literal["shell", "browser", "scanner"]
    executable: str = Field(
        min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9_./:-]+$"
    )
    arguments: list[str] = Field(default_factory=list, max_length=100)
    environment_names: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("arguments")
    @classmethod
    def bound_arguments(cls, value: list[str]) -> list[str]:
        if any(len(item) > 2_000 for item in value):
            raise ValueError("execution arguments may not exceed 2,000 characters")
        return value

    @field_validator("environment_names")
    @classmethod
    def environment_variable_names_only(cls, value: list[str]) -> list[str]:
        names = sorted(set(value))
        if any(
            not name
            or len(name) > 128
            or not name.replace("_", "a").isalnum()
            or name[0].isdigit()
            for name in names
        ):
            raise ValueError("environment_names must contain variable names, never assignments")
        return names


class AgentWorkspaceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    run_id: uuid.UUID
    status: str
    name: str
    max_bytes: int
    used_bytes: int
    manifest: dict[str, Any]
    expires_at: dt.datetime
    closed_at: dt.datetime | None
    version: int
    created_at: dt.datetime
    updated_at: dt.datetime


class WorkspaceArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    workspace_id: uuid.UUID
    task_id: uuid.UUID | None
    kind: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    summary: dict[str, Any]
    is_evidence: bool
    created_at: dt.datetime


class WorkspaceCredentialReferenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    workspace_id: uuid.UUID
    integration_id: uuid.UUID
    label: str
    allowed_tools: list[str]
    status: str
    expires_at: dt.datetime | None
    created_at: dt.datetime


class WorkspaceRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    workspace_id: uuid.UUID
    namespace: str
    key: str
    value: dict[str, Any]
    version: int
    updated_by_task_id: uuid.UUID | None
    created_at: dt.datetime
    updated_at: dt.datetime


class WorkspaceExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    workspace_id: uuid.UUID
    task_id: uuid.UUID
    approval_id: uuid.UUID
    execution_kind: str
    status: str
    executable: str
    argument_names: list[str]
    environment_names: list[str]
    command_digest: str
    result_summary: dict[str, Any]
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    created_at: dt.datetime


__all__ = [name for name in globals() if name.startswith(("AgentWorkspace", "Workspace"))]
