"""Public contracts for tenant-configurable AI agent definitions."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ProviderName = Literal["anthropic", "openai", "google", "openrouter"]
AutonomyMode = Literal["manual", "supervised", "bounded"]


class AgentVersionConfigurationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=160)
    instructions: str = Field(min_length=1, max_length=50_000)
    provider: ProviderName
    model: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:/-]+$")
    autonomy_mode: AutonomyMode = "supervised"
    temperature: float = Field(default=0, ge=0, le=2)
    max_output_tokens: int = Field(default=4096, ge=1, le=200_000)
    max_parallel_tasks: int = Field(default=1, ge=1, le=30)
    max_runtime_seconds: int = Field(default=900, ge=1, le=86_400)
    max_tool_calls: int = Field(default=20, ge=0, le=1000)
    max_input_tokens: int = Field(default=100_000, ge=1, le=2_000_000)
    max_estimated_spend_micros: int = Field(default=1_000_000, ge=0, le=10_000_000_000)
    scope_policy: dict[str, Any] = Field(default_factory=dict)
    retrieval_policy: dict[str, Any] = Field(default_factory=dict)
    tool_names: list[str] = Field(default_factory=list, max_length=100)
    collection_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def unique_links(self) -> AgentVersionConfigurationIn:
        if len(self.tool_names) != len(set(self.tool_names)):
            raise ValueError("tool names must be unique")
        if any(not name or len(name) > 120 for name in self.tool_names):
            raise ValueError("tool names must contain 1 to 120 characters")
        if len(self.collection_ids) != len(set(self.collection_ids)):
            raise ValueError("collection ids must be unique")
        return self


class AgentDefinitionCreateIn(AgentVersionConfigurationIn):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10_000)
    avatar_reference: str | None = Field(default=None, max_length=1000)


class AgentVersionCreateIn(AgentVersionConfigurationIn):
    expected_active_version_id: uuid.UUID


class AgentDefinitionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    avatar_reference: str | None
    active_version_id: uuid.UUID | None
    is_enabled: bool
    version_count: int
    created_at: dt.datetime
    updated_at: dt.datetime


class AgentDefinitionVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_definition_id: uuid.UUID
    version: int
    role: str
    instructions: str
    provider: str
    model: str
    autonomy_mode: str
    temperature: float
    max_output_tokens: int
    max_parallel_tasks: int
    max_runtime_seconds: int
    max_tool_calls: int
    max_input_tokens: int
    max_estimated_spend_micros: int
    scope_policy: dict[str, Any]
    retrieval_policy: dict[str, Any]
    configuration_digest: str
    created_at: dt.datetime


__all__ = [
    "AgentDefinitionCreateIn",
    "AgentDefinitionOut",
    "AgentDefinitionVersionOut",
    "AgentVersionConfigurationIn",
    "AgentVersionCreateIn",
]
