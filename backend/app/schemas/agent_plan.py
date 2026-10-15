"""Typed contracts for bounded multi-agent execution plans."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from app.db.enums import AgentTaskKind

JoinPolicy = Literal["all", "quorum", "best_effort"]
ConditionOperator = Literal["eq", "ne", "exists", "truthy", "falsy"]


class AgentPlanCondition(BaseModel):
    """A deterministic predicate over one dependency's bounded output summary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")]
    path: Annotated[str, Field(min_length=1, max_length=300)]
    operator: ConditionOperator
    value: JsonValue | None = None


class AgentPlanTask(BaseModel):
    """One schema-bound node proposed by a planner.

    Trusted runtime values such as organization, principal, credentials, and database
    handles are intentionally absent.  They are supplied by the executor after the
    plan passes deterministic policy validation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")]
    kind: AgentTaskKind
    depends_on: list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")]] = Field(
        default_factory=list, max_length=30
    )
    condition: AgentPlanCondition | None = None
    input: dict[str, JsonValue] = Field(default_factory=dict)
    required: bool = True
    tool_name: Annotated[str | None, Field(min_length=1, max_length=120)] = None
    tool_version: Annotated[int, Field(ge=1, le=1000)] = 1
    agent_version_id: uuid.UUID | None = None
    target_asset_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    join_policy: JoinPolicy | None = None
    quorum: Annotated[int | None, Field(ge=1, le=30)] = None
    idempotency_key: Annotated[str | None, Field(min_length=1, max_length=160)] = None
    provider: Annotated[str | None, Field(min_length=1, max_length=80)] = None
    conflict_key: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    max_attempts: Annotated[int, Field(ge=1, le=10)] = 3
    estimated_input_tokens: Annotated[int, Field(ge=0, le=2_000_000)] = 0
    estimated_output_tokens: Annotated[int, Field(ge=0, le=200_000)] = 0
    estimated_spend_micros: Annotated[int, Field(ge=0, le=10_000_000_000)] = 0


class AgentPlan(BaseModel):
    """One bounded directed acyclic graph produced for an objective."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    objective: Annotated[str, Field(min_length=1, max_length=4000)]
    tasks: list[AgentPlanTask] = Field(min_length=1, max_length=100)
    max_parallel_tasks: Annotated[int, Field(ge=1, le=30)] = 3


class ValidatedAgentPlan(BaseModel):
    """A planner result annotated with deterministic execution metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: AgentPlan
    ordered_tasks: tuple[AgentPlanTask, ...]
    depth_by_task: dict[str, int]
    payload_digests: dict[str, str]
    maximum_parallel_width: int
    estimated_input_tokens: int
    estimated_output_tokens: int
    estimated_spend_micros: int


__all__ = [
    "AgentPlan",
    "AgentPlanCondition",
    "AgentPlanTask",
    "ConditionOperator",
    "JoinPolicy",
    "ValidatedAgentPlan",
]
