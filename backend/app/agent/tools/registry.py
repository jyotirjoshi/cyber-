"""Typed, versioned tool catalogue backed by Cynux's existing service layer."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, RootModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import Permission
from app.services.context import Principal

ToolSideEffect = Literal["read", "tenant_write", "external_write", "active_security"]
ToolApproval = Literal["never", "policy", "always"]


@dataclass(frozen=True, slots=True)
class ToolExecutionContext:
    """Trusted runtime values that must never be supplied by a model."""

    session: AsyncSession
    principal: Principal
    agent_session_id: uuid.UUID


class ToolExecutor(Protocol):
    def __call__(
        self, context: ToolExecutionContext, arguments: BaseModel
    ) -> Awaitable[BaseModel]: ...


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    version: int
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    permission: Permission
    side_effect: ToolSideEffect
    approval: ToolApproval
    timeout_seconds: int
    idempotent: bool
    executor: ToolExecutor

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 120:
            raise ValueError("tool names must contain 1 to 120 characters")
        if self.version < 1:
            raise ValueError("tool versions start at one")
        if not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("tool timeouts must be between 1 and 3600 seconds")


class ToolRegistry:
    """Append-only registration keyed by public name and contract version."""

    def __init__(self) -> None:
        self._specs: dict[tuple[str, int], ToolSpec] = {}

    def register(self, spec: ToolSpec) -> ToolSpec:
        key = (spec.name, spec.version)
        if key in self._specs:
            raise ValueError(f"tool {spec.name!r} version {spec.version} is already registered")
        self._specs[key] = spec
        return spec

    def get(self, name: str, version: int = 1) -> ToolSpec:
        try:
            return self._specs[(name, version)]
        except KeyError as exc:
            raise KeyError(f"unknown tool {name!r} version {version}") from exc

    def find(self, name: str, version: int = 1) -> ToolSpec | None:
        return self._specs.get((name, version))

    @property
    def specs(self) -> Mapping[tuple[str, int], ToolSpec]:
        return MappingProxyType(self._specs)


class ReadQueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=2000)


class ReadToolOutput(BaseModel):
    content: str | None


class AgentActionInput(RootModel[dict[str, Any]]):
    """The exact action payload; the existing service performs action-specific validation."""


class AgentActionOutput(BaseModel):
    action_id: uuid.UUID
    status: str
    payload_digest: str


async def _read_findings(
    context: ToolExecutionContext, arguments: BaseModel
) -> BaseModel:
    from app.services.agent_read_tools import maybe_read_canonical_findings

    query = ReadQueryInput.model_validate(arguments)
    content = await maybe_read_canonical_findings(
        context.session, context.principal, query.question
    )
    return ReadToolOutput(content=content)


async def _read_assets(context: ToolExecutionContext, arguments: BaseModel) -> BaseModel:
    from app.services.agent_read_tools import maybe_read_assets

    query = ReadQueryInput.model_validate(arguments)
    content = await maybe_read_assets(context.session, context.principal, query.question)
    return ReadToolOutput(content=content)


def _action_executor(action: str) -> ToolExecutor:
    async def propose(context: ToolExecutionContext, arguments: BaseModel) -> BaseModel:
        from app.services.agent_action import propose_action

        payload = AgentActionInput.model_validate(arguments).root
        proposed = await propose_action(
            context.session,
            context.principal,
            session_id=context.agent_session_id,
            action=action,
            label=action.replace("_", " ").title(),
            rationale="Proposed by configured agent tool execution.",
            payload=payload,
        )
        return AgentActionOutput(
            action_id=proposed.id,
            status=proposed.status,
            payload_digest=proposed.payload_digest,
        )

    return propose


_EXTERNAL_WRITES = frozenset({"create_jira_ticket", "create_ticket", "update_github_alert"})
_ACTIVE_SECURITY = frozenset({"start_assessment"})
_IDEMPOTENT_ACTIONS = frozenset({"refresh_ticket_status"})


@lru_cache(maxsize=1)
def default_tool_registry() -> ToolRegistry:
    """Build the process-wide catalogue from existing authorization contracts."""
    from app.services.agent_action import action_permission, registered_action_names

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="read_findings",
            version=1,
            input_model=ReadQueryInput,
            output_model=ReadToolOutput,
            permission=Permission.FINDING_READ,
            side_effect="read",
            approval="never",
            timeout_seconds=30,
            idempotent=True,
            executor=_read_findings,
        )
    )
    registry.register(
        ToolSpec(
            name="read_assets",
            version=1,
            input_model=ReadQueryInput,
            output_model=ReadToolOutput,
            permission=Permission.ASSET_READ,
            side_effect="read",
            approval="never",
            timeout_seconds=30,
            idempotent=True,
            executor=_read_assets,
        )
    )
    for action in registered_action_names():
        if action in _EXTERNAL_WRITES:
            side_effect: ToolSideEffect = "external_write"
            approval: ToolApproval = "always"
        elif action in _ACTIVE_SECURITY:
            side_effect = "active_security"
            approval = "always"
        else:
            side_effect = "tenant_write"
            approval = "policy"
        registry.register(
            ToolSpec(
                name=action,
                version=1,
                input_model=AgentActionInput,
                output_model=AgentActionOutput,
                permission=action_permission(action),
                side_effect=side_effect,
                approval=approval,
                timeout_seconds=60,
                idempotent=action.startswith("sync_") or action in _IDEMPOTENT_ACTIONS,
                executor=_action_executor(action),
            )
        )
    return registry


__all__ = [
    "AgentActionInput",
    "AgentActionOutput",
    "ReadQueryInput",
    "ReadToolOutput",
    "ToolApproval",
    "ToolExecutionContext",
    "ToolExecutor",
    "ToolRegistry",
    "ToolSideEffect",
    "ToolSpec",
    "default_tool_registry",
]
