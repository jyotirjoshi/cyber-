"""Resolve the least authority shared by identity, agent version, and tenant policy."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Protocol

from app.agent.tools.registry import (
    ToolApproval,
    ToolRegistry,
    ToolSideEffect,
    ToolSpec,
    default_tool_registry,
)
from app.services.context import Principal


class ToolAssignment(Protocol):
    tool_name: str
    tool_version: int
    approval_mode: str
    timeout_seconds: int
    per_run_call_limit: int


class AgentToolVersion(Protocol):
    autonomy_mode: str
    max_runtime_seconds: int
    max_tool_calls: int
    tools: Iterable[ToolAssignment]


@dataclass(frozen=True, slots=True)
class OrganizationToolPolicy:
    disabled_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_side_effects: frozenset[ToolSideEffect] = field(
        default_factory=lambda: frozenset(
            {"read", "tenant_write", "external_write", "active_security"}
        )
    )
    max_timeout_seconds: int = 300
    max_calls_per_tool: int = 20
    approval_overrides: Mapping[str, ToolApproval] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_timeout_seconds < 1:
            raise ValueError("organization tool timeout must be positive")
        if self.max_calls_per_tool < 0:
            raise ValueError("organization tool call limit cannot be negative")


@dataclass(frozen=True, slots=True)
class EffectiveTool:
    spec: ToolSpec
    approval: ToolApproval
    timeout_seconds: int
    per_run_call_limit: int


@dataclass(frozen=True, slots=True)
class EffectiveToolPolicy:
    tools: Mapping[str, EffectiveTool]
    rejected: Mapping[str, str]
    max_tool_calls: int


_APPROVAL_RANK: dict[str, int] = {"never": 0, "policy": 1, "always": 2}


def _strictest_approval(*values: str) -> ToolApproval:
    if any(value not in _APPROVAL_RANK for value in values):
        raise ValueError("invalid tool approval mode")
    return max(values, key=_APPROVAL_RANK.__getitem__)  # type: ignore[return-value]


def _assignments(version: AgentToolVersion) -> Iterable[ToolAssignment]:
    try:
        return version.tools
    except AttributeError as exc:
        raise ValueError("agent version tool assignments were not loaded") from exc


def resolve_effective_tools(
    principal: Principal,
    version: AgentToolVersion,
    organization_policy: OrganizationToolPolicy,
    *,
    registry: ToolRegistry | None = None,
) -> EffectiveToolPolicy:
    """Return only tools every authority layer permits; model output cannot widen it."""
    catalogue = registry or default_tool_registry()
    effective: dict[str, EffectiveTool] = {}
    rejected: dict[str, str] = {}
    total_budget = max(0, int(version.max_tool_calls))

    for assignment in _assignments(version):
        name = assignment.tool_name
        spec = catalogue.find(name, assignment.tool_version)
        if spec is None:
            rejected[name] = "unavailable"
            continue
        if not principal.has(spec.permission):
            rejected[name] = "permission"
            continue
        if (
            name in organization_policy.disabled_tools
            or spec.side_effect not in organization_policy.allowed_side_effects
        ):
            rejected[name] = "organization_policy"
            continue
        per_tool_limit = min(
            max(0, int(assignment.per_run_call_limit)),
            organization_policy.max_calls_per_tool,
            total_budget,
        )
        if per_tool_limit == 0:
            rejected[name] = "budget"
            continue
        organization_approval = organization_policy.approval_overrides.get(name, "never")
        mode_approval: Literal["never", "always"] = (
            "always" if version.autonomy_mode == "manual" and spec.side_effect != "read" else "never"
        )
        approval = _strictest_approval(
            spec.approval, assignment.approval_mode, organization_approval, mode_approval
        )
        timeout = min(
            spec.timeout_seconds,
            max(1, int(assignment.timeout_seconds)),
            organization_policy.max_timeout_seconds,
            max(1, int(version.max_runtime_seconds)),
        )
        effective[name] = EffectiveTool(
            spec=spec,
            approval=approval,
            timeout_seconds=timeout,
            per_run_call_limit=per_tool_limit,
        )
    return EffectiveToolPolicy(
        tools=MappingProxyType(effective),
        rejected=MappingProxyType(rejected),
        max_tool_calls=total_budget,
    )


__all__ = [
    "EffectiveTool",
    "EffectiveToolPolicy",
    "OrganizationToolPolicy",
    "resolve_effective_tools",
]
