"""Deterministic safety and feasibility validation for agent task plans."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.agent.tools.registry import ToolRegistry
from app.db.enums import AgentTaskKind
from app.schemas.agent_plan import AgentPlan, AgentPlanTask, ValidatedAgentPlan


class PlanValidationError(ValueError):
    """A stable, user-safe plan rejection returned before any persistence."""

    def __init__(self, code: str, detail: str, *, task_key: str | None = None) -> None:
        self.code = code
        self.detail = detail
        self.task_key = task_key
        super().__init__(f"{code}: {detail}")


@dataclass(frozen=True, slots=True)
class PlanValidationContext:
    """Trusted authority, scope, and remaining-budget facts for one validation."""

    organization_id: uuid.UUID
    tool_registry: ToolRegistry
    allowed_tool_versions: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    allowed_agent_version_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    accessible_asset_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    maximum_depth: int = 3
    maximum_tasks: int = 30
    maximum_parallel_tasks: int = 3
    remaining_task_budget: int = 30
    remaining_tool_call_budget: int = 20
    remaining_input_tokens: int = 100_000
    remaining_output_tokens: int = 20_000
    remaining_spend_micros: int = 1_000_000

    def __post_init__(self) -> None:
        ceilings = (
            self.maximum_depth,
            self.maximum_tasks,
            self.maximum_parallel_tasks,
            self.remaining_task_budget,
            self.remaining_tool_call_budget,
            self.remaining_input_tokens,
            self.remaining_output_tokens,
            self.remaining_spend_micros,
        )
        if any(value < 0 for value in ceilings):
            raise ValueError("plan validation ceilings cannot be negative")
        if self.maximum_depth < 1 or self.maximum_tasks < 1 or self.maximum_parallel_tasks < 1:
            raise ValueError("plan validation maximums must be positive")


def _tasks_by_key(plan: AgentPlan) -> dict[str, AgentPlanTask]:
    tasks: dict[str, AgentPlanTask] = {}
    for task in plan.tasks:
        if task.key in tasks:
            raise PlanValidationError(
                "duplicate_task_key", "Task keys must be unique within a run.", task_key=task.key
            )
        if len(task.depends_on) != len(set(task.depends_on)):
            raise PlanValidationError(
                "duplicate_dependency",
                "A task cannot depend on the same parent more than once.",
                task_key=task.key,
            )
        tasks[task.key] = task
    return tasks


def stable_topological_sort(plan: AgentPlan) -> tuple[AgentPlanTask, ...]:
    """Return dependency order while preserving planner order between ready peers."""

    tasks = _tasks_by_key(plan)
    position = {task.key: index for index, task in enumerate(plan.tasks)}
    dependents: dict[str, list[str]] = {key: [] for key in tasks}
    indegree: dict[str, int] = {}

    for task in plan.tasks:
        for parent in task.depends_on:
            if parent not in tasks:
                raise PlanValidationError(
                    "unknown_dependency",
                    "A dependency does not exist in this plan.",
                    task_key=task.key,
                )
            if parent == task.key:
                raise PlanValidationError(
                    "plan_cycle", "A task cannot depend on itself.", task_key=task.key
                )
            dependents[parent].append(task.key)
        if task.condition is not None and task.condition.task_key not in task.depends_on:
            raise PlanValidationError(
                "invalid_condition",
                "A condition may reference only one of the task's dependencies.",
                task_key=task.key,
            )
        indegree[task.key] = len(task.depends_on)

    ready = sorted((key for key, count in indegree.items() if count == 0), key=position.get)
    ordered: list[AgentPlanTask] = []
    while ready:
        key = ready.pop(0)
        ordered.append(tasks[key])
        for child in sorted(dependents[key], key=position.get):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort(key=position.get)

    if len(ordered) != len(tasks):
        raise PlanValidationError("plan_cycle", "The proposed task graph contains a cycle.")
    return tuple(ordered)


def _depths(ordered: tuple[AgentPlanTask, ...], *, maximum: int) -> tuple[dict[str, int], int]:
    depths: dict[str, int] = {}
    widths: dict[int, int] = {}
    for task in ordered:
        depth = 1 + max((depths[parent] for parent in task.depends_on), default=0)
        depths[task.key] = depth
        widths[depth] = widths.get(depth, 0) + 1
        if depth > maximum:
            raise PlanValidationError(
                "plan_depth_exceeded",
                f"The task graph exceeds the maximum depth of {maximum}.",
                task_key=task.key,
            )
    return depths, max(widths.values(), default=0)


def enforce_depth(ordered: tuple[AgentPlanTask, ...], maximum: int = 3) -> dict[str, int]:
    """Public helper used by planners that need only depth annotations."""

    return _depths(ordered, maximum=maximum)[0]


def _validate_join(task: AgentPlanTask) -> None:
    if task.kind != AgentTaskKind.JOIN:
        if task.join_policy is not None or task.quorum is not None:
            raise PlanValidationError(
                "invalid_join", "Only join tasks may set a join policy.", task_key=task.key
            )
        return
    if not task.depends_on:
        raise PlanValidationError(
            "invalid_join", "A join needs at least one dependency.", task_key=task.key
        )
    policy = task.join_policy or "all"
    if policy == "quorum":
        if task.quorum is None or task.quorum > len(task.depends_on):
            raise PlanValidationError(
                "invalid_join",
                "A quorum must be attainable from the join dependencies.",
                task_key=task.key,
            )
    elif task.quorum is not None:
        raise PlanValidationError(
            "invalid_join", "Only quorum joins may set quorum.", task_key=task.key
        )


def _validate_task(task: AgentPlanTask, context: PlanValidationContext) -> None:
    foreign_assets = set(task.target_asset_ids) - context.accessible_asset_ids
    if foreign_assets:
        raise PlanValidationError(
            "resource_not_found",
            "One or more scoped resources are unavailable.",
            task_key=task.key,
        )

    _validate_join(task)
    if task.kind == AgentTaskKind.TOOL:
        if task.tool_name is None:
            raise PlanValidationError(
                "unknown_tool", "A tool task must name a tool contract.", task_key=task.key
            )
        spec = context.tool_registry.find(task.tool_name, task.tool_version)
        if spec is None:
            raise PlanValidationError(
                "unknown_tool", "The requested tool contract is unavailable.", task_key=task.key
            )
        if (task.tool_name, task.tool_version) not in context.allowed_tool_versions:
            raise PlanValidationError(
                "tool_not_allowed",
                "The requested tool is outside the effective authority policy.",
                task_key=task.key,
            )
        try:
            spec.input_model.model_validate(task.input)
        except ValidationError as exc:
            raise PlanValidationError(
                "invalid_tool_input",
                "The tool input does not match its registered schema.",
                task_key=task.key,
            ) from exc
    elif task.tool_name is not None:
        raise PlanValidationError(
            "unexpected_tool", "Only tool tasks may name a tool.", task_key=task.key
        )

    if task.kind == AgentTaskKind.AGENT:
        if (
            task.agent_version_id is None
            or task.agent_version_id not in context.allowed_agent_version_ids
        ):
            raise PlanValidationError(
                "unknown_agent",
                "The requested immutable agent version is unavailable.",
                task_key=task.key,
            )
    elif task.agent_version_id is not None:
        raise PlanValidationError(
            "unexpected_agent",
            "Only agent tasks may reference an agent version.",
            task_key=task.key,
        )


def _canonical_digest(task: AgentPlanTask) -> str:
    encoded = json.dumps(
        task.model_dump(mode="json", exclude_none=False),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_plan(plan: AgentPlan, context: PlanValidationContext) -> ValidatedAgentPlan:
    """Validate graph structure, schemas, scope, authority, and remaining budgets."""

    task_ceiling = min(context.maximum_tasks, context.remaining_task_budget)
    if len(plan.tasks) > task_ceiling:
        raise PlanValidationError(
            "task_limit_exceeded", f"The plan exceeds the task limit of {task_ceiling}."
        )
    if plan.max_parallel_tasks > context.maximum_parallel_tasks:
        raise PlanValidationError(
            "parallelism_exceeded",
            "The requested parallelism exceeds the effective execution ceiling.",
        )

    ordered = stable_topological_sort(plan)
    depth_by_task, width = _depths(ordered, maximum=context.maximum_depth)
    for task in ordered:
        _validate_task(task, context)

    tool_calls = sum(task.kind == AgentTaskKind.TOOL for task in ordered)
    input_tokens = sum(task.estimated_input_tokens for task in ordered)
    output_tokens = sum(task.estimated_output_tokens for task in ordered)
    spend_micros = sum(task.estimated_spend_micros for task in ordered)
    if (
        tool_calls > context.remaining_tool_call_budget
        or input_tokens > context.remaining_input_tokens
        or output_tokens > context.remaining_output_tokens
        or spend_micros > context.remaining_spend_micros
    ):
        raise PlanValidationError(
            "budget_exceeded", "The plan exceeds one or more remaining hard budgets."
        )

    return ValidatedAgentPlan(
        plan=plan,
        ordered_tasks=ordered,
        depth_by_task=depth_by_task,
        payload_digests={task.key: _canonical_digest(task) for task in ordered},
        maximum_parallel_width=width,
        estimated_input_tokens=input_tokens,
        estimated_output_tokens=output_tokens,
        estimated_spend_micros=spend_micros,
    )


__all__ = [
    "PlanValidationContext",
    "PlanValidationError",
    "enforce_depth",
    "stable_topological_sort",
    "validate_plan",
]
