"""Schema-bound supervisor decisions with deterministic hard-stop behavior."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.schemas.agent_plan import AgentPlan, AgentPlanTask, ValidatedAgentPlan
from app.services.agent_plan_validator import (
    PlanValidationContext,
    PlanValidationError,
    validate_plan,
)

StopReason = Literal[
    "objective_complete",
    "no_valid_next_action",
    "budget_exhausted",
    "policy_blocked",
    "cancelled",
    "runtime_exhausted",
]


class SupervisorDecision(BaseModel):
    """The only model-controlled output accepted by the orchestration boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis: Annotated[str | None, Field(max_length=2000)] = None
    tasks: list[AgentPlanTask] = Field(default_factory=list, max_length=10)
    stop_reason: StopReason | None = None


class SupervisorModel(Protocol):
    async def decide(self, request: SupervisorRequest) -> SupervisorDecision | dict[str, Any]:
        ...


@dataclass(frozen=True, slots=True)
class SupervisorBudget:
    tasks: int
    decision_waves: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    spend_micros: int | None = None

    def __post_init__(self) -> None:
        values = (
            self.tasks,
            self.decision_waves,
            self.input_tokens or 0,
            self.output_tokens or 0,
            self.spend_micros or 0,
        )
        if min(values) < 0:
            raise ValueError("supervisor budgets cannot be negative")


@dataclass(frozen=True, slots=True)
class SupervisorRequest:
    objective: str
    evidence_summary: tuple[dict[str, Any], ...]
    completed_payload_digests: frozenset[str]
    remaining_tasks: int
    remaining_input_tokens: int
    remaining_output_tokens: int
    remaining_spend_micros: int
    wave: int


@dataclass(frozen=True, slots=True)
class SupervisorWave:
    sequence: int
    hypothesis: str | None
    plan: ValidatedAgentPlan


@dataclass(frozen=True, slots=True)
class SupervisorResult:
    stop_reason: StopReason
    waves: tuple[SupervisorWave, ...]
    task_count: int
    evidence_summary: tuple[dict[str, Any], ...]
    rejection_codes: tuple[str, ...] = ()


def _bounded_evidence(
    items: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    bounded: list[dict[str, Any]] = []
    for item in items[:100]:
        bounded.append({str(key)[:80]: value for key, value in list(item.items())[:30]})
    return tuple(bounded)


async def plan_objective(
    model: SupervisorModel,
    *,
    objective: str,
    evidence_summary: tuple[dict[str, Any], ...],
    completed_payload_digests: frozenset[str],
    remaining_tasks: int,
    remaining_input_tokens: int,
    remaining_output_tokens: int,
    remaining_spend_micros: int,
    wave: int,
) -> SupervisorDecision:
    """Ask for one decision and reject every non-schema model response."""

    raw = await model.decide(
        SupervisorRequest(
            objective=objective,
            evidence_summary=evidence_summary,
            completed_payload_digests=completed_payload_digests,
            remaining_tasks=remaining_tasks,
            remaining_input_tokens=remaining_input_tokens,
            remaining_output_tokens=remaining_output_tokens,
            remaining_spend_micros=remaining_spend_micros,
            wave=wave,
        )
    )
    return raw if isinstance(raw, SupervisorDecision) else SupervisorDecision.model_validate(raw)


def decide_next_wave(
    *,
    objective: str,
    decision: SupervisorDecision,
    context: PlanValidationContext,
    completed_payload_digests: frozenset[str],
) -> tuple[ValidatedAgentPlan | None, StopReason | None, tuple[str, ...]]:
    """Validate trusted limits, remove duplicates, and return one executable wave."""

    if decision.stop_reason is not None:
        return None, decision.stop_reason, ()
    if not decision.tasks:
        return None, "no_valid_next_action", ("empty_decision",)
    try:
        candidate = validate_plan(
            AgentPlan(
                objective=objective,
                tasks=decision.tasks,
                max_parallel_tasks=min(
                    context.maximum_parallel_tasks,
                    max(1, len(decision.tasks)),
                ),
            ),
            context,
        )
    except PlanValidationError as exc:
        return None, "policy_blocked", (exc.code,)

    novel = [
        task
        for task in candidate.ordered_tasks
        if candidate.payload_digests[task.key] not in completed_payload_digests
    ]
    if not novel:
        return None, "no_valid_next_action", ("duplicate_proposal",)
    if len(novel) != len(candidate.ordered_tasks):
        novel_keys = {task.key for task in novel}
        if any(parent not in novel_keys for task in novel for parent in task.depends_on):
            return None, "policy_blocked", ("duplicate_dependency",)
        try:
            candidate = validate_plan(
                AgentPlan(
                    objective=objective,
                    tasks=novel,
                    max_parallel_tasks=min(
                        context.maximum_parallel_tasks,
                        max(1, len(novel)),
                    ),
                ),
                context,
            )
        except PlanValidationError as exc:
            return None, "policy_blocked", (exc.code,)
    return candidate, None, ()


class AgentSupervisor:
    """Run bounded planning waves; execution remains the durable scheduler's job."""

    def __init__(self, validation_context: PlanValidationContext) -> None:
        self._context = validation_context

    async def run(
        self,
        *,
        model: SupervisorModel,
        objective: str,
        budget: SupervisorBudget,
        evidence_summary: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
    ) -> SupervisorResult:
        evidence = _bounded_evidence(evidence_summary)
        task_limit = min(budget.tasks, self._context.remaining_task_budget)
        input_limit = min(
            budget.input_tokens
            if budget.input_tokens is not None
            else self._context.remaining_input_tokens,
            self._context.remaining_input_tokens,
        )
        output_limit = min(
            budget.output_tokens
            if budget.output_tokens is not None
            else self._context.remaining_output_tokens,
            self._context.remaining_output_tokens,
        )
        spend_limit = min(
            budget.spend_micros
            if budget.spend_micros is not None
            else self._context.remaining_spend_micros,
            self._context.remaining_spend_micros,
        )
        if task_limit == 0 or budget.decision_waves == 0:
            return SupervisorResult("budget_exhausted", (), 0, evidence)

        completed: set[str] = set()
        waves: list[SupervisorWave] = []
        used_tasks = used_input = used_output = used_spend = 0
        rejections: list[str] = []
        for sequence in range(1, budget.decision_waves + 1):
            remaining_tasks = task_limit - used_tasks
            remaining_input = input_limit - used_input
            remaining_output = output_limit - used_output
            remaining_spend = spend_limit - used_spend
            if min(remaining_tasks, remaining_input, remaining_output, remaining_spend) <= 0:
                return SupervisorResult(
                    "budget_exhausted",
                    tuple(waves),
                    used_tasks,
                    evidence,
                    tuple(rejections),
                )
            try:
                decision = await plan_objective(
                    model,
                    objective=objective,
                    evidence_summary=evidence,
                    completed_payload_digests=frozenset(completed),
                    remaining_tasks=remaining_tasks,
                    remaining_input_tokens=remaining_input,
                    remaining_output_tokens=remaining_output,
                    remaining_spend_micros=remaining_spend,
                    wave=sequence,
                )
            except (ValidationError, TypeError, ValueError):
                return SupervisorResult(
                    "policy_blocked",
                    tuple(waves),
                    used_tasks,
                    evidence,
                    (*rejections, "invalid_supervisor_output"),
                )
            context = replace(
                self._context,
                remaining_task_budget=remaining_tasks,
                remaining_input_tokens=remaining_input,
                remaining_output_tokens=remaining_output,
                remaining_spend_micros=remaining_spend,
            )
            plan, stop_reason, rejected = decide_next_wave(
                objective=objective,
                decision=decision,
                context=context,
                completed_payload_digests=frozenset(completed),
            )
            rejections.extend(rejected)
            if plan is None:
                return SupervisorResult(
                    stop_reason or "no_valid_next_action",
                    tuple(waves),
                    used_tasks,
                    evidence,
                    tuple(rejections),
                )
            waves.append(SupervisorWave(sequence, decision.hypothesis, plan))
            used_tasks += len(plan.ordered_tasks)
            used_input += plan.estimated_input_tokens
            used_output += plan.estimated_output_tokens
            used_spend += plan.estimated_spend_micros
            completed.update(plan.payload_digests.values())

        return SupervisorResult(
            "budget_exhausted",
            tuple(waves),
            used_tasks,
            evidence,
            tuple(rejections),
        )


__all__ = [
    "AgentSupervisor",
    "StopReason",
    "SupervisorBudget",
    "SupervisorDecision",
    "SupervisorModel",
    "SupervisorRequest",
    "SupervisorResult",
    "SupervisorWave",
    "decide_next_wave",
    "plan_objective",
]
