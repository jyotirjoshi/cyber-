"""Deterministic validation for model-proposed multi-agent DAGs."""

from __future__ import annotations

import uuid

import pytest

from app.agent.tools.registry import default_tool_registry
from app.schemas.agent_plan import AgentPlan, AgentPlanTask
from app.services.agent_plan_validator import (
    PlanValidationContext,
    PlanValidationError,
    validate_plan,
)

ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")
AGENT_ID = uuid.UUID("20000000-0000-0000-0000-000000000001")
ASSET_ID = uuid.UUID("30000000-0000-0000-0000-000000000001")
FOREIGN_ASSET_ID = uuid.UUID("30000000-0000-0000-0000-000000000099")


def _context(**overrides: object) -> PlanValidationContext:
    values: dict[str, object] = {
        "organization_id": ORG_ID,
        "tool_registry": default_tool_registry(),
        "allowed_tool_versions": frozenset({("read_assets", 1)}),
        "allowed_agent_version_ids": frozenset({AGENT_ID}),
        "accessible_asset_ids": frozenset({ASSET_ID}),
        "remaining_task_budget": 30,
        "remaining_tool_call_budget": 20,
        "remaining_input_tokens": 100_000,
        "remaining_output_tokens": 20_000,
        "remaining_spend_micros": 1_000_000,
    }
    values.update(overrides)
    return PlanValidationContext(**values)  # type: ignore[arg-type]


def _task(key: str, **overrides: object) -> AgentPlanTask:
    values: dict[str, object] = {"key": key, "kind": "decision"}
    values.update(overrides)
    return AgentPlanTask(**values)  # type: ignore[arg-type]


def _plan(*tasks: AgentPlanTask) -> AgentPlan:
    return AgentPlan(objective="Investigate the scoped exposure", tasks=list(tasks))


def test_task_success_criteria_are_bounded_and_schema_validated() -> None:
    from pydantic import ValidationError

    task = _task(
        "verify",
        success_criteria=[
            {"source": "output", "path": "verified", "operator": "eq", "value": True},
            {"source": "evidence", "path": "kind", "operator": "eq", "value": "scan"},
        ],
    )
    assert len(task.success_criteria) == 2

    with pytest.raises(ValidationError):
        _task(
            "invalid",
            success_criteria=[{"source": "output", "path": "x", "operator": "shell"}],
        )


@pytest.mark.parametrize(
    ("plan", "code"),
    [
        (
            _plan(
                _task("first", depends_on=["second"]),
                _task("second", depends_on=["first"]),
            ),
            "plan_cycle",
        ),
        (
            _plan(
                _task(
                    "unknown",
                    kind="tool",
                    tool_name="missing_tool",
                    input={"question": "what is exposed?"},
                )
            ),
            "unknown_tool",
        ),
        (
            _plan(
                _task("one"),
                _task("two", depends_on=["one"]),
                _task("three", depends_on=["two"]),
                _task("four", depends_on=["three"]),
            ),
            "plan_depth_exceeded",
        ),
        (
            _plan(*(_task(f"task_{index}") for index in range(31))),
            "task_limit_exceeded",
        ),
        (
            _plan(_task("foreign", target_asset_ids=[FOREIGN_ASSET_ID])),
            "resource_not_found",
        ),
    ],
)
def test_invalid_plans_are_rejected(plan: AgentPlan, code: str) -> None:
    with pytest.raises(PlanValidationError) as exc:
        validate_plan(plan, _context())

    assert exc.value.code == code


def test_valid_plan_is_stably_topologically_sorted_and_digest_bound() -> None:
    plan = _plan(
        _task("intel"),
        _task("asset"),
        _task("join", kind="join", depends_on=["intel", "asset"], join_policy="all"),
        _task("final", kind="finalize", depends_on=["join"]),
    )

    validated = validate_plan(plan, _context())

    assert [task.key for task in validated.ordered_tasks] == ["intel", "asset", "join", "final"]
    assert validated.depth_by_task == {"intel": 1, "asset": 1, "join": 2, "final": 3}
    assert set(validated.payload_digests) == {"intel", "asset", "join", "final"}
    assert all(len(value) == 64 for value in validated.payload_digests.values())


def test_tool_payload_is_validated_against_registered_contract() -> None:
    plan = _plan(
        _task(
            "read",
            kind="tool",
            tool_name="read_assets",
            input={"unexpected": "payload"},
        )
    )

    with pytest.raises(PlanValidationError) as exc:
        validate_plan(plan, _context())

    assert exc.value.code == "invalid_tool_input"
    assert exc.value.task_key == "read"


def test_agent_task_must_reference_an_allowed_immutable_version() -> None:
    plan = _plan(_task("specialist", kind="agent", agent_version_id=uuid.uuid4()))

    with pytest.raises(PlanValidationError) as exc:
        validate_plan(plan, _context())

    assert exc.value.code == "unknown_agent"


def test_estimated_plan_usage_cannot_exceed_remaining_budget() -> None:
    plan = _plan(_task("expensive", estimated_spend_micros=500_000))

    with pytest.raises(PlanValidationError) as exc:
        validate_plan(plan, _context(remaining_spend_micros=499_999))

    assert exc.value.code == "budget_exceeded"


def test_quorum_join_rejects_impossible_quorum() -> None:
    plan = _plan(
        _task("one"),
        _task("join", kind="join", depends_on=["one"], join_policy="quorum", quorum=2),
    )

    with pytest.raises(PlanValidationError) as exc:
        validate_plan(plan, _context())

    assert exc.value.code == "invalid_join"
