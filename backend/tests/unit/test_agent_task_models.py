"""Persistence invariants for durable multi-agent task graphs."""

from __future__ import annotations

import sqlalchemy as sa

from app.db.models.agent_task import (
    AgentBudgetReservation,
    AgentEvidence,
    AgentTask,
    AgentTaskAttempt,
    AgentTaskDependency,
)

MODELS = (
    AgentTask,
    AgentTaskDependency,
    AgentTaskAttempt,
    AgentEvidence,
    AgentBudgetReservation,
)


def _constraint_names(model: type) -> set[str | None]:
    prefix = f"ck_{model.__tablename__}_"
    names = {constraint.name for constraint in model.__table__.constraints}
    names.update(
        name.removeprefix(prefix)
        for name in tuple(names)
        if isinstance(name, str) and name.startswith(prefix)
    )
    return names


def test_task_has_unique_run_idempotency_key() -> None:
    assert "unique_agent_task_idempotency" in _constraint_names(AgentTask)


def test_attempt_lease_generation_is_positive() -> None:
    assert "valid_agent_task_attempt_lease" in _constraint_names(AgentTaskAttempt)


def test_every_task_graph_table_is_tenant_scoped() -> None:
    for model in MODELS:
        column = model.__table__.c.get("organization_id")
        assert column is not None, model.__tablename__
        assert column.nullable is False, model.__tablename__
        assert any(
            foreign_key.target_fullname == "organizations.id" and foreign_key.ondelete == "CASCADE"
            for foreign_key in column.foreign_keys
        ), model.__tablename__


def test_dependency_edges_are_unique_and_cannot_point_to_themselves() -> None:
    names = _constraint_names(AgentTaskDependency)
    assert "unique_agent_task_dependency" in names
    assert "valid_agent_task_dependency_distinct" in names


def test_task_scope_is_available_for_composite_dependency_foreign_keys() -> None:
    assert "unique_agent_task_scope" in _constraint_names(AgentTask)
    targets = {
        tuple(element.target_fullname for element in constraint.elements)
        for constraint in AgentTaskDependency.__table__.constraints
        if isinstance(constraint, sa.ForeignKeyConstraint) and len(constraint.elements) == 3
    }
    expected = (
        "agent_tasks.id",
        "agent_tasks.run_id",
        "agent_tasks.organization_id",
    )
    assert expected in targets


def test_attempt_generation_is_unique_per_task() -> None:
    assert "unique_agent_task_attempt_generation" in _constraint_names(AgentTaskAttempt)


def test_budget_amounts_cannot_be_negative() -> None:
    assert "valid_agent_budget_reservation_amounts" in _constraint_names(AgentBudgetReservation)
