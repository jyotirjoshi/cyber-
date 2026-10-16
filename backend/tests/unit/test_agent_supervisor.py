"""Hard budget reservations and bounded supervisor decision waves."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.agent.tools.registry import default_tool_registry
from app.db.models.agent import AgentRun
from app.db.models.agent_task import AgentBudgetReservation
from app.schemas.agent_plan import AgentPlanTask
from app.services.agent_budget import BudgetLimits, BudgetRequest, reserve_budget, settle_usage
from app.services.agent_plan_validator import PlanValidationContext
from app.services.agent_supervisor import AgentSupervisor, SupervisorBudget, SupervisorDecision
from app.services.usage_metering import MeterEvent, agent_usage_quantities

ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")


def _copy_table(model: type, metadata: MetaData) -> None:
    Table(
        model.__tablename__,
        metadata,
        *[
            Column(
                column.name,
                JSON()
                if isinstance(column.type, JSONB)
                else Uuid()
                if isinstance(column.type, Uuid)
                else column.type,
                primary_key=column.primary_key,
                nullable=column.nullable,
                server_default=column.server_default
                or (func.now() if column.name in {"created_at", "updated_at"} else None),
            )
            for column in model.__table__.columns
        ],
    )


@pytest.fixture
async def budget_store():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (AgentRun, AgentBudgetReservation):
        _copy_table(model, metadata)
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_budget_reservation_is_atomic_idempotent_and_reconciles_actuals(budget_store) -> None:
    run_id = uuid.uuid4()
    async with budget_store() as session:
        session.add(
            AgentRun(
                id=run_id,
                organization_id=ORG_ID,
                thread_id=str(run_id),
                graph="multi_agent",
                status="running",
            )
        )
        await session.commit()
    limits = BudgetLimits(tasks=2, input_tokens=100, output_tokens=50, spend_micros=1_000)
    request = BudgetRequest(tasks=1, input_tokens=40, output_tokens=20, spend_micros=400)
    async with budget_store() as session:
        first = await reserve_budget(
            session,
            ORG_ID,
            run_id,
            reservation_key="wave-1",
            request=request,
            limits=limits,
        )
        again = await reserve_budget(
            session,
            ORG_ID,
            run_id,
            reservation_key="wave-1",
            request=request,
            limits=limits,
        )
        assert first is not None and again is not None and first.id == again.id
        assert (
            await reserve_budget(
                session,
                ORG_ID,
                run_id,
                reservation_key="too-large",
                request=BudgetRequest(tasks=2, input_tokens=61),
                limits=limits,
            )
            is None
        )
        await settle_usage(
            session,
            ORG_ID,
            first.id,
            actual=BudgetRequest(tasks=1, input_tokens=30, output_tokens=15, spend_micros=350),
        )
        await session.commit()
    async with budget_store() as session:
        stored = (await session.execute(select(AgentBudgetReservation))).scalar_one()
        assert stored.status == "settled"
        assert stored.actual_tasks == 1
        assert stored.actual_input_tokens == 30
        assert stored.actual_output_tokens == 15
        assert stored.actual_spend_micros == 350


def _context(**overrides: object) -> PlanValidationContext:
    values: dict[str, object] = {
        "organization_id": ORG_ID,
        "tool_registry": default_tool_registry(),
        "maximum_depth": 2,
        "maximum_tasks": 5,
        "maximum_parallel_tasks": 2,
        "remaining_task_budget": 5,
        "remaining_tool_call_budget": 5,
        "remaining_input_tokens": 1_000,
        "remaining_output_tokens": 500,
        "remaining_spend_micros": 10_000,
    }
    values.update(overrides)
    return PlanValidationContext(**values)  # type: ignore[arg-type]


class _RepeatingModel:
    def __init__(self) -> None:
        self.calls = 0

    async def decide(self, request):
        self.calls += 1
        return SupervisorDecision(
            hypothesis="Check the same hypothesis",
            tasks=[AgentPlanTask(key="repeat", kind="decision")],
        )


@pytest.mark.asyncio
async def test_duplicate_rejected_proposals_stop_within_budget() -> None:
    model = _RepeatingModel()
    supervisor = AgentSupervisor(_context())
    result = await supervisor.run(
        model=model,
        objective="Investigate the scoped exposure",
        budget=SupervisorBudget(tasks=5, decision_waves=5),
    )
    assert result.stop_reason == "no_valid_next_action"
    assert result.task_count <= 5
    assert result.task_count == 1
    assert model.calls == 2


@pytest.mark.asyncio
async def test_exhausted_budget_finalizes_partial_evidence_without_model_call() -> None:
    model = _RepeatingModel()
    supervisor = AgentSupervisor(_context(remaining_task_budget=0))
    result = await supervisor.run(
        model=model,
        objective="Investigate the scoped exposure",
        budget=SupervisorBudget(tasks=0, decision_waves=2),
        evidence_summary=[{"kind": "observation", "summary": "One exposed service"}],
    )
    assert result.stop_reason == "budget_exhausted"
    assert result.evidence_summary == ({"kind": "observation", "summary": "One exposed service"},)
    assert model.calls == 0


@pytest.mark.asyncio
async def test_model_cannot_raise_task_or_depth_limits() -> None:
    class OversizedModel:
        async def decide(self, request):
            return {
                "hypothesis": "Attempt to exceed the trusted ceiling",
                "tasks": [{"key": f"task_{index}", "kind": "decision"} for index in range(6)],
            }

    result = await AgentSupervisor(_context(maximum_tasks=2, remaining_task_budget=2)).run(
        model=OversizedModel(),
        objective="Investigate",
        budget=SupervisorBudget(tasks=2, decision_waves=1),
    )
    assert result.task_count == 0
    assert result.stop_reason == "policy_blocked"


def test_agent_usage_is_mapped_to_append_only_meter_events() -> None:
    quantities = agent_usage_quantities(
        BudgetRequest(tasks=2, input_tokens=30, output_tokens=12, spend_micros=90)
    )
    assert quantities == {
        MeterEvent.AGENT_TASK_COMPLETED: 2,
        MeterEvent.AI_INPUT_TOKEN: 30,
        MeterEvent.AI_OUTPUT_TOKEN: 12,
        MeterEvent.AI_SPEND_MICRO: 90,
    }


def test_existing_planner_surface_exposes_generic_supervisor_contract() -> None:
    from app.services import agent_planner

    assert agent_planner.plan_objective is not None
    assert agent_planner.decide_next_wave is not None
