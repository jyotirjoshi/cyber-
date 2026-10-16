"""Durable plan materialization and dependency scheduling."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.agent.tools.registry import default_tool_registry
from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.agent_task import AgentTask, AgentTaskDependency
from app.schemas.agent_plan import AgentPlan, AgentPlanTask
from app.services.agent_plan_validator import PlanValidationContext, validate_plan
from app.services.agent_scheduler import materialize_plan, release_ready_tasks

ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")
OTHER_ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000002")


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
                or (func.now() if column.name == "created_at" else None),
            )
            for column in model.__table__.columns
        ],
    )


@pytest.fixture
async def scheduler_session():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (AgentRun, AgentTask, AgentTaskDependency, RunDispatch):
        _copy_table(model, metadata)
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await engine.dispose()


def _validated(*tasks: AgentPlanTask):
    return validate_plan(
        AgentPlan(objective="Investigate", tasks=list(tasks)),
        PlanValidationContext(
            organization_id=ORG_ID,
            tool_registry=default_tool_registry(),
        ),
    )


async def _run(session, *, organization_id: uuid.UUID = ORG_ID) -> AgentRun:
    run = AgentRun(
        id=uuid.uuid4(),
        organization_id=organization_id,
        thread_id=str(uuid.uuid4()),
        graph="multi_agent",
        status="running",
    )
    session.add(run)
    await session.flush()
    return run


async def _status(session, run_id: uuid.UUID, task_key: str) -> str:
    return (
        await session.execute(
            select(AgentTask.status).where(
                AgentTask.run_id == run_id, AgentTask.task_key == task_key
            )
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_only_dependency_free_tasks_are_released(scheduler_session) -> None:
    run = await _run(scheduler_session)
    plan = _validated(
        AgentPlanTask(key="triage", kind="decision"),
        AgentPlanTask(key="intel", kind="decision"),
        AgentPlanTask(key="asset", kind="decision"),
        AgentPlanTask(
            key="join",
            kind="join",
            depends_on=["triage", "intel", "asset"],
            join_policy="all",
        ),
    )
    await materialize_plan(scheduler_session, ORG_ID, run.id, plan)

    released = await release_ready_tasks(scheduler_session, ORG_ID, run.id)

    assert [task.task_key for task in released] == ["triage", "intel", "asset"]
    assert await _status(scheduler_session, run.id, "join") == "blocked"
    dispatches = (
        (await scheduler_session.execute(select(RunDispatch).where(RunDispatch.run_id == run.id)))
        .scalars()
        .all()
    )
    assert {dispatch.task_id for dispatch in dispatches} == {task.id for task in released}


@pytest.mark.asyncio
async def test_materialization_and_release_are_idempotent(scheduler_session) -> None:
    run = await _run(scheduler_session)
    plan = _validated(AgentPlanTask(key="triage", kind="decision"))

    first = await materialize_plan(scheduler_session, ORG_ID, run.id, plan)
    second = await materialize_plan(scheduler_session, ORG_ID, run.id, plan)
    released = await release_ready_tasks(scheduler_session, ORG_ID, run.id)
    rereleased = await release_ready_tasks(scheduler_session, ORG_ID, run.id)

    assert [task.id for task in first] == [task.id for task in second]
    assert len(released) == 1
    assert rereleased == []
    assert len((await scheduler_session.execute(select(RunDispatch))).scalars().all()) == 1


@pytest.mark.asyncio
async def test_all_join_releases_after_every_dependency_succeeds(scheduler_session) -> None:
    run = await _run(scheduler_session)
    plan = _validated(
        AgentPlanTask(key="one", kind="decision"),
        AgentPlanTask(key="two", kind="decision"),
        AgentPlanTask(key="join", kind="join", depends_on=["one", "two"], join_policy="all"),
    )
    tasks = await materialize_plan(scheduler_session, ORG_ID, run.id, plan)
    await release_ready_tasks(scheduler_session, ORG_ID, run.id)
    for task in tasks:
        if task.task_key in {"one", "two"}:
            task.status = "completed"
    await scheduler_session.flush()

    released = await release_ready_tasks(scheduler_session, ORG_ID, run.id)

    assert [task.task_key for task in released] == ["join"]


@pytest.mark.asyncio
async def test_impossible_quorum_fails_join_without_dispatch(scheduler_session) -> None:
    run = await _run(scheduler_session)
    plan = _validated(
        AgentPlanTask(key="one", kind="decision"),
        AgentPlanTask(key="two", kind="decision"),
        AgentPlanTask(
            key="join",
            kind="join",
            depends_on=["one", "two"],
            join_policy="quorum",
            quorum=2,
        ),
    )
    tasks = await materialize_plan(scheduler_session, ORG_ID, run.id, plan)
    await release_ready_tasks(scheduler_session, ORG_ID, run.id)
    for task in tasks:
        if task.task_key == "one":
            task.status = "completed"
        elif task.task_key == "two":
            task.status = "failed"
    await scheduler_session.flush()

    assert await release_ready_tasks(scheduler_session, ORG_ID, run.id) == []
    assert await _status(scheduler_session, run.id, "join") == "failed"


@pytest.mark.asyncio
async def test_best_effort_join_records_degradation_and_releases(scheduler_session) -> None:
    run = await _run(scheduler_session)
    plan = _validated(
        AgentPlanTask(key="one", kind="decision"),
        AgentPlanTask(key="two", kind="decision"),
        AgentPlanTask(
            key="join",
            kind="join",
            depends_on=["one", "two"],
            join_policy="best_effort",
        ),
    )
    tasks = await materialize_plan(scheduler_session, ORG_ID, run.id, plan)
    await release_ready_tasks(scheduler_session, ORG_ID, run.id)
    for task in tasks:
        if task.task_key == "one":
            task.status = "completed"
        elif task.task_key == "two":
            task.status = "failed"
    await scheduler_session.flush()

    released = await release_ready_tasks(scheduler_session, ORG_ID, run.id)

    assert [task.task_key for task in released] == ["join"]
    assert released[0].output_summary["degraded_dependencies"] == ["two"]


@pytest.mark.asyncio
async def test_other_tenant_cannot_materialize_or_release_run(scheduler_session) -> None:
    run = await _run(scheduler_session, organization_id=OTHER_ORG_ID)
    plan = _validated(AgentPlanTask(key="triage", kind="decision"))

    assert await materialize_plan(scheduler_session, ORG_ID, run.id, plan) == []
    assert await release_ready_tasks(scheduler_session, ORG_ID, run.id) == []
    assert (await scheduler_session.execute(select(AgentTask))).scalars().all() == []
