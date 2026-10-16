"""Parent cancellation wins dispatch and late-settlement races."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.agent_task import AgentTask, AgentTaskAttempt, AgentTaskDependency
from app.db.models.assessment import Approval
from app.services.agent_scheduler import cancel_agent_run, release_ready_tasks
from app.services.agent_task_executor import TaskExecutionResult, claim_task, settle_task

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
                or (func.now() if column.name == "created_at" else None),
            )
            for column in model.__table__.columns
        ],
    )


@pytest.fixture
async def cancellation_store():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (
        AgentRun,
        AgentTask,
        AgentTaskDependency,
        AgentTaskAttempt,
        RunDispatch,
        Approval,
    ):
        _copy_table(model, metadata)
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


def _task(run_id: uuid.UUID, key: str, index: int) -> AgentTask:
    return AgentTask(
        id=uuid.uuid4(),
        organization_id=ORG_ID,
        run_id=run_id,
        task_key=key,
        kind="decision",
        status="pending",
        idempotency_key=f"{run_id}:{key}",
        payload_digest=(key[0] * 64),
        tool_version=1,
        input_schema_version="v1",
        output_schema_version="v1",
        input_payload={},
        orchestration={},
        output_summary={},
        required=True,
        plan_index=index,
        priority=100,
        attempt_count=0,
        max_attempts=3,
        current_lease_generation=0,
    )


@pytest.mark.asyncio
async def test_cancel_prevents_new_dispatch_and_late_settlement(cancellation_store) -> None:
    run_id = uuid.uuid4()
    async with cancellation_store() as session:
        session.add(
            AgentRun(
                id=run_id,
                organization_id=ORG_ID,
                thread_id=str(uuid.uuid4()),
                graph="multi_agent",
                status="running",
            )
        )
        session.add_all([_task(run_id, "one", 0), _task(run_id, "two", 1)])
        await session.commit()
    async with cancellation_store() as session:
        released = await release_ready_tasks(session, ORG_ID, run_id)
        assert len(released) == 2
        await session.commit()
        running_id = released[0].id
    async with cancellation_store() as session:
        claim = await claim_task(session, ORG_ID, running_id, worker_id="worker-one")
        assert claim is not None
        await session.commit()

    async with cancellation_store() as session:
        cancellation = await cancel_agent_run(session, ORG_ID, run_id)
        assert cancellation is not None
        await session.commit()
    async with cancellation_store() as session:
        assert await release_ready_tasks(session, ORG_ID, run_id) == []
        assert not await settle_task(
            session,
            claim,
            TaskExecutionResult(status="completed", output_summary={"late": True}),
        )
        statuses = set((await session.execute(select(AgentTask.status))).scalars().all())
        dispatch_statuses = set((await session.execute(select(RunDispatch.status))).scalars().all())
        assert statuses == {"cancelled"}
        assert dispatch_statuses == {"cancelled"}


@pytest.mark.asyncio
async def test_cancel_expires_pending_approval_and_is_idempotent(cancellation_store) -> None:
    run_id = uuid.uuid4()
    async with cancellation_store() as session:
        session.add(
            AgentRun(
                id=run_id,
                organization_id=ORG_ID,
                thread_id=str(uuid.uuid4()),
                graph="multi_agent",
                status="running",
            )
        )
        session.add(
            Approval(
                id=uuid.uuid4(),
                organization_id=ORG_ID,
                assessment_id=uuid.uuid4(),
                agent_run_id=run_id,
                kind="high_risk_tool",
                decision="pending",
                prompt="Approve action",
                requested_payload={},
                approved_payload={},
                risk_level="high",
            )
        )
        await session.commit()
    async with cancellation_store() as session:
        first = await cancel_agent_run(session, ORG_ID, run_id)
        second = await cancel_agent_run(session, ORG_ID, run_id)
        await session.commit()
        assert first is not None and second is not None
    async with cancellation_store() as session:
        run = await session.get(AgentRun, run_id)
        approval = (await session.execute(select(Approval))).scalar_one()
        assert run is not None and run.status == "cancelled"
        assert approval.decision == "expired"
        assert approval.resolution_note == "Run cancelled before approval execution."


@pytest.mark.asyncio
async def test_other_tenant_cannot_cancel_run(cancellation_store) -> None:
    run_id = uuid.uuid4()
    async with cancellation_store() as session:
        session.add(
            AgentRun(
                id=run_id,
                organization_id=ORG_ID,
                thread_id=str(uuid.uuid4()),
                graph="multi_agent",
                status="running",
            )
        )
        await session.commit()
    async with cancellation_store() as session:
        assert await cancel_agent_run(session, uuid.uuid4(), run_id) is None
