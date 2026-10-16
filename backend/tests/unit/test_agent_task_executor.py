"""Lease fencing, retry idempotency, and durable task settlement."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.agent_task import (
    AgentEvidence,
    AgentTask,
    AgentTaskAttempt,
    AgentTaskDependency,
)
from app.services.agent_task_executor import (
    TaskEvidenceRecord,
    TaskExecutionResult,
    claim_task,
    execute_task,
    recover_stale_tasks,
    settle_task,
)
from app.worker.protocol import RunAction, RunRequest

ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")


def test_task_request_round_trip_binds_the_task_id_without_a_principal() -> None:
    run_id = uuid.uuid4()
    task_id = uuid.uuid4()

    request = RunRequest.new(run_id, RunAction.TASK, task_id=task_id)

    assert RunRequest.from_fields(request.to_fields()) == request
    with pytest.raises(ValueError):
        RunRequest.new(run_id, RunAction.TASK)


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
async def executor_store():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (
        AgentRun,
        AgentTask,
        AgentTaskDependency,
        AgentTaskAttempt,
        AgentEvidence,
        RunDispatch,
    ):
        _copy_table(model, metadata)
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


async def _seed_task(factory, *, max_attempts: int = 3) -> AgentTask:
    async with factory() as session:
        run = AgentRun(
            id=uuid.uuid4(),
            organization_id=ORG_ID,
            thread_id=str(uuid.uuid4()),
            graph="multi_agent",
            status="running",
        )
        task = AgentTask(
            id=uuid.uuid4(),
            organization_id=ORG_ID,
            run_id=run.id,
            task_key="execute",
            kind="decision",
            status="ready",
            idempotency_key=f"task:{uuid.uuid4()}",
            payload_digest="a" * 64,
            tool_version=1,
            input_schema_version="v1",
            output_schema_version="v1",
            input_payload={"objective": "inspect"},
            orchestration={},
            output_summary={},
            required=True,
            plan_index=0,
            priority=100,
            attempt_count=0,
            max_attempts=max_attempts,
            current_lease_generation=0,
        )
        session.add_all([run, task])
        await session.commit()
        return task


@pytest.mark.asyncio
async def test_old_lease_cannot_settle_after_reclaim(executor_store) -> None:
    task = await _seed_task(executor_store)
    async with executor_store() as session:
        first = await claim_task(session, ORG_ID, task.id, worker_id="worker-one", lease_seconds=1)
        assert first is not None
        await session.commit()
    async with executor_store() as session:
        recovered = await recover_stale_tasks(
            session, ORG_ID, now=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=2)
        )
        assert [item.id for item in recovered] == [task.id]
        await session.commit()
    async with executor_store() as session:
        second = await claim_task(session, ORG_ID, task.id, worker_id="worker-two")
        assert second is not None
        assert second.generation == first.generation + 1
        await session.commit()

    result = TaskExecutionResult(status="completed", output_summary={"ok": True})
    async with executor_store() as session:
        assert await settle_task(session, first, result) is False
        await session.rollback()
    async with executor_store() as session:
        assert await settle_task(session, second, result) is True
        await session.commit()


@pytest.mark.asyncio
async def test_provider_success_before_crash_is_not_duplicated(executor_store) -> None:
    task = await _seed_task(executor_store)
    provider_results: dict[str, str] = {}
    mutation_count = 0
    crash_once = True

    class SimulatedWorkerCrash(BaseException):
        pass

    async def handler(claim):
        nonlocal mutation_count, crash_once
        if claim.idempotency_key not in provider_results:
            mutation_count += 1
            provider_results[claim.idempotency_key] = "provider-receipt"
        if crash_once:
            crash_once = False
            raise SimulatedWorkerCrash()
        return TaskExecutionResult(
            status="completed",
            output_summary={"receipt": provider_results[claim.idempotency_key]},
        )

    with pytest.raises(SimulatedWorkerCrash):
        await execute_task(
            ORG_ID,
            task.id,
            executor_store,
            handler,
            worker_id="worker-one",
            lease_seconds=1,
        )
    async with executor_store() as session:
        await recover_stale_tasks(
            session, ORG_ID, now=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=2)
        )
        await session.commit()

    assert await execute_task(
        ORG_ID,
        task.id,
        executor_store,
        handler,
        worker_id="worker-two",
    )
    assert mutation_count == 1
    async with executor_store() as session:
        settled = await session.get(AgentTask, task.id)
        assert settled is not None
        assert settled.status == "completed"
        assert settled.output_summary == {"receipt": "provider-receipt"}


@pytest.mark.asyncio
async def test_settlement_persists_bounded_evidence_and_usage(executor_store) -> None:
    task = await _seed_task(executor_store)
    async with executor_store() as session:
        claim = await claim_task(session, ORG_ID, task.id, worker_id="worker-one")
        assert claim is not None
        await session.commit()
    result = TaskExecutionResult(
        status="degraded",
        output_summary={"summary": "partial"},
        usage={"input_tokens": 12, "output_tokens": 4},
        evidence=(
            TaskEvidenceRecord(
                key="receipt",
                kind="provider_receipt",
                artifact_reference="gs://bucket/receipt.json",
                content_digest="b" * 64,
                verified=True,
            ),
        ),
    )
    async with executor_store() as session:
        assert await settle_task(session, claim, result)
        await session.commit()
    async with executor_store() as session:
        evidence = (await session.execute(select(AgentEvidence))).scalar_one()
        attempt = (await session.execute(select(AgentTaskAttempt))).scalar_one()
        assert evidence.evidence_key == "receipt"
        assert evidence.verified is True
        assert attempt.usage == {"input_tokens": 12, "output_tokens": 4}


@pytest.mark.asyncio
async def test_exhausted_stale_task_fails_without_redispatch(executor_store) -> None:
    task = await _seed_task(executor_store, max_attempts=1)
    async with executor_store() as session:
        assert await claim_task(session, ORG_ID, task.id, worker_id="worker-one", lease_seconds=1)
        await session.commit()
    async with executor_store() as session:
        assert (
            await recover_stale_tasks(
                session, ORG_ID, now=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=2)
            )
            == []
        )
        await session.commit()
    async with executor_store() as session:
        failed = await session.get(AgentTask, task.id)
        assert failed is not None
        assert failed.status == "failed"
        assert failed.failure_code == "task_attempts_exhausted"
        assert (await session.execute(select(RunDispatch))).scalars().all() == []
