"""Exact-payload approval and execution-time authority checks for agent tasks."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.errors import ConflictError, PermissionDeniedError
from app.db.enums import Role
from app.db.models.agent import AgentRun
from app.db.models.agent_definition import AgentDefinitionVersion, AgentVersionTool
from app.db.models.agent_task import AgentTask
from app.db.models.assessment import Approval
from app.db.models.identity import Membership, Organization
from app.services.agent_task_executor import execute_approved_task
from app.services.approval import grant_task_approval, open_task_approval
from app.services.context import Principal

ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")
USER_ID = uuid.UUID("20000000-0000-0000-0000-000000000001")
VERSION_ID = uuid.UUID("30000000-0000-0000-0000-000000000001")


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
async def approval_store():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (
        Organization,
        Membership,
        AgentDefinitionVersion,
        AgentVersionTool,
        AgentRun,
        AgentTask,
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


async def _seed(approval_store) -> tuple[uuid.UUID, uuid.UUID]:
    run_id, task_id = uuid.uuid4(), uuid.uuid4()
    async with approval_store() as session:
        session.add(
            Organization(
                id=ORG_ID,
                name="Acme",
                slug="acme",
                max_concurrent_scanner_jobs=4,
                policy={},
                entitlements={},
                risk_policy_version=0,
                is_active=True,
            )
        )
        session.add(
            Membership(
                id=uuid.uuid4(),
                organization_id=ORG_ID,
                user_id=USER_ID,
                role=Role.OWNER.value,
                is_default=True,
                accepted_at=dt.datetime.now(dt.UTC),
            )
        )
        session.add(
            AgentDefinitionVersion(
                id=VERSION_ID,
                organization_id=ORG_ID,
                agent_definition_id=uuid.uuid4(),
                version=1,
                role="Security operator",
                instructions="Execute approved security operations.",
                provider="test",
                model="test-model",
                autonomy_mode="bounded",
                temperature=0,
                max_output_tokens=1000,
                max_parallel_tasks=2,
                max_runtime_seconds=120,
                max_tool_calls=5,
                max_input_tokens=10_000,
                max_estimated_spend_micros=100_000,
                scope_policy={},
                retrieval_policy={},
                configuration_digest="a" * 64,
                created_by_id=USER_ID,
            )
        )
        session.add(
            AgentVersionTool(
                id=uuid.uuid4(),
                organization_id=ORG_ID,
                agent_version_id=VERSION_ID,
                tool_name="create_jira_ticket",
                tool_version=1,
                approval_mode="always",
                timeout_seconds=60,
                per_run_call_limit=2,
            )
        )
        session.add(
            AgentRun(
                id=run_id,
                organization_id=ORG_ID,
                triggered_by_id=USER_ID,
                thread_id=str(run_id),
                graph="multi_agent",
                status="running",
            )
        )
        session.add(
            AgentTask(
                id=task_id,
                organization_id=ORG_ID,
                run_id=run_id,
                task_key="ticket",
                kind="tool",
                status="awaiting_approval",
                idempotency_key=f"{run_id}:ticket",
                payload_digest="b" * 64,
                tool_name="create_jira_ticket",
                tool_version=1,
                input_schema_version="v1",
                output_schema_version="v1",
                input_payload={"finding_id": str(uuid.uuid4())},
                orchestration={},
                output_summary={},
                required=True,
                plan_index=0,
                priority=100,
                attempt_count=0,
                max_attempts=3,
                current_lease_generation=0,
            )
        )
        await session.commit()
    return run_id, task_id


def _owner() -> Principal:
    return Principal(user_id=USER_ID, organization_id=ORG_ID, role=Role.OWNER)


async def _approve(approval_store, task_id: uuid.UUID) -> uuid.UUID:
    async with approval_store() as session:
        approval = await open_task_approval(
            session,
            ORG_ID,
            task_id,
            agent_version_id=VERSION_ID,
            prompt="Create the remediation ticket?",
        )
        await grant_task_approval(session, _owner(), approval.id)
        await session.commit()
        return approval.id


@pytest.mark.asyncio
async def test_permission_revoked_after_approval_prevents_execution(approval_store) -> None:
    _run_id, task_id = await _seed(approval_store)
    approval_id = await _approve(approval_store, task_id)
    async with approval_store() as session:
        membership = (
            await session.execute(
                select(Membership).where(
                    Membership.organization_id == ORG_ID,
                    Membership.user_id == USER_ID,
                )
            )
        ).scalar_one()
        membership.role = Role.VIEWER.value
        await session.commit()

    calls: list[object] = []

    async def provider(context):
        calls.append(context)
        return {"created": True}

    async with approval_store() as session:
        with pytest.raises(PermissionDeniedError):
            await execute_approved_task(session, ORG_ID, approval_id, provider)
    assert calls == []


@pytest.mark.asyncio
async def test_expired_or_changed_payload_approval_never_calls_provider(approval_store) -> None:
    _run_id, task_id = await _seed(approval_store)
    approval_id = await _approve(approval_store, task_id)
    calls: list[object] = []

    async def provider(context):
        calls.append(context)
        return {"created": True}

    async with approval_store() as session:
        approval = await session.get(Approval, approval_id)
        assert approval is not None
        approval.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        await session.commit()
    async with approval_store() as session:
        with pytest.raises(ConflictError):
            await execute_approved_task(session, ORG_ID, approval_id, provider)

    async with approval_store() as session:
        approval = await session.get(Approval, approval_id)
        task = await session.get(AgentTask, task_id)
        assert approval is not None and task is not None
        approval.expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
        task.input_payload = {"finding_id": str(uuid.uuid4())}
        await session.commit()
    async with approval_store() as session:
        with pytest.raises(ConflictError):
            await execute_approved_task(session, ORG_ID, approval_id, provider)
    assert calls == []


@pytest.mark.asyncio
async def test_changed_organization_policy_prevents_execution(approval_store) -> None:
    _run_id, task_id = await _seed(approval_store)
    approval_id = await _approve(approval_store, task_id)
    async with approval_store() as session:
        organization = await session.get(Organization, ORG_ID)
        assert organization is not None
        organization.policy = {"agent_disabled_tools": ["create_jira_ticket"]}
        await session.commit()

    calls: list[object] = []

    async def provider(context):
        calls.append(context)
        return {"created": True}

    async with approval_store() as session:
        with pytest.raises(PermissionDeniedError):
            await execute_approved_task(session, ORG_ID, approval_id, provider)
    assert calls == []


@pytest.mark.asyncio
async def test_exact_approved_task_executes_once_with_current_authority(approval_store) -> None:
    _run_id, task_id = await _seed(approval_store)
    approval_id = await _approve(approval_store, task_id)
    calls: list[object] = []

    async def provider(context):
        calls.append(context)
        return {"created": True}

    async with approval_store() as session:
        result = await execute_approved_task(session, ORG_ID, approval_id, provider)
        assert result == {"created": True}
    assert len(calls) == 1
    assert calls[0].task_id == task_id
    assert calls[0].tool_name == "create_jira_ticket"
    assert calls[0].principal.user_id == USER_ID
