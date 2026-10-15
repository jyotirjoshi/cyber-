"""Agent GraphQL mutations are tenant scoped and retry safe."""

import uuid

import pytest
from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    Uuid,
    func,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.enums import Role
from app.db.models.agent_definition import (
    AgentDefinition,
    AgentDefinitionVersion,
    AgentVersionCollection,
    AgentVersionTool,
)
from app.db.models.audit import AuditEvent
from app.graphql.schema import schema
from app.services.context import Principal


@pytest.fixture
async def mutation_context():
    from app.graphql.context import GraphQLContext

    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (
        AgentDefinition,
        AgentDefinitionVersion,
        AgentVersionCollection,
        AgentVersionTool,
        AuditEvent,
    ):
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
                    server_default=column.server_default,
                )
                for column in model.__table__.columns
            ],
        )
    Table(
        "graphql_mutation_receipts",
        metadata,
        Column("id", Uuid(), primary_key=True),
        Column("organization_id", Uuid(), nullable=False),
        Column("actor_key", String(80), nullable=False),
        Column("operation", String(120), nullable=False),
        Column("idempotency_key", String(160), nullable=False),
        Column("input_digest", String(64), nullable=False),
        Column("resource_type", String(80)),
        Column("resource_id", Uuid()),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        UniqueConstraint(
            "organization_id",
            "actor_key",
            "operation",
            "idempotency_key",
            name="unique_graphql_mutation_receipt",
        ),
    )
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=Role.OWNER,
        request_id="mutation-test",
    )
    try:
        yield GraphQLContext(
            principal,
            Settings(_env_file=None, security={"jwt_secret": "s" * 32}),
            factory,
        )
    finally:
        await engine.dispose()


CREATE_AGENT = """mutation($input: CreateAgentDefinitionInput!) {
  createAgentDefinition(input: $input) {
    agent { id name versionCount isEnabled }
    clientMutationId
  }
}"""


def agent_input(*, name="Triage"):
    return {
        "idempotencyKey": "create-triage-v1",
        "clientMutationId": "browser-request-7",
        "name": name,
        "role": "Security analyst",
        "instructions": "Triage findings using evidence.",
        "provider": "openai",
        "model": "gpt-5-mini",
        "autonomyMode": "supervised",
    }


@pytest.mark.asyncio
async def test_retrying_create_agent_returns_one_effect(mutation_context):
    first = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": agent_input()},
    )
    second = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": agent_input()},
    )
    assert first.errors is None
    assert second.errors is None
    assert first.data == second.data
    assert first.data["createAgentDefinition"]["clientMutationId"] == "browser-request-7"

    async with mutation_context.session_factory() as session:
        agents = list((await session.scalars(select(AgentDefinition))).all())
        versions = list((await session.scalars(select(AgentDefinitionVersion))).all())
        audits = list((await session.scalars(select(AuditEvent))).all())
    assert len(agents) == len(versions) == len(audits) == 1


@pytest.mark.asyncio
async def test_idempotency_key_reuse_with_different_input_is_rejected(mutation_context):
    first = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": agent_input()},
    )
    conflict = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": agent_input(name="Different")},
    )
    assert first.errors is None
    assert conflict.errors[0].extensions["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_oversized_client_mutation_id_is_rejected_before_write(mutation_context):
    payload = agent_input()
    payload["clientMutationId"] = "x" * 161
    result = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    assert result.errors[0].extensions["code"] == "BAD_USER_INPUT"
    async with mutation_context.session_factory() as session:
        assert list((await session.scalars(select(AgentDefinition))).all()) == []
