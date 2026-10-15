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
from app.db.models.knowledge import KnowledgeCollection
from app.graphql.ids import encode_global_id
from app.graphql.schema import schema
from app.services.context import ACTOR_API_KEY, Principal


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
        KnowledgeCollection,
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
    agent { id name versionCount activeVersionId isEnabled }
    clientMutationId
  }
}"""

CREATE_AGENT_VERSION = """mutation($input: CreateAgentDefinitionVersionInput!) {
  createAgentDefinitionVersion(input: $input) {
    version { id agentDefinitionId version role model maxEstimatedSpendMicros }
    clientMutationId
  }
}"""

DISABLE_AGENT = """mutation($input: DisableAgentDefinitionInput!) {
  disableAgentDefinition(input: $input) {
    agent { id name versionCount isEnabled }
    clientMutationId
  }
}"""

CREATE_KNOWLEDGE_COLLECTION = """mutation($input: CreateKnowledgeCollectionInput!) {
  createKnowledgeCollection(input: $input) {
    collection { id name description retrievalProvider revision isEnabled }
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


async def create_agent(mutation_context):
    result = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": agent_input()},
    )
    assert result.errors is None
    return result.data["createAgentDefinition"]["agent"]


def version_input(agent, *, expected_active_version_id, role="Lead analyst"):
    return {
        "idempotencyKey": "triage-version-2",
        "clientMutationId": "version-request-8",
        "agentDefinitionId": agent["id"],
        "expectedActiveVersionId": expected_active_version_id,
        "role": role,
        "instructions": "Correlate findings and require supporting evidence.",
        "provider": "anthropic",
        "model": "claude-sonnet-4-5",
        "autonomyMode": "bounded",
        "maxEstimatedSpendMicros": "2500000",
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


@pytest.mark.asyncio
async def test_replay_rechecks_current_permission(mutation_context):
    from app.graphql.context import GraphQLContext

    created = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": agent_input()},
    )
    revoked_context = GraphQLContext(
        mutation_context.principal.downgraded_to(Role.VIEWER),
        mutation_context.settings,
        mutation_context.session_factory,
    )
    replay = await schema.execute(
        CREATE_AGENT,
        context_value=revoked_context,
        variable_values={"input": agent_input()},
    )
    assert created.errors is None
    assert replay.errors[0].extensions["code"] == "PERMISSION_DENIED"


@pytest.mark.asyncio
async def test_api_keys_have_independent_idempotency_namespaces(mutation_context):
    from app.graphql.context import GraphQLContext

    first_context = GraphQLContext(
        Principal(
            user_id=None,
            organization_id=mutation_context.principal.organization_id,
            role=Role.OWNER,
            actor_type=ACTOR_API_KEY,
            credential_id=uuid.uuid4(),
        ),
        mutation_context.settings,
        mutation_context.session_factory,
    )
    second_context = GraphQLContext(
        Principal(
            user_id=None,
            organization_id=mutation_context.principal.organization_id,
            role=Role.OWNER,
            actor_type=ACTOR_API_KEY,
            credential_id=uuid.uuid4(),
        ),
        mutation_context.settings,
        mutation_context.session_factory,
    )
    first = await schema.execute(
        CREATE_AGENT,
        context_value=first_context,
        variable_values={"input": agent_input(name="First key agent")},
    )
    second = await schema.execute(
        CREATE_AGENT,
        context_value=second_context,
        variable_values={"input": agent_input(name="Second key agent")},
    )
    assert first.errors is None
    assert second.errors is None
    assert first.data != second.data


@pytest.mark.asyncio
async def test_non_object_policy_is_bad_user_input(mutation_context):
    payload = agent_input()
    payload["scopePolicy"] = "not-an-object"
    result = await schema.execute(
        CREATE_AGENT,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    assert result.errors[0].extensions["code"] == "BAD_USER_INPUT"


@pytest.mark.asyncio
async def test_retrying_create_agent_version_returns_one_immutable_version(mutation_context):
    agent = await create_agent(mutation_context)
    first_version_id = agent["activeVersionId"]
    payload = version_input(agent, expected_active_version_id=first_version_id)

    first = await schema.execute(
        CREATE_AGENT_VERSION,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    replay = await schema.execute(
        CREATE_AGENT_VERSION,
        context_value=mutation_context,
        variable_values={"input": payload},
    )

    assert first.errors is None
    assert replay.errors is None
    assert replay.data == first.data
    result = first.data["createAgentDefinitionVersion"]
    assert result["clientMutationId"] == "version-request-8"
    assert result["version"]["agentDefinitionId"] == agent["id"]
    assert result["version"]["version"] == 2
    assert result["version"]["role"] == "Lead analyst"
    assert result["version"]["maxEstimatedSpendMicros"] == "2500000"

    async with mutation_context.session_factory() as session:
        versions = list((await session.scalars(select(AgentDefinitionVersion))).all())
        audits = list((await session.scalars(select(AuditEvent))).all())
        stored_agent = await session.scalar(select(AgentDefinition))
    assert len(versions) == 2
    assert len(audits) == 2
    assert stored_agent.version_count == 2
    assert result["version"]["id"] == encode_global_id(
        "AgentDefinitionVersion", stored_agent.active_version_id
    )


@pytest.mark.asyncio
async def test_create_agent_version_rejects_a_stale_active_version(mutation_context):
    agent = await create_agent(mutation_context)
    payload = version_input(
        agent,
        expected_active_version_id=agent["activeVersionId"],
    )
    created = await schema.execute(
        CREATE_AGENT_VERSION,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    stale_payload = version_input(
        agent,
        expected_active_version_id=agent["activeVersionId"],
        role="Stale configuration",
    )
    stale_payload["idempotencyKey"] = "stale-version-request"
    stale = await schema.execute(
        CREATE_AGENT_VERSION,
        context_value=mutation_context,
        variable_values={"input": stale_payload},
    )

    assert created.errors is None
    assert stale.errors[0].extensions["code"] == "CONFLICT"
    async with mutation_context.session_factory() as session:
        assert len(list((await session.scalars(select(AgentDefinitionVersion))).all())) == 2


@pytest.mark.asyncio
async def test_retrying_disable_agent_returns_one_effect_and_rechecks_permission(
    mutation_context,
):
    from app.graphql.context import GraphQLContext

    agent = await create_agent(mutation_context)
    payload = {
        "idempotencyKey": "disable-triage-v1",
        "clientMutationId": "disable-request-9",
        "agentDefinitionId": agent["id"],
    }
    first = await schema.execute(
        DISABLE_AGENT,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    replay = await schema.execute(
        DISABLE_AGENT,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    revoked_context = GraphQLContext(
        mutation_context.principal.downgraded_to(Role.VIEWER),
        mutation_context.settings,
        mutation_context.session_factory,
    )
    denied_replay = await schema.execute(
        DISABLE_AGENT,
        context_value=revoked_context,
        variable_values={"input": payload},
    )

    assert first.errors is None
    assert replay.errors is None
    assert replay.data == first.data
    assert first.data["disableAgentDefinition"]["agent"]["isEnabled"] is False
    assert denied_replay.errors[0].extensions["code"] == "PERMISSION_DENIED"
    async with mutation_context.session_factory() as session:
        audits = list((await session.scalars(select(AuditEvent))).all())
    assert len(audits) == 2


@pytest.mark.asyncio
async def test_retrying_create_knowledge_collection_returns_one_effect(mutation_context):
    payload = {
        "idempotencyKey": "create-incident-runbooks-v1",
        "clientMutationId": "collection-request-10",
        "name": "Incident runbooks",
        "description": "Approved response procedures",
        "retrievalProvider": "internal",
        "retrievalPolicy": {
            "embedding": {"provider": "openai", "model": "text-embedding-3-small"}
        },
    }
    first = await schema.execute(
        CREATE_KNOWLEDGE_COLLECTION,
        context_value=mutation_context,
        variable_values={"input": payload},
    )
    replay = await schema.execute(
        CREATE_KNOWLEDGE_COLLECTION,
        context_value=mutation_context,
        variable_values={"input": payload},
    )

    assert first.errors is None
    assert replay.errors is None
    assert replay.data == first.data
    result = first.data["createKnowledgeCollection"]
    assert result["clientMutationId"] == "collection-request-10"
    assert {key: value for key, value in result["collection"].items() if key != "id"} == {
        "name": "Incident runbooks",
        "description": "Approved response procedures",
        "retrievalProvider": "internal",
        "revision": 1,
        "isEnabled": True,
    }
    async with mutation_context.session_factory() as session:
        collections = list((await session.scalars(select(KnowledgeCollection))).all())
        audits = list((await session.scalars(select(AuditEvent))).all())
    assert len(collections) == 1
    assert len(audits) == 1
    assert result["collection"]["id"] == encode_global_id(
        "KnowledgeCollection", collections[0].id
    )


@pytest.mark.asyncio
async def test_create_knowledge_collection_rejects_non_object_policy(mutation_context):
    result = await schema.execute(
        CREATE_KNOWLEDGE_COLLECTION,
        context_value=mutation_context,
        variable_values={
            "input": {
                "idempotencyKey": "invalid-collection",
                "clientMutationId": "invalid-collection-request",
                "name": "Invalid",
                "retrievalPolicy": ["not", "an", "object"],
            }
        },
    )
    assert result.errors[0].extensions["code"] == "BAD_USER_INPUT"
    async with mutation_context.session_factory() as session:
        assert list((await session.scalars(select(KnowledgeCollection))).all()) == []
