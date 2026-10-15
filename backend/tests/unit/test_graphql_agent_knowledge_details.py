"""Detailed agent and knowledge projections remain tenant safe and secret free."""
import datetime as dt
import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition, AgentDefinitionVersion
from app.db.models.knowledge import KnowledgeCollection, KnowledgeSource
from app.graphql.ids import encode_global_id
from app.graphql.schema import schema
from app.services.context import Principal


@pytest.fixture
async def detailed_context():
    from app.graphql.context import GraphQLContext

    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (AgentDefinition, AgentDefinitionVersion, KnowledgeCollection, KnowledgeSource):
        Table(
            model.__tablename__,
            metadata,
            *[
                Column(
                    c.name,
                    JSON()
                    if isinstance(c.type, JSONB)
                    else Uuid()
                    if isinstance(c.type, Uuid)
                    else c.type,
                    primary_key=c.primary_key,
                    nullable=c.nullable,
                    server_default=c.server_default,
                )
                for c in model.__table__.columns
            ],
        )
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    principal = Principal.for_api_key(
        organization_id=uuid.uuid4(),
        scopes=frozenset({Permission.AGENT_CHAT}),
        request_id="detail-test",
    )
    agent_id, collection_id = uuid.uuid4(), uuid.uuid4()
    now = dt.datetime.now(dt.UTC)
    async with factory() as session:
        session.add(
            AgentDefinition(
                id=agent_id,
                organization_id=principal.organization_id,
                name="Triage",
                is_enabled=True,
                version_count=2,
            )
        )
        for number in (1, 2):
            session.add(
                AgentDefinitionVersion(
                    id=uuid.uuid4(),
                    organization_id=principal.organization_id,
                    agent_definition_id=agent_id,
                    version=number,
                    role="Analyst",
                    instructions="Use evidence",
                    provider="openai",
                    model="model",
                    autonomy_mode="supervised",
                    temperature=0,
                    max_output_tokens=1000,
                    max_parallel_tasks=2,
                    max_runtime_seconds=300,
                    max_tool_calls=5,
                    max_input_tokens=10000,
                    max_estimated_spend_micros=1000,
                    scope_policy={},
                    retrieval_policy={},
                    configuration_digest=str(number) * 64,
                )
            )
        session.add(
            KnowledgeCollection(
                id=collection_id,
                organization_id=principal.organization_id,
                name="Runbooks",
                retrieval_provider="internal",
                retrieval_policy={},
                is_enabled=True,
                revision=1,
            )
        )
        session.add(
            KnowledgeSource(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                collection_id=collection_id,
                source_type="upload",
                filename="response.md",
                title="Response",
                object_key="tenant/secret-storage-key",
                mime_type="text/markdown",
                content_hash="a" * 64,
                size_bytes=100,
                status="ready",
                document_metadata={},
                current_revision=1,
                lease_generation=0,
                index_attempts=0,
                indexed_chunks=1,
                total_chunks=1,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    try:
        yield (
            GraphQLContext(
                principal, Settings(_env_file=None, security={"jwt_secret": "s" * 32}), factory
            ),
            agent_id,
            collection_id,
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_versions_are_descending_and_exclude_instructions_and_scope_policy(detailed_context):
    context, agent_id, _ = detailed_context
    query = """query($id: ID!) { agentDefinitionVersions(agentDefinitionId: $id) {
      nodes { id version role provider model autonomyMode maxParallelTasks }
      pageInfo { hasNextPage endCursor } } }"""
    result = await schema.execute(
        query,
        context_value=context,
        variable_values={"id": encode_global_id("AgentDefinition", agent_id)},
    )
    assert result.errors is None
    assert [row["version"] for row in result.data["agentDefinitionVersions"]["nodes"]] == [2, 1]
    assert "instructions" not in result.data["agentDefinitionVersions"]["nodes"][0]


@pytest.mark.asyncio
async def test_sources_exclude_object_keys_and_enforce_parent_tenant(detailed_context):
    context, _, collection_id = detailed_context
    query = """query($id: ID!) { knowledgeSources(collectionId: $id) {
      nodes { id filename title mimeType contentHash sizeBytes status indexedChunks totalChunks }
      pageInfo { hasNextPage } } }"""
    result = await schema.execute(
        query,
        context_value=context,
        variable_values={"id": encode_global_id("KnowledgeCollection", collection_id)},
    )
    assert result.errors is None
    assert result.data["knowledgeSources"]["nodes"][0]["filename"] == "response.md"
    assert "objectKey" not in str(schema)
    foreign = await schema.execute(
        query,
        context_value=context,
        variable_values={"id": encode_global_id("KnowledgeCollection", uuid.uuid4())},
    )
    assert foreign.errors[0].extensions["code"] == "RESOURCE_NOT_FOUND"


@pytest.mark.asyncio
async def test_tool_catalog_is_filtered_by_machine_scope(detailed_context):
    context, _, _ = detailed_context
    result = await schema.execute(
        "{ agentTools { name permission permitted sideEffect approval } }", context_value=context
    )
    assert result.errors is None
    assert result.data["agentTools"]
    assert all(
        tool["permitted"] == (tool["permission"] == "agent:chat")
        for tool in result.data["agentTools"]
    )
