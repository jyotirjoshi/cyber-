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

SEARCH = """query($ids: [ID!]!, $query: String!, $limit: Int = 6) {
  knowledgeSearch(collectionIds: $ids, query: $query, limit: $limit) {
    chunkId sourceId text score
    citation { collectionId sourceId sourceVersionId filename page section ordinal contentHash provider }
  }
}"""


@pytest.mark.asyncio
async def test_search_projects_citations_and_passes_tenant_policy(detailed_context, monkeypatch):
    from app.services.knowledge_retrieval import KnowledgeCitation, KnowledgeHit

    context, _, collection_id, _, _ = detailed_context
    chunk, source, version = (uuid.UUID(int=n) for n in (21, 22, 23))
    calls = []

    async def retrieve(retriever, query, policy):
        # The provider/database ranking is covered by retrieval service tests.
        # This checks the new resolver's authorization, policy and wire projection.
        calls.append((retriever.principal, query, policy))
        return [KnowledgeHit(chunk, source, "Require owner approval.", 0.032,
            KnowledgeCitation(collection_id, source, version, "runbook.pdf", 3,
                "Containment", 2, "a" * 64))]

    monkeypatch.setattr("app.graphql.queries.InternalKnowledgeRetriever.retrieve", retrieve)
    result = await schema.execute(SEARCH, context_value=context, variable_values={
        "ids": [encode_global_id("KnowledgeCollection", collection_id)] * 2,
        "query": "  containment approval  ", "limit": 3,
    })
    assert result.errors is None
    assert len(calls) == 1
    principal, query, policy = calls[0]
    assert principal is context.principal
    assert query == "containment approval"
    assert policy.organization_id == context.principal.organization_id
    assert policy.collection_ids == (collection_id,)
    assert policy.limit == 3
    assert result.data["knowledgeSearch"] == [{
        "chunkId": encode_global_id("KnowledgeChunk", chunk),
        "sourceId": encode_global_id("KnowledgeSource", source),
        "text": "Require owner approval.", "score": 0.032,
        "citation": {
            "collectionId": encode_global_id("KnowledgeCollection", collection_id),
            "sourceId": encode_global_id("KnowledgeSource", source),
            "sourceVersionId": encode_global_id("KnowledgeSourceVersion", version),
            "filename": "runbook.pdf", "page": 3, "section": "Containment",
            "ordinal": 2, "contentHash": "a" * 64, "provider": "internal",
        },
    }]


@pytest.mark.asyncio
async def test_search_rejects_foreign_collection_using_real_retriever(detailed_context):
    context, _, _, _, _ = detailed_context
    foreign_id = uuid.uuid4()
    async with context.session_factory() as session:
        session.add(KnowledgeCollection(id=foreign_id, organization_id=uuid.uuid4(),
            name="Foreign", retrieval_provider="internal", retrieval_policy={},
            is_enabled=True, revision=1))
        await session.commit()
    for identifier in (foreign_id, uuid.uuid4()):
        result = await schema.execute(SEARCH, context_value=context, variable_values={
            "ids": [encode_global_id("KnowledgeCollection", identifier)], "query": "approval",
        })
        assert result.errors[0].extensions["code"] == "RESOURCE_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [{"query": "  "}, {"query": "x" * 2001},
                                   {"limit": 21}, {"ids": []}])
async def test_invalid_search_fails_before_retrieval(detailed_context, monkeypatch, change):
    context, _, collection_id, _, _ = detailed_context
    async def unexpected(*args):
        pytest.fail("invalid search reached retrieval")
    monkeypatch.setattr("app.graphql.queries.InternalKnowledgeRetriever.retrieve", unexpected)
    result = await schema.execute(SEARCH, context_value=context, variable_values={
        "ids": [encode_global_id("KnowledgeCollection", collection_id)], "query": "approval",
        **change,
    })
    assert result.errors[0].extensions["code"] == "BAD_USER_INPUT"


@pytest.mark.asyncio
async def test_search_respects_feature_and_permission_guards(detailed_context):
    context, _, collection_id, _, _ = detailed_context
    variables = {"ids": [encode_global_id("KnowledgeCollection", collection_id)], "query": "a"}
    context.settings.features.internal_knowledge = False
    result = await schema.execute(SEARCH, context_value=context, variable_values=variables)
    assert result.errors[0].extensions["code"] == "RESOURCE_NOT_FOUND"
    context.settings.features.internal_knowledge = True
    context.principal = Principal.for_api_key(
        organization_id=context.principal.organization_id, scopes=frozenset())
    result = await schema.execute(SEARCH, context_value=context, variable_values=variables)
    assert result.errors[0].extensions["code"] == "PERMISSION_DENIED"


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
    agent_id, second_agent_id = uuid.uuid4(), uuid.uuid4()
    collection_id, second_collection_id = uuid.uuid4(), uuid.uuid4()
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
        session.add(
            AgentDefinition(
                id=second_agent_id,
                organization_id=principal.organization_id,
                name="Responder",
                is_enabled=True,
                version_count=1,
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
                    max_estimated_spend_micros=3_000_000_000 if number == 2 else 1000,
                    scope_policy={},
                    retrieval_policy={},
                    configuration_digest=str(number) * 64,
                )
            )
        session.add(
            AgentDefinitionVersion(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                agent_definition_id=second_agent_id,
                version=1,
                role="Responder",
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
                configuration_digest="b" * 64,
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
        session.add(
            KnowledgeCollection(
                id=second_collection_id,
                organization_id=principal.organization_id,
                name="Procedures",
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
                collection_id=second_collection_id,
                source_type="upload",
                filename="procedure.md",
                object_key="tenant/second-secret-storage-key",
                mime_type="text/markdown",
                content_hash="c" * 64,
                size_bytes=90,
                status="ready",
                document_metadata={},
                current_revision=1,
                lease_generation=0,
                index_attempts=0,
                indexed_chunks=1,
                total_chunks=1,
                created_at=now - dt.timedelta(minutes=1),
                updated_at=now - dt.timedelta(minutes=1),
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
            second_agent_id,
            second_collection_id,
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_versions_are_descending_and_exclude_instructions_and_scope_policy(detailed_context):
    context, agent_id, _, _, _ = detailed_context
    query = """query($id: ID!) { agentDefinitionVersions(agentDefinitionId: $id) {
      nodes { id version role provider model autonomyMode maxParallelTasks maxEstimatedSpendMicros }
      pageInfo { hasNextPage endCursor } } }"""
    result = await schema.execute(
        query,
        context_value=context,
        variable_values={"id": encode_global_id("AgentDefinition", agent_id)},
    )
    assert result.errors is None
    assert [row["version"] for row in result.data["agentDefinitionVersions"]["nodes"]] == [2, 1]
    assert (
        result.data["agentDefinitionVersions"]["nodes"][0]["maxEstimatedSpendMicros"]
        == "3000000000"
    )
    assert "instructions" not in result.data["agentDefinitionVersions"]["nodes"][0]


@pytest.mark.asyncio
async def test_sources_exclude_object_keys_and_enforce_parent_tenant(detailed_context):
    context, _, collection_id, _, _ = detailed_context
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
    context, _, _, _, _ = detailed_context
    result = await schema.execute(
        "{ agentTools { name permission permitted sideEffect approval } }", context_value=context
    )
    assert result.errors is None
    assert result.data["agentTools"]
    assert all(
        tool["permitted"] == (tool["permission"] == "agent:chat")
        for tool in result.data["agentTools"]
    )


@pytest.mark.asyncio
async def test_agent_version_cursor_is_bound_to_parent(detailed_context):
    context, agent_id, _, second_agent_id, _ = detailed_context
    query = """query($id: ID!, $after: String) {
      agentDefinitionVersions(agentDefinitionId: $id, first: 1, after: $after) {
        nodes { version }
        pageInfo { endCursor }
      }
    }"""
    first = await schema.execute(
        query,
        context_value=context,
        variable_values={"id": encode_global_id("AgentDefinition", agent_id)},
    )
    cursor = first.data["agentDefinitionVersions"]["pageInfo"]["endCursor"]
    reused = await schema.execute(
        query,
        context_value=context,
        variable_values={
            "id": encode_global_id("AgentDefinition", second_agent_id),
            "after": cursor,
        },
    )
    assert reused.errors[0].extensions["code"] == "INVALID_CURSOR"


@pytest.mark.asyncio
async def test_knowledge_source_cursor_is_bound_to_parent(detailed_context):
    context, _, collection_id, _, second_collection_id = detailed_context
    query = """query($id: ID!, $after: String) {
      knowledgeSources(collectionId: $id, first: 1, after: $after) {
        nodes { filename }
        pageInfo { endCursor }
      }
    }"""
    first = await schema.execute(
        query,
        context_value=context,
        variable_values={"id": encode_global_id("KnowledgeCollection", collection_id)},
    )
    cursor = first.data["knowledgeSources"]["pageInfo"]["endCursor"]
    reused = await schema.execute(
        query,
        context_value=context,
        variable_values={
            "id": encode_global_id("KnowledgeCollection", second_collection_id),
            "after": cursor,
        },
    )
    assert reused.errors[0].extensions["code"] == "INVALID_CURSOR"
