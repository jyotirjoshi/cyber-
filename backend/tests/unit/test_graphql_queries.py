"""Exercise resolver SQL against a local database, without cloud/provider calls."""
import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition
from app.db.models.knowledge import KnowledgeCollection
from app.graphql.schema import schema
from app.services.context import Principal


@pytest.fixture
async def query_context():
    from app.graphql.context import GraphQLContext

    engine = create_async_engine("sqlite+aiosqlite://")
    # Same column types, but without PostgreSQL-only DDL/foreign-key targets. This
    # checks the real resolver's predicates and keyset traversal, not migrations.
    metadata = MetaData()
    for model in (AgentDefinition, KnowledgeCollection):
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
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    principal = Principal.for_api_key(
        organization_id=uuid.uuid4(),
        scopes=frozenset({Permission.AGENT_CHAT}),
        request_id="query-test",
    )
    context = GraphQLContext(
        principal, Settings(_env_file=None, security={"jwt_secret": "s" * 32}), factory
    )
    async with factory() as session:
        for i, name in enumerate(("A", "B", "C"), 1):
            session.add(
                AgentDefinition(
                    id=uuid.UUID(int=i),
                    organization_id=principal.organization_id,
                    name=name,
                    is_enabled=True,
                    version_count=0,
                )
            )
        session.add(
            AgentDefinition(
                id=uuid.UUID(int=4),
                organization_id=uuid.uuid4(),
                name="Other tenant",
                is_enabled=True,
                version_count=0,
            )
        )
        session.add(
            KnowledgeCollection(
                id=uuid.UUID(int=5),
                organization_id=principal.organization_id,
                name="Runbooks",
                retrieval_provider="internal",
                retrieval_policy={},
                is_enabled=True,
                revision=1,
            )
        )
        await session.commit()
    try:
        yield context
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_agent_connection_traverses_without_duplicates_or_other_tenants(query_context):
    query = """query($after: String) { agentDefinitions(first: 2, after: $after) {
      nodes { id name } pageInfo { hasNextPage endCursor } } }"""
    first = await schema.execute(query, context_value=query_context)
    assert first.errors is None
    page = first.data["agentDefinitions"]
    assert [n["name"] for n in page["nodes"]] == ["A", "B"]
    assert page["pageInfo"]["hasNextPage"] is True
    second = await schema.execute(
        query, context_value=query_context, variable_values={"after": page["pageInfo"]["endCursor"]}
    )
    assert second.errors is None
    assert [n["name"] for n in second.data["agentDefinitions"]["nodes"]] == ["C"]
    assert second.data["agentDefinitions"]["pageInfo"]["hasNextPage"] is False


@pytest.mark.asyncio
async def test_foreign_and_missing_agent_have_identical_results(query_context):
    from app.graphql.ids import encode_global_id

    query = "query($id: ID!) { agentDefinition(id: $id) { name } }"
    for identifier in (uuid.UUID(int=4), uuid.UUID(int=999)):
        result = await schema.execute(
            query,
            context_value=query_context,
            variable_values={"id": encode_global_id("AgentDefinition", identifier)},
        )
        assert result.errors is None
        assert result.data == {"agentDefinition": None}


@pytest.mark.asyncio
async def test_knowledge_collection_queries_and_disabled_capabilities(query_context):
    result = await schema.execute(
        "{ knowledgeCollections { nodes { name retrievalProvider } } }", context_value=query_context
    )
    assert result.errors is None
    assert result.data["knowledgeCollections"]["nodes"] == [
        {"name": "Runbooks", "retrievalProvider": "internal"}
    ]
    query_context.settings.features.internal_knowledge = False
    result = await schema.execute(
        "{ system { capabilities } knowledgeCollections { nodes { name } } }",
        context_value=query_context,
    )
    assert result.errors[0].extensions["code"] == "RESOURCE_NOT_FOUND"
    system = await schema.execute("{ system { capabilities } }", context_value=query_context)
    assert "internal-knowledge" not in system.data["system"]["capabilities"]


@pytest.mark.asyncio
async def test_scoped_key_requires_agent_permission(query_context):
    query_context.principal = Principal.for_api_key(
        organization_id=query_context.principal.organization_id, scopes=frozenset()
    )
    result = await schema.execute(
        "{ agentDefinitions { nodes { name } } }", context_value=query_context
    )
    assert result.errors[0].extensions["code"] == "PERMISSION_DENIED"


@pytest.mark.asyncio
async def test_resolver_errors_never_leak_provider_or_database_details(query_context, caplog):
    @asynccontextmanager
    async def broken():
        raise RuntimeError("postgres://secret@internal.example")
        yield

    query_context.session_factory = broken
    result = await schema.execute(
        "{ agentDefinitions { nodes { name } } }", context_value=query_context
    )
    assert result.errors[0].extensions == {
        "code": "INTERNAL_ERROR",
        "retryable": False,
        "requestId": "query-test",
    }
    assert "secret" not in str(result.errors)
    assert "postgres://secret" not in caplog.text


@pytest.mark.asyncio
async def test_missing_context_and_oversized_pages_are_rejected(query_context):
    result = await schema.execute("{ agentDefinitions { nodes { name } } }")
    assert result.errors[0].extensions["code"] == "UNAUTHENTICATED"
    result = await schema.execute(
        "{ agentDefinitions(first: 101) { nodes { name } } }", context_value=query_context
    )
    assert result.errors[0].extensions["code"] == "INVALID_PAGE_SIZE"
