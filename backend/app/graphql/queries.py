"""Bounded agent/knowledge reads using the same tenant and permission rules as REST."""
import datetime as dt

import strawberry
from sqlalchemy import and_, or_
from strawberry.types import Info

from app.agent.tools.registry import default_tool_registry
from app.api.deps import require_custom_agents, require_internal_knowledge
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition, AgentDefinitionVersion
from app.db.models.knowledge import KnowledgeCollection, KnowledgeSource
from app.db.repository import tenant_select
from app.graphql.context import require_context
from app.graphql.errors import PublicGraphQLError
from app.graphql.ids import decode_global_id
from app.graphql.pagination import CursorCodec, page_size
from app.graphql.types import (
    AgentDefinitionNode,
    AgentDefinitionVersionNode,
    AgentToolNode,
    Connection,
    KnowledgeCollectionNode,
    KnowledgeSourceNode,
    PageInfo,
)


def _authorize(info, guard):
    context = require_context(info)
    context.principal.require(Permission.AGENT_CHAT)
    guard(context.settings)
    return context


async def _connection(context, model, projection, connection, first, after):
    size = page_size(first)
    codec = CursorCodec(
        context.settings.security.jwt_secret.get_secret_value(),
        context.principal.organization_id,
        connection,
    )
    query = tenant_select(model, context.principal.organization_id)
    if after is not None:
        name, identifier = codec.decode(after)
        if not isinstance(name, str):
            raise PublicGraphQLError("INVALID_CURSOR", "Invalid cursor; restart pagination.")
        query = query.where(or_(model.name > name, and_(model.name == name, model.id > identifier)))
    query = query.order_by(model.name, model.id).limit(size + 1)
    async with context.session_factory() as session:
        rows = list((await session.scalars(query)).all())
    page = rows[:size]
    return Connection(
        nodes=[projection.from_row(row) for row in page],
        page_info=PageInfo(
            has_next_page=len(rows) > size,
            end_cursor=codec.encode(page[-1].name, page[-1].id) if page else None,
        ),
    )


async def _node(context, model, projection, type_name, identifier):
    resource_id = decode_global_id(str(identifier), type_name)
    async with context.session_factory() as session:
        row = await session.scalar(
            tenant_select(model, context.principal.organization_id).where(model.id == resource_id)
        )
        return projection.from_row(row) if row else None


@strawberry.type
class AgentKnowledgeQueries:
    @strawberry.field
    async def agent_definitions(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[AgentDefinitionNode]:
        return await _connection(
            _authorize(info, require_custom_agents),
            AgentDefinition,
            AgentDefinitionNode,
            "agentDefinitions",
            first,
            after,
        )

    @strawberry.field
    async def agent_definition(self, info: Info, id: strawberry.ID) -> AgentDefinitionNode | None:
        return await _node(
            _authorize(info, require_custom_agents),
            AgentDefinition,
            AgentDefinitionNode,
            "AgentDefinition",
            id,
        )

    @strawberry.field
    async def knowledge_collections(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[KnowledgeCollectionNode]:
        return await _connection(
            _authorize(info, require_internal_knowledge),
            KnowledgeCollection,
            KnowledgeCollectionNode,
            "knowledgeCollections",
            first,
            after,
        )

    @strawberry.field
    async def knowledge_collection(
        self, info: Info, id: strawberry.ID
    ) -> KnowledgeCollectionNode | None:
        return await _node(
            _authorize(info, require_internal_knowledge),
            KnowledgeCollection,
            KnowledgeCollectionNode,
            "KnowledgeCollection",
            id,
        )

    @strawberry.field
    async def agent_definition_versions(
        self,
        info: Info,
        agent_definition_id: strawberry.ID,
        first: int = 25,
        after: str | None = None,
    ) -> Connection[AgentDefinitionVersionNode]:
        context = _authorize(info, require_custom_agents)
        agent_id = decode_global_id(str(agent_definition_id), "AgentDefinition")
        size = page_size(first)
        codec = CursorCodec(
            context.settings.security.jwt_secret.get_secret_value(),
            context.principal.organization_id,
            "agentDefinitionVersions",
        )
        async with context.session_factory() as session:
            parent = await session.scalar(
                tenant_select(AgentDefinition, context.principal.organization_id).where(
                    AgentDefinition.id == agent_id
                )
            )
            if parent is None:
                raise ResourceNotFoundError("agent definition not found")
            query = tenant_select(AgentDefinitionVersion, context.principal.organization_id).where(
                AgentDefinitionVersion.agent_definition_id == agent_id
            )
            if after is not None:
                version, identifier = codec.decode(after)
                if not isinstance(version, int) or isinstance(version, bool):
                    raise PublicGraphQLError(
                        "INVALID_CURSOR", "Invalid cursor; restart pagination."
                    )
                query = query.where(
                    or_(
                        AgentDefinitionVersion.version < version,
                        and_(
                            AgentDefinitionVersion.version == version,
                            AgentDefinitionVersion.id < identifier,
                        ),
                    )
                )
            rows = list(
                (
                    await session.scalars(
                        query.order_by(
                            AgentDefinitionVersion.version.desc(),
                            AgentDefinitionVersion.id.desc(),
                        ).limit(size + 1)
                    )
                ).all()
            )
        page = rows[:size]
        return Connection(
            nodes=[AgentDefinitionVersionNode.from_row(row) for row in page],
            page_info=PageInfo(
                has_next_page=len(rows) > size,
                end_cursor=codec.encode(page[-1].version, page[-1].id) if page else None,
            ),
        )

    @strawberry.field
    async def knowledge_sources(
        self,
        info: Info,
        collection_id: strawberry.ID,
        first: int = 25,
        after: str | None = None,
    ) -> Connection[KnowledgeSourceNode]:
        context = _authorize(info, require_internal_knowledge)
        decoded_collection_id = decode_global_id(str(collection_id), "KnowledgeCollection")
        size = page_size(first)
        codec = CursorCodec(
            context.settings.security.jwt_secret.get_secret_value(),
            context.principal.organization_id,
            "knowledgeSources",
        )
        async with context.session_factory() as session:
            parent = await session.scalar(
                tenant_select(KnowledgeCollection, context.principal.organization_id).where(
                    KnowledgeCollection.id == decoded_collection_id
                )
            )
            if parent is None:
                raise ResourceNotFoundError("knowledge collection not found")
            query = tenant_select(KnowledgeSource, context.principal.organization_id).where(
                KnowledgeSource.collection_id == decoded_collection_id
            )
            if after is not None:
                created_at, identifier = codec.decode(after)
                if not isinstance(created_at, dt.datetime):
                    raise PublicGraphQLError(
                        "INVALID_CURSOR", "Invalid cursor; restart pagination."
                    )
                query = query.where(
                    or_(
                        KnowledgeSource.created_at < created_at,
                        and_(
                            KnowledgeSource.created_at == created_at,
                            KnowledgeSource.id < identifier,
                        ),
                    )
                )
            rows = list(
                (
                    await session.scalars(
                        query.order_by(
                            KnowledgeSource.created_at.desc(), KnowledgeSource.id.desc()
                        ).limit(size + 1)
                    )
                ).all()
            )
        page = rows[:size]
        return Connection(
            nodes=[KnowledgeSourceNode.from_row(row) for row in page],
            page_info=PageInfo(
                has_next_page=len(rows) > size,
                end_cursor=codec.encode(
                    page[-1].created_at
                    if page[-1].created_at.tzinfo is not None
                    else page[-1].created_at.replace(tzinfo=dt.UTC),
                    page[-1].id,
                )
                if page
                else None,
            ),
        )

    @strawberry.field
    def agent_tools(self, info: Info) -> list[AgentToolNode]:
        context = _authorize(info, require_custom_agents)
        return [
            AgentToolNode(
                name=spec.name,
                version=spec.version,
                permission=spec.permission.value,
                side_effect=spec.side_effect,
                approval=spec.approval,
                timeout_seconds=spec.timeout_seconds,
                permitted=context.principal.has(spec.permission),
            )
            for spec in sorted(default_tool_registry().specs.values(), key=lambda item: item.name)
        ]
