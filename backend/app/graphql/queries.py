"""Bounded agent/knowledge reads using the same tenant and permission rules as REST."""
import strawberry
from sqlalchemy import and_, or_
from strawberry.types import Info

from app.api.deps import require_custom_agents, require_internal_knowledge
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition
from app.db.models.knowledge import KnowledgeCollection
from app.db.repository import tenant_select
from app.graphql.context import require_context
from app.graphql.ids import decode_global_id
from app.graphql.pagination import CursorCodec, page_size
from app.graphql.types import AgentDefinitionNode, Connection, KnowledgeCollectionNode, PageInfo


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
