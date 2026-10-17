"""Bounded agent/knowledge reads using the same tenant and permission rules as REST."""
import datetime as dt

import strawberry
from pydantic import ValidationError
from sqlalchemy import and_, or_
from strawberry.types import Info

from app.agent.tools.registry import default_tool_registry
from app.api.deps import require_custom_agents, require_internal_knowledge
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition, AgentDefinitionVersion
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.canonical import AutomationRule, CanonicalFinding
from app.db.models.knowledge import KnowledgeCollection, KnowledgeSource
from app.db.models.report import Report
from app.db.repository import tenant_select
from app.graphql.context import require_context
from app.graphql.errors import PublicGraphQLError
from app.graphql.ids import decode_global_id
from app.graphql.pagination import CursorCodec, page_size
from app.graphql.types import (
    AgentDefinitionNode,
    AgentDefinitionVersionNode,
    AgentToolNode,
    AssessmentNode,
    AssetNode,
    AutomationRuleNode,
    CanonicalFindingNode,
    Connection,
    KnowledgeCollectionNode,
    KnowledgeSearchHitNode,
    KnowledgeSourceNode,
    PageInfo,
    ReportNode,
)
from app.schemas.knowledge import KnowledgeSearchIn
from app.services.knowledge_retrieval import InternalKnowledgeRetriever, RetrievalPolicy


def _authorize(info, guard):
    context = require_context(info)
    context.principal.require(Permission.AGENT_CHAT)
    guard(context.settings)
    return context


def _authorize_permission(info, permission: Permission):
    context = require_context(info)
    context.principal.require(permission)
    return context


async def _connection(
    context,
    model,
    projection,
    connection,
    first,
    after,
    *,
    sort_column=None,
):
    sort_column = sort_column or model.name
    size = page_size(first)
    codec = CursorCodec(
        context.settings.security.jwt_secret.get_secret_value(),
        context.principal.organization_id,
        connection,
    )
    query = tenant_select(model, context.principal.organization_id)
    if after is not None:
        sort_value, identifier = codec.decode(after)
        if not isinstance(sort_value, str):
            raise PublicGraphQLError("INVALID_CURSOR", "Invalid cursor; restart pagination.")
        query = query.where(
            or_(
                sort_column > sort_value,
                and_(sort_column == sort_value, model.id > identifier),
            )
        )
    query = query.order_by(sort_column, model.id).limit(size + 1)
    async with context.session_factory() as session:
        rows = list((await session.scalars(query)).all())
    page = rows[:size]
    return Connection(
        nodes=[projection.from_row(row) for row in page],
        page_info=PageInfo(
            has_next_page=len(rows) > size,
            end_cursor=(
                codec.encode(str(getattr(page[-1], sort_column.key)), page[-1].id)
                if page
                else None
            ),
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
    async def assets(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[AssetNode]:
        return await _connection(
            _authorize_permission(info, Permission.ASSET_READ),
            Asset,
            AssetNode,
            "assets",
            first,
            after,
            sort_column=Asset.name,
        )

    @strawberry.field
    async def canonical_findings(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[CanonicalFindingNode]:
        return await _connection(
            _authorize_permission(info, Permission.FINDING_READ),
            CanonicalFinding,
            CanonicalFindingNode,
            "canonicalFindings",
            first,
            after,
            sort_column=CanonicalFinding.title,
        )

    @strawberry.field
    async def assessments(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[AssessmentNode]:
        return await _connection(
            _authorize_permission(info, Permission.ASSESSMENT_READ),
            Assessment,
            AssessmentNode,
            "assessments",
            first,
            after,
            sort_column=Assessment.title,
        )

    @strawberry.field
    async def reports(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[ReportNode]:
        return await _connection(
            _authorize_permission(info, Permission.REPORT_READ),
            Report,
            ReportNode,
            "reports",
            first,
            after,
            sort_column=Report.title,
        )

    @strawberry.field
    async def automation_rules(
        self, info: Info, first: int = 25, after: str | None = None
    ) -> Connection[AutomationRuleNode]:
        return await _connection(
            _authorize_permission(info, Permission.ORG_READ),
            AutomationRule,
            AutomationRuleNode,
            "automationRules",
            first,
            after,
            sort_column=AutomationRule.name,
        )

    @strawberry.field
    async def knowledge_search(
        self,
        info: Info,
        query: str,
        collection_ids: list[strawberry.ID],
        limit: int = 6,
        min_similarity: float = 0.25,
    ) -> list[KnowledgeSearchHitNode]:
        context = _authorize(info, require_internal_knowledge)
        if not 1 <= len(collection_ids) <= 20:
            raise PublicGraphQLError("BAD_USER_INPUT", "Select 1 to 20 knowledge collections.")
        try:
            payload = KnowledgeSearchIn(
                query=query.strip(),
                collection_ids=[
                    decode_global_id(str(value), "KnowledgeCollection") for value in collection_ids
                ],
                limit=limit,
                min_similarity=min_similarity,
            )
        except ValidationError as exc:
            raise PublicGraphQLError("BAD_USER_INPUT", "Knowledge search input is invalid.") from exc
        policy = RetrievalPolicy(
            context.principal.organization_id,
            tuple(dict.fromkeys(payload.collection_ids)),
            limit=payload.limit,
            min_similarity=payload.min_similarity,
        )
        async with context.session_factory() as session:
            hits = await InternalKnowledgeRetriever(
                session, context.principal, context.settings
            ).retrieve(payload.query, policy)
        return [KnowledgeSearchHitNode.from_hit(hit) for hit in hits]

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
            f"agentDefinitionVersions:{agent_id}",
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
            f"knowledgeSources:{decoded_collection_id}",
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
