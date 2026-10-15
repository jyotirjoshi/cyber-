"""Process-wide GraphQL schema and FastAPI router."""

from __future__ import annotations

import logging

import strawberry
from strawberry.extensions import MaxTokensLimiter
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info

from app.api import API_VERSION
from app.core.config import get_settings
from app.graphql.context import GraphQLContext, build_graphql_context
from app.graphql.errors import PublicErrors
from app.graphql.queries import AgentKnowledgeQueries
from app.graphql.validation import QueryBudget


@strawberry.type
class SystemInfo:
    api_version: str
    capabilities: list[str]


@strawberry.type
class Query(AgentKnowledgeQueries):
    @strawberry.field(description="Public server version and optional API capabilities.")
    def system(self, info: Info) -> SystemInfo:
        settings = (
            info.context.settings if isinstance(info.context, GraphQLContext) else get_settings()
        )
        capabilities = ["graphql", "rest"]
        if settings.features.custom_agents:
            capabilities.append("custom-agents")
        if settings.features.internal_knowledge:
            capabilities.append("internal-knowledge")
        return SystemInfo(
            api_version=API_VERSION,
            capabilities=capabilities,
        )


class PublicSchema(strawberry.Schema):
    def process_errors(self, errors, execution_context=None):
        # Strawberry's default logger renders query text, variables and exception
        # strings. Log only correlation metadata; provider failures can hold keys.
        principal = getattr(getattr(execution_context, "context", None), "principal", None)
        logging.getLogger(__name__).warning(
            "GraphQL operation failed",
            extra={
                "request_id": getattr(principal, "request_id", None),
                "error_count": len(errors),
            },
        )


schema = PublicSchema(query=Query, extensions=[PublicErrors, MaxTokensLimiter(10_000), QueryBudget])
graphql_router = GraphQLRouter(
    schema,
    context_getter=build_graphql_context,
    graphql_ide=None,
    allow_queries_via_get=False,
)

__all__ = ["graphql_router", "schema"]
