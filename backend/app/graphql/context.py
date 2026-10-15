"""Reuse REST authentication; allocate a separate database session per resolver."""
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from sqlalchemy.ext.asyncio import AsyncSession
from strawberry.fastapi import BaseContext
from strawberry.types import Info

from app.api.deps import PrincipalDep, SettingsDep
from app.core.config import Settings
from app.db.session import get_sessionmaker
from app.graphql.errors import PublicGraphQLError
from app.services.context import Principal


class GraphQLContext(BaseContext):
    def __init__(
        self,
        principal: Principal,
        settings: Settings,
        session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ):
        super().__init__()
        self.principal = principal
        self.settings = settings
        self.session_factory = session_factory


async def build_graphql_context(principal: PrincipalDep, settings: SettingsDep) -> GraphQLContext:
    return GraphQLContext(principal, settings, get_sessionmaker(settings))


def require_context(info: Info) -> GraphQLContext:
    if not isinstance(info.context, GraphQLContext):
        raise PublicGraphQLError("UNAUTHENTICATED", "Sign in to continue.")
    return info.context
