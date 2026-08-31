"""FastAPI dependency wiring (FR-001, FR-002, SEC-002, SEC-003).

WHY a dedicated module: every route needs the same handful of things -- a request-scoped
database session, the process Redis client, the authenticated user, and the tenant-scoped
:class:`~app.services.context.Principal` that authorises the work -- and they must be
wired in exactly one place so a route cannot accidentally authenticate without also
resolving a tenant, or open a second session for the same request.

The session dependency is :func:`app.db.session.get_db`, which deliberately does *not*
commit: a route commits at the point it means to persist, so a handler that raises after
a partial write leaves nothing behind. Authentication and authorization are two separate
dependencies because a valid credential with no organization membership is a 403, not a
401 -- retrying with a fresh token cannot help when the *authorization* is what is missing
(see :func:`app.services.auth.resolve_principal`). Resolving the principal also binds the
tenant and actor onto the structlog context; it never binds anything that identifies a
scanned *target* (SEC-002).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable
from typing import Annotated, Literal, cast

from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.contextvars import bind_contextvars

from app.core.config import Settings, get_settings
from app.core.errors import AuthenticationError
from app.core.redis_client import TokenDenyList, get_redis
from app.core.security import TokenClaims
from app.db.enums import IntegrationKind
from app.db.models.identity import User
from app.db.session import get_db
from app.integrations.dify import DifyClient
from app.integrations.storage import ObjectStorage
from app.llm.gateway import LLMGateway, get_gateway
from app.schemas.common import PaginationParams, SortParams
from app.services.auth import authenticate_token, resolve_principal
from app.services.context import Principal
from app.services.events import EventBus
from app.services.integration import resolve_settings

_bearer = HTTPBearer(auto_error=False, description="Bearer access token")


def _settings() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(_settings)]
DbSession = Annotated[AsyncSession, Depends(get_db)]


def _redis(settings: SettingsDep) -> Redis:
    return get_redis(settings)


RedisDep = Annotated[Redis, Depends(_redis)]


def _deny_list(redis: RedisDep) -> TokenDenyList:
    return TokenDenyList(redis)


DenyListDep = Annotated[TokenDenyList, Depends(_deny_list)]


def _event_bus(redis: RedisDep, settings: SettingsDep) -> EventBus:
    return EventBus(redis, settings)


EventBusDep = Annotated[EventBus, Depends(_event_bus)]


def _gateway(settings: SettingsDep) -> LLMGateway:
    """The process-wide LLM gateway (FR-021, FR-023, FR-024, FR-025).

    A singleton: provider SDK clients and their connection pools are built lazily inside it
    and shared across every request, so it is never closed per-request -- only when the
    process shuts down. The gateway's credentials are deployment-wide, not per-tenant, so no
    integration overlay is applied here.
    """
    return get_gateway(settings)


GatewayDep = Annotated[LLMGateway, Depends(_gateway)]


def _storage(settings: SettingsDep) -> ObjectStorage:
    """Object storage for report artifacts and scanner evidence (FR-028, FR-031).

    Cheap to construct -- the boto3 client is built lazily on first use and holds no
    connection until then -- so a fresh instance per request needs no teardown.
    """
    return ObjectStorage(settings)


StorageDep = Annotated[ObjectStorage, Depends(_storage)]


async def _dify(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> AsyncIterator[DifyClient | None]:
    """This organization's Dify knowledge-base client, or ``None`` when unconfigured.

    Dify enrichment is optional: :func:`app.services.finding.analyze_finding` and
    :func:`app.services.remediation.generate_remediation` accept ``dify=None`` and skip the
    knowledge-base retrieval, so an organization that has not connected Dify still gets
    analysis and remediation. Credentials are per-tenant, so the client is built from settings
    with this organization's integration row overlaid (SEC-003) and closed when the request
    ends -- an unconfigured client's ``aclose`` is a no-op, its HTTP client never having been
    built.
    """
    scoped = await resolve_settings(session, principal, IntegrationKind.DIFY, settings=settings)
    client = DifyClient(scoped, redis)
    try:
        yield client if client.configured else None
    finally:
        await client.aclose()


DifyDep = Annotated[DifyClient | None, Depends(_dify)]


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def current_identity(
    session: DbSession,
    deny_list: DenyListDep,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> tuple[User, TokenClaims]:
    """Authenticate the bearer token and load the account it names.

    Returns the claims alongside the user so a route that needs the ``jti`` (sign-out) or
    the ``org`` claim (active tenant) does not have to decode the token a second time.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError(
            "missing bearer token",
            user_message="Sign in to continue.",
        )
    return await authenticate_token(session, deny_list, credentials.credentials, settings=settings)


IdentityDep = Annotated[tuple[User, TokenClaims], Depends(current_identity)]


def current_user(identity: IdentityDep) -> User:
    return identity[0]


CurrentUser = Annotated[User, Depends(current_user)]


def current_claims(identity: IdentityDep) -> TokenClaims:
    return identity[1]


CurrentClaims = Annotated[TokenClaims, Depends(current_claims)]


async def current_principal(
    request: Request, session: DbSession, identity: IdentityDep
) -> Principal:
    """Resolve the tenant-scoped authority for the request and bind it to the log context.

    A valid credential whose account belongs to no organization raises
    :class:`~app.core.errors.PermissionDeniedError` (403) inside ``resolve_principal`` --
    the credential is fine, the authorization is missing.
    """
    user, claims = identity
    principal = await resolve_principal(
        session,
        user,
        claims,
        source_ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    request.state.principal = principal
    bind_contextvars(
        organization_id=str(principal.organization_id),
        actor=str(principal.user_id) if principal.user_id is not None else principal.actor_type,
    )
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def pagination(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginationParams:
    return PaginationParams(limit=limit, offset=offset)


PaginationDep = Annotated[PaginationParams, Depends(pagination)]


def sorting(
    sort_by: Annotated[str | None, Query(max_length=40)] = None,
    sort_dir: Annotated[Literal["asc", "desc"], Query()] = "desc",
) -> SortParams:
    return SortParams(sort_by=sort_by, sort_dir=sort_dir)


SortDep = Annotated[SortParams, Depends(sorting)]


async def redis_ping(redis: Redis) -> bool:
    """Await a Redis ``PING`` through the async-typed cast idiom used across the codebase."""
    return await cast(Awaitable[bool], redis.ping())


__all__ = [
    "CurrentClaims",
    "CurrentUser",
    "DbSession",
    "DenyListDep",
    "DifyDep",
    "EventBusDep",
    "GatewayDep",
    "IdentityDep",
    "PaginationDep",
    "PrincipalDep",
    "RedisDep",
    "SettingsDep",
    "SortDep",
    "StorageDep",
    "current_claims",
    "current_identity",
    "current_principal",
    "current_user",
    "pagination",
    "redis_ping",
    "sorting",
]
