"""ASGI application factory (FR-001..FR-040, SEC-002, PRD section 58).

WHY a factory and no module-level ``app``: constructing the application calls
``get_settings()``, which fails fast on a missing ``jwt_secret`` and other required
configuration. Doing that at import time would break the per-file gate, which only
imports modules. Run the server with ``uvicorn --factory app.api.app:create_app``.

Boot order matches PRD section 58: configure logging, then telemetry, then LangSmith,
*then* build the app and instrument it -- so the first log line the app emits already
carries structured output and, when enabled, a trace context. A request-context
middleware assigns every request an id, binds it (with the trace id, method and path)
onto the structlog context, and echoes it back as ``X-Request-ID``; because it sits
outside Starlette's exception middleware, that id is available to the RFC 9457 handlers,
which is what lets a user quote one id that an operator can grep for.

Startup refuses to proceed on a fatal misconfiguration
(:func:`app.core.config.validate_runtime_configuration` with ``role="api"``) and drains
the Redis pool and database engine on shutdown.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response
from structlog.contextvars import bind_contextvars, clear_contextvars

from app.api import API_VERSION
from app.api.errors import install_exception_handlers
from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.api.ws import ws_router
from app.core.config import Settings, get_settings, validate_runtime_configuration
from app.core.logging_conf import configure_logging
from app.core.redis_client import close_redis
from app.core.telemetry import configure_langsmith, instrument_app, setup_telemetry
from app.db.session import dispose_engine

log = structlog.get_logger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign and propagate a request id, and scope the structlog context to the request.

    The id is taken from an inbound ``X-Request-ID`` when present (so a trace started at
    the edge is preserved) and generated otherwise. It is stored on ``request.state`` for
    the dependencies and error handlers, bound onto the log context for the duration of
    the request, and returned as a response header. The context is always cleared in a
    ``finally`` so one request's binding can never bleed into the next on a reused worker.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        trace_id = request.headers.get("x-trace-id") or request_id
        request.state.request_id = request_id
        request.state.trace_id = trace_id
        clear_contextvars()
        bind_contextvars(
            request_id=request_id,
            trace_id=trace_id,
            http_method=request.method,
            http_path=request.url.path,
        )
        try:
            response = await call_next(request)
        finally:
            clear_contextvars()
        response.headers["x-request-id"] = request_id
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    for warning in validate_runtime_configuration(settings, role="api"):
        log.warning("api.config_warning", detail=warning)
    log.info("api.startup", environment=settings.environment, version=API_VERSION)
    try:
        yield
    finally:
        await close_redis()
        await dispose_engine()
        log.info("api.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the fully wired ASGI application. Safe to call more than once (tests do)."""
    settings = settings or get_settings()
    configure_logging(settings)
    setup_telemetry(settings, service_name="cynux-api")
    configure_langsmith(settings)

    docs_disabled = settings.is_production
    app = FastAPI(
        title="Cynux API",
        version=API_VERSION,
        summary="AI-driven security assessment platform.",
        lifespan=_lifespan,
        docs_url=None if docs_disabled else "/docs",
        redoc_url=None if docs_disabled else "/redoc",
        openapi_url=None if docs_disabled else "/openapi.json",
    )
    app.state.settings = settings

    # CORS is added first (innermost) so its headers are applied to every response,
    # including the problem documents produced by the exception handlers; the
    # request-context middleware is added last so it is outermost and stamps the id before
    # anything else runs.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["x-request-id"],
    )
    if list(settings.allowed_hosts) != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(RequestContextMiddleware)

    install_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(api_router, prefix=settings.api_prefix)
    # The live agent stream is mounted without the API prefix: it declares its own ``/ws/...``
    # path and is a transport rather than a versioned resource (see app.api.ws).
    app.include_router(ws_router)

    instrument_app(app, settings)
    log.info("api.created", environment=settings.environment, docs_enabled=not docs_disabled)
    return app


__all__ = ["RequestContextMiddleware", "create_app"]
