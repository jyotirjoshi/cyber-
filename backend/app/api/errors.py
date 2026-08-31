"""RFC 9457 problem responses for every non-2xx (FR-024, SEC-002).

WHY: any API client -- the frontend included -- should get one predictable error shape,
``application/problem+json`` carrying a stable machine ``code``, whether the failure was
a domain error we raised, a request that failed validation, a bare HTTP error, or an
outright bug. Four handlers, one shape.

SEC-002 governs what may cross this boundary. The human-facing ``title`` is the error's
curated ``user_message`` -- never a raw exception string. ``detail`` is populated only
with text known to be safe. The catch-all never places the exception's message in the
response: an unexpected error is logged server-side with its type and traceback and
answered with a generic 500 plus the request id. A validation error reflects the
offending *field path*, never the submitted value, so a rejected password is not echoed
back to the caller.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from app.core.errors import CynuxError, ErrorCategory
from app.schemas.common import Problem

log = structlog.get_logger(__name__)

_PROBLEM_MEDIA_TYPE = "application/problem+json"
_ERROR_DOC_BASE = "https://docs.cynux.io/errors"


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _render(problem: Problem, *, status_code: int) -> JSONResponse:
    return JSONResponse(
        problem.model_dump(exclude_none=True),
        status_code=status_code,
        media_type=_PROBLEM_MEDIA_TYPE,
    )


async def handle_cynux_error(request: Request, exc: Exception) -> Response:
    """Render a raised :class:`CynuxError` (or any subclass) as its problem document."""
    assert isinstance(exc, CynuxError)  # noqa: S101 - registered for exactly this type
    problem = Problem.model_validate(
        {
            **exc.to_problem(),
            "instance": request.url.path,
            "request_id": _request_id(request),
        }
    )
    if exc.http_status >= 500:
        # Our fault. Log with the structured error fields (to_log_fields emits code /
        # category / ctx_* only, never a secret) plus a traceback for the operator.
        log.error("api.domain_error", exc_info=exc, **exc.to_log_fields())
    else:
        log.info("api.client_error", **exc.to_log_fields())
    return _render(problem, status_code=exc.http_status)


async def handle_validation_error(request: Request, exc: Exception) -> Response:
    """Turn a request-validation failure into a 422 problem with a field->messages map."""
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    errors: dict[str, list[str]] = {}
    for err in exc.errors():
        loc = err.get("loc", ())
        # Drop the leading segment ("body" / "query" / "path"): the client cares about the
        # field, not where FastAPI found it. err["input"] is never read (SEC-002).
        parts = [str(p) for p in loc[1:]] if len(loc) > 1 else [str(p) for p in loc]
        field = ".".join(parts) if parts else "__root__"
        errors.setdefault(field, []).append(str(err.get("msg", "invalid")))
    problem = Problem(
        type=f"{_ERROR_DOC_BASE}/validation_error",
        title="The request could not be processed.",
        status=422,
        code="validation_error",
        category=ErrorCategory.USER.value,
        instance=request.url.path,
        request_id=_request_id(request),
        errors=errors,
    )
    return _render(problem, status_code=422)


async def handle_http_exception(request: Request, exc: Exception) -> Response:
    """Wrap a bare Starlette/FastAPI ``HTTPException`` in the problem shape."""
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101
    detail = exc.detail if isinstance(exc.detail, str) else None
    category = ErrorCategory.USER if exc.status_code < 500 else ErrorCategory.INTERNAL
    problem = Problem(
        type=f"{_ERROR_DOC_BASE}/http_error",
        title=detail or "The request could not be completed.",
        status=exc.status_code,
        code="http_error",
        category=category.value,
        instance=request.url.path,
        request_id=_request_id(request),
    )
    return _render(problem, status_code=exc.status_code)


async def handle_unexpected(request: Request, exc: Exception) -> Response:
    """Last resort: a bug or an unmapped library error. The caller learns nothing but the id."""
    log.error("api.unhandled_exception", exc_info=exc, error_type=type(exc).__name__)
    problem = Problem(
        type=f"{_ERROR_DOC_BASE}/internal_error",
        title="An unexpected error occurred. Quote the request id when reporting it.",
        status=500,
        code="internal_error",
        category=ErrorCategory.INTERNAL.value,
        instance=request.url.path,
        request_id=_request_id(request),
    )
    return _render(problem, status_code=500)


def install_exception_handlers(app: FastAPI) -> None:
    """Register the four handlers. Starlette resolves the most specific by walking the MRO,
    so registering :class:`CynuxError` covers every subclass and ``Exception`` is the floor.
    """
    app.add_exception_handler(CynuxError, handle_cynux_error)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(Exception, handle_unexpected)


__all__ = [
    "handle_cynux_error",
    "handle_http_exception",
    "handle_unexpected",
    "handle_validation_error",
    "install_exception_handlers",
]
