"""Shared wire types: the error document, pagination and trivial responses.

Every non-2xx response in Cynux is an RFC 9457 problem document, produced by
:meth:`app.core.errors.CynuxError.to_problem`.  ``title`` carries the *user-safe*
message -- the one field a UI may render verbatim -- while ``detail`` is reserved for
operator-facing context and is only populated where it is known to be safe.  Keeping
those two roles in separate fields is what lets the frontend show an error without
risking a leaked credential or a provider response body (SEC-002).
"""

from __future__ import annotations

from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Problem(BaseModel):
    """RFC 9457 problem document.

    Mirrors ``CynuxError.to_problem()`` plus the three fields the API layer adds:
    ``detail``, ``instance`` and ``request_id``.  ``category`` and ``retryable`` come
    from the error taxonomy rather than being restated per route, so a client can
    decide whether to offer a retry without pattern-matching on ``code``.
    """

    model_config = ConfigDict(from_attributes=True)

    type: str = Field(description="Stable URI identifying the error class.")
    title: str = Field(description="User-safe message. Safe to render verbatim.")
    status: int
    code: str = Field(description="Machine-readable code, e.g. 'scanner_timeout'.")
    category: str
    retryable: bool = False
    detail: str | None = Field(
        default=None,
        description="Operator-facing context. Populated only when known secret-free.",
    )
    instance: str | None = Field(default=None, description="Request path.")
    request_id: str | None = Field(default=None, description="Correlates with logs and traces.")
    #: Field-level validation errors, ``{"field": ["message", ...]}``.
    errors: dict[str, list[str]] | None = None


class PageMeta(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    limit: int
    offset: int
    has_more: bool


class Page(BaseModel, Generic[T]):
    """Envelope for every list endpoint, e.g. ``Page[FindingOut]``.

    A bare JSON array cannot carry a total, and a client that cannot see the total
    cannot tell "no results" from "first page of many" -- which matters when the list
    in question is a findings triage queue.
    """

    model_config = ConfigDict(from_attributes=True)

    items: list[T]
    meta: PageMeta

    @classmethod
    def build(cls, items: list[T], *, total: int, limit: int, offset: int) -> Page[T]:
        return cls(
            items=items,
            meta=PageMeta(
                total=total,
                limit=limit,
                offset=offset,
                has_more=offset + len(items) < total,
            ),
        )


class PaginationParams(BaseModel):
    """Query-string pagination.

    ``limit`` is capped at 200: an uncapped page size on the findings endpoint is a
    trivial way to make the API serialize a whole engagement into one response.
    """

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class SortParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sort_by: str | None = Field(default=None, max_length=40)
    sort_dir: Literal["asc", "desc"] = "desc"


class DependencyHealth(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    healthy: bool
    detail: str | None = None
    latency_ms: int | None = None


class HealthOut(BaseModel):
    """Liveness/readiness payload.

    ``degraded`` is reported distinctly from ``unhealthy``: Cynux is designed to keep
    running when an *enrichment* provider is down (FR-020), so an operator needs to be
    able to tell "NVD unreachable" from "database unreachable".
    """

    model_config = ConfigDict(from_attributes=True)

    status: Literal["ok", "degraded", "unhealthy"]
    version: str
    environment: str
    dependencies: list[DependencyHealth] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class OkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ok: bool = True


__all__ = [
    "DependencyHealth",
    "HealthOut",
    "OkOut",
    "Page",
    "PageMeta",
    "PaginationParams",
    "Problem",
    "SortParams",
]
