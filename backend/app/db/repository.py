"""Tenant-safe query helpers (SEC-003).

The rule this module enforces: *a query against a tenant-scoped table must carry an
``organization_id`` filter*.  Relying on each route to remember that is how
cross-tenant leaks happen -- one forgotten ``where`` in one list endpoint is enough.
Here it is structural instead. :func:`tenant_select` is the only sanctioned way to
build a select over a :class:`~app.db.base.TenantMixin` model, and it refuses to
produce one without a tenant.

:class:`TenantRepository` wraps the common operations (get, list, count, exists) so
service code rarely writes a raw select at all, and :func:`assert_tenant_owned` gives
the one-liner used after any lookup by primary key.

Cross-tenant access surfaces as a 404, never a 403.  A 403 confirms the resource
exists, which turns an id into an oracle for enumerating another organization's data.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any, Generic, TypeVar

from sqlalchemy import Select, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.base import ExecutableOption

from app.core.errors import CynuxError, ErrorCategory, TenantIsolationError
from app.db.base import Base, TenantMixin

ModelT = TypeVar("ModelT", bound=Base)
TenantModelT = TypeVar("TenantModelT", bound=Base)


class TenantScopeError(CynuxError):
    """Raised when code tries to query a tenant table without a tenant.

    This is a programming error, not a user error: it means a developer used
    ``select(Model)`` where they needed :func:`tenant_select`.  It is deliberately an
    exception rather than a warning so it fails in tests.
    """

    category = ErrorCategory.INTERNAL
    http_status = 500
    default_user_message = "An unexpected error occurred."


def is_tenant_scoped(model: type[Any]) -> bool:
    return isinstance(model, type) and issubclass(model, TenantMixin)


def tenant_select(
    model: type[TenantModelT],
    organization_id: uuid.UUID,
    *options: ExecutableOption,
) -> Select[tuple[TenantModelT]]:
    """``select(model).where(model.organization_id == organization_id)``.

    Raises :class:`TenantScopeError` if ``model`` is not tenant-scoped, which catches
    the mistake of routing a global table (users, audit_events) through this helper and
    silently filtering on a column that does not exist.
    """
    if not is_tenant_scoped(model):
        raise TenantScopeError(
            f"{model.__name__} is not tenant-scoped; use select() directly",
            context={"model": model.__name__},
        )
    if organization_id is None:  # pragma: no cover - defensive
        raise TenantScopeError(f"tenant_select({model.__name__}) called without organization_id")
    stmt = select(model).where(model.organization_id == organization_id)  # type: ignore[attr-defined]
    if options:
        stmt = stmt.options(*options)
    return stmt


def assert_tenant_owned(obj: Any, organization_id: uuid.UUID, *, resource: str) -> None:
    """Verify a loaded row belongs to the caller's organization.

    Used after a lookup that could not be tenant-filtered (a join through another
    table, or a bare ``session.get``).  Raises :class:`TenantIsolationError`, which
    renders as 404.
    """
    if obj is None:
        raise TenantIsolationError(f"{resource} not found", context={"resource": resource})
    owner = getattr(obj, "organization_id", None)
    if owner is None or owner != organization_id:
        raise TenantIsolationError(
            f"{resource} belongs to another organization",
            context={"resource": resource, "requested_by": str(organization_id)},
        )


class TenantRepository(Generic[ModelT]):
    """Thin data-access wrapper bound to one model and one organization.

    Constructed per request from the authenticated principal, so no call site has to
    pass ``organization_id`` around and none of them can forget it.
    """

    __slots__ = ("model", "organization_id", "session")

    def __init__(
        self,
        session: AsyncSession,
        model: type[ModelT],
        organization_id: uuid.UUID,
    ) -> None:
        if not is_tenant_scoped(model):
            raise TenantScopeError(
                f"{model.__name__} is not tenant-scoped",
                context={"model": model.__name__},
            )
        self.session = session
        self.model = model
        self.organization_id = organization_id

    # -- reads ---------------------------------------------------------------

    def select(self, *options: ExecutableOption) -> Select[tuple[ModelT]]:
        return tenant_select(self.model, self.organization_id, *options)

    async def get(self, obj_id: uuid.UUID, *options: ExecutableOption) -> ModelT | None:
        stmt = self.select(*options).where(self.model.id == obj_id)  # type: ignore[attr-defined]
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def get_or_404(self, obj_id: uuid.UUID, *options: ExecutableOption) -> ModelT:
        obj = await self.get(obj_id, *options)
        if obj is None:
            raise TenantIsolationError(
                f"{self.model.__name__} not found",
                context={"resource": self.model.__name__, "id": str(obj_id)},
            )
        return obj

    async def list(
        self,
        *options: ExecutableOption,
        order_by: InstrumentedAttribute[Any] | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Sequence[ModelT]:
        stmt = self.select(*options)
        if order_by is not None:
            stmt = stmt.order_by(order_by)
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return (await self.session.execute(stmt)).scalars().all()

    async def count(self) -> int:
        stmt = (
            select(func.count())
            .select_from(self.model)
            .where(self.model.organization_id == self.organization_id)  # type: ignore[attr-defined]
        )
        return int((await self.session.execute(stmt)).scalar_one())

    async def exists(self, obj_id: uuid.UUID) -> bool:
        stmt = (
            select(func.count())
            .select_from(self.model)
            .where(
                self.model.organization_id == self.organization_id,  # type: ignore[attr-defined]
                self.model.id == obj_id,  # type: ignore[attr-defined]
            )
        )
        return int((await self.session.execute(stmt)).scalar_one()) > 0

    # -- writes --------------------------------------------------------------

    def add(self, obj: ModelT) -> ModelT:
        """Stamp the tenant and stage the row.

        The stamp is unconditional: a caller that set ``organization_id`` to another
        org -- by copying a payload, say -- gets it corrected rather than persisted.
        """
        obj.organization_id = self.organization_id  # type: ignore[attr-defined]
        self.session.add(obj)
        return obj

    async def delete(self, obj_id: uuid.UUID) -> int:
        stmt = delete(self.model).where(
            self.model.organization_id == self.organization_id,  # type: ignore[attr-defined]
            self.model.id == obj_id,  # type: ignore[attr-defined]
        )
        result = await self.session.execute(stmt)
        return int(result.rowcount or 0)


__all__ = [
    "TenantRepository",
    "TenantScopeError",
    "assert_tenant_owned",
    "is_tenant_scoped",
    "tenant_select",
]
