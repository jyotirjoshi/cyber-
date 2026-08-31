"""Declarative base, shared column types and mixins.

Two conventions matter here:

``TenantMixin``
    Every tenant-scoped table carries ``organization_id`` with an index and a
    foreign key.  SEC-003 is then enforced in one place -- the repository helpers in
    :mod:`app.db.repository` refuse to build a query for a tenant table without a
    tenant filter -- rather than relying on each route remembering to add one.

Naming convention
    Constraint names are generated deterministically so Alembic autogenerate
    produces stable diffs instead of renaming indexes on every run.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Final

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: Default ``lazy=`` for every relationship in the model layer.
#:
#: ``raise_on_sql`` turns an accidental lazy load into a loud exception rather than a silent
#: per-row query. That matters twice over here: on an async session an implicit load raises an
#: opaque greenlet error far from the attribute access that caused it, and a relationship
#: traversed in a loop is the ordinary way an endpoint becomes an N+1. Callers state their
#: intent with ``selectinload`` instead of getting IO by accident.
#:
#: ``Final`` is load-bearing, not decoration: without it mypy widens the value to ``str`` and
#: every ``relationship(lazy=LAZY)`` call fails against SQLAlchemy's ``Literal`` overload.
LAZY: Final = "raise_on_sql"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {
        dict[str, Any]: JSONB,
        list[str]: JSONB,
        uuid.UUID: PgUUID(as_uuid=True),
        dt.datetime: DateTime(timezone=True),
    }
    # There is deliberately no ``list[dict[str, Any]]`` entry.  Every module here uses
    # ``from __future__ import annotations``, so SQLAlchemy sees the annotation as a
    # string and de-stringifies it -- and for a *nested* generic the inner arguments come
    # back as ForwardRefs, yielding ``list[dict['str', 'Any']]``, which never compares
    # equal to a ``list[dict[str, Any]]`` key.  An entry here would therefore look like
    # it worked while silently never matching.  Array-of-object columns instead pass
    # ``JSONB`` to ``mapped_column`` explicitly.  One level of nesting resolves fine,
    # which is why ``dict[str, Any]`` and ``list[str]`` are mapped above.

    def as_dict(self, *, exclude: set[str] | None = None) -> dict[str, Any]:
        exclude = exclude or set()
        return {
            c.name: getattr(self, c.name) for c in self.__table__.columns if c.name not in exclude
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} id={pk}>"


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class TenantMixin:
    """Marks a table as organization-scoped (SEC-003).

    The presence of this mixin is what :func:`app.db.repository.tenant_query`
    checks; forgetting it on a new tenant table causes a loud failure in tests
    rather than a silent cross-tenant read.
    """

    @property
    def _is_tenant_scoped(self) -> bool:
        return True

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "LAZY",
    "NAMING_CONVENTION",
    "Base",
    "TenantMixin",
    "TimestampMixin",
    "utcnow",
    "uuid_pk",
]
