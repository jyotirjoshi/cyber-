"""PostgreSQL query helpers for bounded-parameter bulk workflows."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import ColumnElement, any_, literal
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import InstrumentedAttribute


def pg_any(
    column: InstrumentedAttribute[Any] | ColumnElement[Any], values: Iterable[Any]
) -> ColumnElement[bool]:
    """Membership with one typed array bind, including an empty collection.

    Expanding IN lists allocate one bind per value and can exceed asyncpg's
    parameter limit on large imports. Never interpolate values into SQL text.
    Callers must still include their normal organization and scope predicates.
    """
    return column == any_(literal(list(values), type_=ARRAY(column.type)))
