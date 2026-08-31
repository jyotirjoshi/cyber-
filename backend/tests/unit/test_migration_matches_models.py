"""The migration must describe the same schema the models declare.

Model drift is silent and expensive: the models are what the application queries, the
migration is what the database actually contains, and nothing in normal development
compares them.  A column added to a model without a migration produces
``UndefinedColumn`` on the first query in a deployed environment and nowhere earlier.

Rather than running Alembic against a live Postgres, the migration's ``upgrade()`` is
executed against a recorder standing in for ``op``.  Every ``create_table`` and
``create_index`` call is captured, and the resulting picture is diffed against
``Base.metadata``.  That keeps the test offline while still reading the real migration
file -- a hand-written table block with a typo fails here.

``downgrade()`` is checked too, because a migration that cannot be reversed is one that
cannot be tested against in CI later.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.db.base import Base
from app.db.models import (  # noqa: F401 - registers the mappers
    agent,
    assessment,
    asset,
    audit,
    finding,
    identity,
    integration,
    notification,
    report,
    scanner,
)

#: Loaded by path, not by import name: ``alembic.versions`` resolves to the *installed*
#: Alembic package, and the local ``alembic/`` directory is deliberately not a package
#: (Alembic loads revision files by path itself, for the same reason).
MIGRATION_PATH = Path(__file__).resolve().parents[2] / "alembic" / "versions"


def _load_migration(filename: str) -> ModuleType:
    path = MIGRATION_PATH / filename
    spec = importlib.util.spec_from_file_location(f"_cynux_migration_{path.stem}", path)
    assert spec and spec.loader, f"could not load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_there_is_exactly_one_migration_and_this_test_covers_it() -> None:
    """Guards the whole file from going stale.

    Every assertion below reads ``0001_initial_schema``. A second revision would mean the
    schema is no longer described by that file alone, and this test is the thing that
    notices -- otherwise the suite would keep passing while checking an obsolete picture.
    """
    revisions = sorted(p.name for p in MIGRATION_PATH.glob("[0-9]*.py"))
    assert revisions == ["0001_initial_schema.py"], (
        f"migrations changed to {revisions}; this test must be taught to replay all of "
        f"them in order rather than just the first"
    )


#: LangGraph owns these and migrates them itself; ``alembic/env.py`` filters them out of
#: autogenerate for the same reason, so their absence from the migration is correct.
LANGGRAPH_TABLES = frozenset({"checkpoints", "checkpoint_blobs", "checkpoint_writes"})


class OpRecorder:
    """Stands in for ``alembic.op``, capturing schema operations instead of emitting SQL."""

    def __init__(self) -> None:
        self.tables: dict[str, list[Any]] = {}
        self.indexes: list[tuple[str, str, tuple[str, ...], bool]] = []
        self.dropped_tables: list[str] = []
        self.dropped_indexes: list[tuple[str, str]] = []
        self.other: list[str] = []

    # -- upgrade ------------------------------------------------------------

    def create_table(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.tables[name] = list(args)

    def create_index(
        self, name: str, table: str, columns: list[str], unique: bool = False, **kwargs: Any
    ) -> None:
        self.indexes.append((name, table, tuple(columns), unique))

    # -- downgrade ----------------------------------------------------------

    def drop_table(self, name: str, **kwargs: Any) -> None:
        self.dropped_tables.append(name)

    def drop_index(self, name: str, table_name: str = "", **kwargs: Any) -> None:
        self.dropped_indexes.append((name, table_name))

    # -- misc ---------------------------------------------------------------

    def f(self, name: str) -> str:
        """``op.f`` marks a name as already-conventional. Identity is the right stand-in."""
        return name

    def execute(self, statement: Any, **kwargs: Any) -> None:
        self.other.append(str(statement))

    def __getattr__(self, item: str) -> Any:
        """Fail loudly on an unhandled operation rather than silently ignoring it.

        A migration that starts using ``add_column`` or ``alter_column`` must extend this
        recorder; passing those through as no-ops would make the diff below lie.
        """
        raise AssertionError(
            f"the migration used op.{item}(), which this recorder does not model -- "
            f"add it to OpRecorder so the schema diff stays honest"
        )


@pytest.fixture(scope="module")
def recorded() -> Iterator[OpRecorder]:
    module = _load_migration("0001_initial_schema.py")
    recorder = OpRecorder()
    with patch.object(module, "op", recorder):
        module.upgrade()
    yield recorder


@pytest.fixture(scope="module")
def migrated() -> Iterator[sa.MetaData]:
    """The migration's schema as a real :class:`sqlalchemy.MetaData`.

    Rebuilding actual ``Table`` objects rather than inspecting the raw ``create_table``
    arguments is what makes the comparisons below symmetric -- both sides are then the
    same kind of object and the same accessors work on each.

    It is also the difference between a correct test and a confidently wrong one: an
    unattached ``UniqueConstraint("session_id", "seq")`` holds column *names*, and its
    ``.columns`` collection is empty until it is bound to a table. Reading ``.columns``
    off the raw argument reports every unique constraint in the schema as missing.
    """
    module = _load_migration("0001_initial_schema.py")
    recorder = OpRecorder()
    with patch.object(module, "op", recorder):
        module.upgrade()

    metadata = sa.MetaData()
    #: Insertion order is the migration's own dependency order, so a foreign key's
    #: target table already exists by the time it is referenced.
    for name, args in recorder.tables.items():
        sa.Table(name, metadata, *args)
    for _name, table, columns, unique in recorder.indexes:
        if table in metadata.tables:
            sa.Index(_name, *(metadata.tables[table].c[c] for c in columns), unique=unique)
    yield metadata


@pytest.fixture(scope="module")
def recorded_downgrade() -> Iterator[OpRecorder]:
    module = _load_migration("0001_initial_schema.py")
    recorder = OpRecorder()
    with patch.object(module, "op", recorder):
        module.downgrade()
    yield recorder


def _model_tables() -> dict[str, sa.Table]:
    return {
        name: table for name, table in Base.metadata.tables.items() if name not in LANGGRAPH_TABLES
    }


def _columns_of(create_table_args: list[Any]) -> set[str]:
    """Column names from raw ``create_table`` arguments.

    Only used by the two table-set tests, which run before the reconstructed metadata is
    trustworthy; everything else compares real ``Table`` objects via the ``migrated``
    fixture.
    """
    return {arg.name for arg in create_table_args if isinstance(arg, sa.Column)}


# ---------------------------------------------------------------------------
# Tables and columns
# ---------------------------------------------------------------------------


def test_the_migration_creates_every_model_table(recorded: OpRecorder) -> None:
    missing = sorted(set(_model_tables()) - set(recorded.tables))
    assert not missing, f"models declare tables the migration does not create: {missing}"


def test_the_migration_creates_no_unknown_tables(recorded: OpRecorder) -> None:
    extra = sorted(set(recorded.tables) - set(_model_tables()) - LANGGRAPH_TABLES)
    assert not extra, f"the migration creates tables no model declares: {extra}"


@pytest.mark.parametrize("table_name", sorted(_model_tables()))
def test_columns_match_per_table(migrated: sa.MetaData, table_name: str) -> None:
    """Parametrized per table so a failure names the one that drifted."""
    model_columns = {c.name for c in _model_tables()[table_name].columns}
    migration_columns = {c.name for c in migrated.tables[table_name].columns}

    missing = sorted(model_columns - migration_columns)
    extra = sorted(migration_columns - model_columns)
    assert not missing, f"{table_name}: migration is missing {missing}"
    assert not extra, f"{table_name}: migration has columns no model declares: {extra}"


@pytest.mark.parametrize("table_name", sorted(_model_tables()))
def test_nullability_matches_per_table(migrated: sa.MetaData, table_name: str) -> None:
    """A column that is NOT NULL in the model but nullable in the database accepts rows
    the application assumes cannot exist -- ``organization_id`` above all."""
    model_nullable = {c.name: c.nullable for c in _model_tables()[table_name].columns}
    for column in migrated.tables[table_name].columns:
        expected = model_nullable[column.name]
        assert column.nullable == expected, (
            f"{table_name}.{column.name}: migration nullable={column.nullable}, "
            f"model nullable={expected}"
        )


@pytest.mark.parametrize("table_name", sorted(_model_tables()))
def test_column_types_match_per_table(migrated: sa.MetaData, table_name: str) -> None:
    """Compared by rendered DDL type, which is what the database actually enforces.

    A ``String(200)`` that the migration wrote as ``String(20)`` truncates real data, and
    a ``JSONB`` written as ``Text`` silently turns structured evidence into a string.
    """
    dialect = postgresql.dialect()
    model_types = {c.name: c.type.compile(dialect) for c in _model_tables()[table_name].columns}
    for column in migrated.tables[table_name].columns:
        expected = model_types[column.name]
        actual = column.type.compile(dialect)
        assert (
            actual == expected
        ), f"{table_name}.{column.name}: migration has {actual}, model has {expected}"


# ---------------------------------------------------------------------------
# Tenant columns specifically -- SEC-003 depends on these existing in the database
# ---------------------------------------------------------------------------


def test_every_tenant_table_gets_its_column_fk_and_index(migrated: sa.MetaData) -> None:
    """The three pieces the repository layer assumes: column, cascade, index.

    ``tenant_select`` filters on ``organization_id``; if the migration omitted the column
    for one table, every query against it would fail at runtime, and if it omitted the
    index the filter would still be correct but seq-scan the table.
    """
    from app.db.repository import is_tenant_scoped

    checked = 0
    for model in (mapper.class_ for mapper in Base.registry.mappers):
        if not is_tenant_scoped(model):
            continue
        checked += 1
        table = migrated.tables[model.__tablename__]

        assert "organization_id" in table.c, f"{table.name}: no organization_id column"
        column = table.c["organization_id"]
        assert not column.nullable, f"{table.name}: organization_id is nullable"

        cascades = [fk for fk in column.foreign_keys if fk.ondelete == "CASCADE"]
        assert cascades, f"{table.name}: organization_id has no ON DELETE CASCADE foreign key"

        indexed = any("organization_id" in {c.name for c in idx.columns} for idx in table.indexes)
        assert indexed, f"{table.name}: organization_id is not indexed"

    assert checked >= 15, f"only checked {checked} tenant tables; the sweep found too few"


# ---------------------------------------------------------------------------
# Indexes and constraints
# ---------------------------------------------------------------------------


def test_every_model_index_is_created(recorded: OpRecorder) -> None:
    """Covers both ``index=True`` columns and explicit ``Index(...)`` declarations."""
    created = {(table, columns) for _name, table, columns, _unique in recorded.indexes}
    missing: list[str] = []

    for name, table in _model_tables().items():
        for index in table.indexes:
            key = (name, tuple(c.name for c in index.columns))
            if key not in created:
                missing.append(f"{name}({', '.join(key[1])})")
        for column in table.columns:
            if column.index and (name, (column.name,)) not in created:
                missing.append(f"{name}({column.name})")

    assert not missing, f"the migration does not create: {sorted(set(missing))}"


def test_index_names_are_unique(recorded: OpRecorder) -> None:
    """Postgres index names are database-wide, so a duplicate fails the whole migration."""
    names = [name for name, _table, _columns, _unique in recorded.indexes]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert not duplicates, f"duplicate index names: {duplicates}"


@pytest.mark.parametrize("table_name", sorted(_model_tables()))
def test_unique_constraints_match(migrated: sa.MetaData, table_name: str) -> None:
    """Deduplication depends on these. ``assets.unique_asset`` in particular is what
    keeps a rediscovered host from becoming a second row."""

    def uniques(table: sa.Table) -> set[tuple[str, ...]]:
        found = {
            tuple(sorted(c.name for c in constraint.columns))
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }
        #: A unique index is an equivalent expression of the same guarantee.
        found |= {
            tuple(sorted(c.name for c in index.columns)) for index in table.indexes if index.unique
        }
        return found

    expected = uniques(_model_tables()[table_name])
    found = uniques(migrated.tables[table_name])
    missing = sorted(expected - found)
    assert not missing, f"{table_name}: migration is missing unique constraints {missing}"


@pytest.mark.parametrize("table_name", sorted(_model_tables()))
def test_check_constraints_match(migrated: sa.MetaData, table_name: str) -> None:
    """Cynux uses varchar + CHECK rather than native enums, so the CHECKs *are* the enum.

    Compared by name and by SQL text: a dropped CHECK lets the database hold a status no
    code path handles, and an altered one silently widens the accepted set.
    """

    def checks(table: sa.Table) -> dict[str, str]:
        return {
            constraint.name: str(constraint.sqltext)
            for constraint in table.constraints
            if isinstance(constraint, sa.CheckConstraint) and constraint.name
        }

    expected = checks(_model_tables()[table_name])
    found = checks(migrated.tables[table_name])

    assert not sorted(
        set(expected) - set(found)
    ), f"{table_name}: migration is missing checks {sorted(set(expected) - set(found))}"
    # Checked in both directions. A CHECK that exists only in the migration is drift
    # too, and the more confusing kind: the model says a value is legal, the database
    # rejects it, and the failure surfaces as an IntegrityError from a write that every
    # unit test -- which never touches Postgres -- reports as fine.
    assert not sorted(set(found) - set(expected)), (
        f"{table_name}: migration has checks the model does not declare "
        f"{sorted(set(found) - set(expected))}"
    )
    for name, sqltext in expected.items():
        assert (
            found[name] == sqltext
        ), f"{table_name}.{name}: migration has {found[name]!r}, model has {sqltext!r}"


@pytest.mark.parametrize("table_name", sorted(_model_tables()))
def test_foreign_keys_match(migrated: sa.MetaData, table_name: str) -> None:
    """Including ``ondelete``. A missing CASCADE leaves orphans; an unintended one
    deletes a customer's findings when an assessment is tidied up."""

    def keys(table: sa.Table) -> set[tuple[str, str, str]]:
        return {
            (fk.parent.name, fk.target_fullname, fk.ondelete or "") for fk in table.foreign_keys
        }

    expected = keys(_model_tables()[table_name])
    found = keys(migrated.tables[table_name])
    assert found == expected, (
        f"{table_name}: foreign keys differ.\n"
        f"  only in model:     {sorted(expected - found)}\n"
        f"  only in migration: {sorted(found - expected)}"
    )


# ---------------------------------------------------------------------------
# Reversibility
# ---------------------------------------------------------------------------


def test_downgrade_drops_everything_upgrade_created(
    recorded: OpRecorder, recorded_downgrade: OpRecorder
) -> None:
    assert set(recorded_downgrade.dropped_tables) == set(
        recorded.tables
    ), "downgrade does not drop exactly the tables upgrade creates"
    created_indexes = {name for name, _t, _c, _u in recorded.indexes}
    dropped_indexes = {name for name, _t in recorded_downgrade.dropped_indexes}
    assert created_indexes == dropped_indexes, (
        f"index create/drop mismatch: only created {sorted(created_indexes - dropped_indexes)}, "
        f"only dropped {sorted(dropped_indexes - created_indexes)}"
    )


def test_downgrade_drops_tables_in_reverse_dependency_order(
    recorded: OpRecorder, recorded_downgrade: OpRecorder
) -> None:
    """A child table must be dropped before its parent, or the FK blocks the drop."""
    order = {name: i for i, name in enumerate(recorded_downgrade.dropped_tables)}
    for name, table in _model_tables().items():
        for fk in table.foreign_keys:
            parent = fk.column.table.name
            if parent == name or parent not in order:
                continue
            assert order[name] < order[parent], f"downgrade drops {parent} before its child {name}"


def test_tables_are_created_in_dependency_order(recorded: OpRecorder) -> None:
    """The mirror of the above: a FK cannot reference a table that does not exist yet."""
    order = {name: i for i, name in enumerate(recorded.tables)}
    for name, table in _model_tables().items():
        for fk in table.foreign_keys:
            parent = fk.column.table.name
            if parent == name or parent not in order:
                continue
            assert (
                order[parent] < order[name]
            ), f"{name} is created before the table it references, {parent}"
