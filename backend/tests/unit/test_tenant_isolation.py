"""SEC-003: one organization must never reach another's data.

The PRD names four things that must not cross a tenant boundary -- assets, findings,
conversations and scanner outputs -- and the design answer is structural rather than
per-route: :class:`~app.db.base.TenantMixin` marks a table as organization-scoped, and
:mod:`app.db.repository` refuses to build a query against such a table without a tenant
filter.  These tests attack that claim from three directions.

**Does the filter actually reach the SQL?**  Compiled statements are inspected, not
mocked.  A helper that looked right and produced ``SELECT * FROM findings`` would pass
any test that only checked it returned a ``Select``.

**Is every table that holds tenant data actually marked?**  ``test_every_tenant_table_
is_marked`` walks the whole mapper registry.  This is the test that catches the real
leak vector: not a route that forgets a filter, but a *new model* added six months from
now without the mixin, at which point ``tenant_select`` cannot protect it because it was
never asked to.

**Does a cross-tenant hit look like a 404?**  A 403 confirms the row exists, which turns
an id into an oracle for enumerating another organization's data.

No live database is required.  These are properties of the query the ORM builds and of
the model definitions, both of which are decided before anything reaches Postgres.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

from app.core.errors import TenantIsolationError
from app.db.base import Base, TenantMixin
from app.db.models import (  # noqa: F401 - imported for the side effect of registering mappers
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
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.finding import Finding
from app.db.models.identity import Organization, User
from app.db.repository import (
    TenantRepository,
    TenantScopeError,
    assert_tenant_owned,
    is_tenant_scoped,
    tenant_select,
)

ORG_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
ORG_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def compiled(stmt: Any) -> str:
    """Render a statement as Postgres SQL with its literal values inlined.

    Inlining is what makes the assertion meaningful: without it the tenant id is a
    ``$1`` placeholder and the test cannot tell org A's query from org B's.
    """
    return str(
        stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )


# ---------------------------------------------------------------------------
# Tables that hold tenant data must be marked as such
# ---------------------------------------------------------------------------

#: Every mapped model, discovered rather than listed, so a new model is covered the day
#: it is written instead of the day someone remembers to add it here.
ALL_MODELS: list[type[Base]] = sorted(
    (mapper.class_ for mapper in Base.registry.mappers),
    key=lambda model: model.__name__,
)

#: Tables that are deliberately global. Each needs a reason, because "not tenant-scoped"
#: is the dangerous answer and an unexplained entry here is how a leak gets waived in.
GLOBAL_TABLES: dict[str, str] = {
    "Organization": "is the tenant; scoping it to itself is circular",
    "User": "a person may belong to several organizations, so Membership is the scoped table",
    "Membership": "is the user-to-organization mapping rather than a scoped record",
    "AuditEvent": "organization-stamped but readable across tenants by platform operators "
    "for incident response (FR-032)",
    "PasswordResetToken": "keyed by user, and consumed before any organization is chosen",
}

#: A column whose presence means the row describes one customer's environment. If a table
#: has one of these and is not tenant-scoped, that is a leak waiting for a query.
TENANT_DATA_COLUMNS = frozenset(
    {
        "assessment_id",
        "asset_id",
        "finding_id",
        "target",
        "host",
        "session_id",
        "job_id",
    }
)


def test_at_least_one_model_is_tenant_scoped() -> None:
    """Stops the sweep below from passing vacuously if imports ever break."""
    scoped = [m for m in ALL_MODELS if is_tenant_scoped(m)]
    assert len(scoped) >= 15, f"only {len(scoped)} tenant-scoped models found"


@pytest.mark.parametrize("model", ALL_MODELS, ids=[m.__name__ for m in ALL_MODELS])
def test_every_tenant_table_is_marked(model: type[Base]) -> None:
    """A table holding customer data carries ``TenantMixin``, or is listed as global.

    The failure message names the model, because the fix is a one-line mixin addition
    and the person reading it will not have this file open.
    """
    if is_tenant_scoped(model):
        columns = {c.name for c in inspect(model).columns}
        assert "organization_id" in columns, f"{model.__name__} has the mixin but no column"
        return

    if model.__name__ in GLOBAL_TABLES:
        return

    columns = {c.name for c in inspect(model).columns}
    offending = sorted(columns & TENANT_DATA_COLUMNS)
    assert not offending, (
        f"{model.__name__} holds tenant data ({', '.join(offending)}) but is not "
        f"tenant-scoped. Add TenantMixin, or add it to GLOBAL_TABLES with a reason."
    )


def test_global_tables_list_has_no_stale_entries() -> None:
    """A waiver that no longer names a real model hides the next one that needs review."""
    names = {model.__name__ for model in ALL_MODELS}
    assert not (
        set(GLOBAL_TABLES) - names
    ), f"GLOBAL_TABLES names models that no longer exist: {sorted(set(GLOBAL_TABLES) - names)}"


def test_tenant_column_is_indexed_and_cascades() -> None:
    """The filter is on every tenant query, so it has to be indexed.

    ``ON DELETE CASCADE`` is the other half: deleting an organization must not leave
    orphaned findings that a later query could surface without a tenant filter.
    """
    for model in ALL_MODELS:
        if not is_tenant_scoped(model):
            continue
        column = inspect(model).columns["organization_id"]
        assert not column.nullable, f"{model.__name__}.organization_id is nullable"
        indexed = column.index or any(
            "organization_id" in {c.name for c in idx.columns} for idx in model.__table__.indexes
        )
        assert indexed, f"{model.__name__}.organization_id is not indexed"
        assert any(
            fk.ondelete == "CASCADE" for fk in column.foreign_keys
        ), f"{model.__name__}.organization_id does not cascade on organization delete"


# ---------------------------------------------------------------------------
# The filter reaches the SQL
# ---------------------------------------------------------------------------


def test_tenant_select_emits_an_organization_filter() -> None:
    sql = compiled(tenant_select(Finding, ORG_A))
    assert "organization_id" in sql
    assert str(ORG_A) in sql
    assert str(ORG_B) not in sql


def test_two_organizations_produce_different_sql() -> None:
    """Guards against a filter that is present but constant -- e.g. bound once at import."""
    assert compiled(tenant_select(Asset, ORG_A)) != compiled(tenant_select(Asset, ORG_B))


@pytest.mark.parametrize("model", [Assessment, Asset, Finding], ids=lambda m: m.__name__)
def test_the_four_sec_003_resources_are_filtered(model: type[Base]) -> None:
    """SEC-003 names assets, findings, conversations and scanner outputs."""
    sql = compiled(tenant_select(model, ORG_A))
    assert f"{model.__tablename__}.organization_id" in sql


def test_agent_sessions_and_scanner_jobs_are_filtered() -> None:
    """The other two SEC-003 resources: conversations and scanner outputs."""
    from app.db.models.agent import AgentSession
    from app.db.models.scanner import ScannerJob

    for model in (AgentSession, ScannerJob):
        assert is_tenant_scoped(model), f"{model.__name__} must be tenant-scoped"
        assert f"{model.__tablename__}.organization_id" in compiled(tenant_select(model, ORG_A))


def test_a_global_table_cannot_be_routed_through_tenant_select() -> None:
    """Catches filtering on a column that does not exist -- which would be a silent
    ``AttributeError`` at best and a cross-tenant read at worst."""
    for model in (User, Organization):
        with pytest.raises(TenantScopeError):
            tenant_select(model, ORG_A)  # type: ignore[type-var]


def test_repository_refuses_a_global_model() -> None:
    with pytest.raises(TenantScopeError):
        TenantRepository(None, User, ORG_A)  # type: ignore[arg-type,type-var]


# ---------------------------------------------------------------------------
# Repository statements
# ---------------------------------------------------------------------------


class RecordingSession:
    """Captures the statement instead of executing it.

    Enough of an ``AsyncSession`` for the repository's code path: the assertions are
    about the SQL the ORM built, which is fully determined before execution.
    """

    def __init__(self) -> None:
        self.statements: list[Any] = []
        self.added: list[Any] = []

    async def execute(self, stmt: Any, *args: Any, **kwargs: Any) -> Any:
        self.statements.append(stmt)
        return _EmptyResult()

    def add(self, obj: Any) -> None:
        self.added.append(obj)


class _EmptyResult:
    def scalar_one_or_none(self) -> None:
        return None

    def scalar_one(self) -> int:
        return 0

    def scalars(self) -> _EmptyResult:
        return self

    def all(self) -> list[Any]:
        return []

    @property
    def rowcount(self) -> int:
        return 0


@pytest.fixture
def repo() -> tuple[TenantRepository[Finding], RecordingSession]:
    session = RecordingSession()
    return TenantRepository(session, Finding, ORG_A), session  # type: ignore[arg-type]


async def test_every_repository_read_carries_the_tenant_filter(repo) -> None:
    """``get``, ``list``, ``count`` and ``exists`` each build their own statement.

    Testing only ``select()`` would miss ``count`` and ``exists``, which construct a
    ``select(func.count())`` by hand rather than going through it.
    """
    repository, session = repo
    await repository.get(uuid.uuid4())
    await repository.list(limit=10)
    await repository.count()
    await repository.exists(uuid.uuid4())

    assert len(session.statements) == 4
    for stmt in session.statements:
        sql = compiled(stmt)
        assert "organization_id" in sql, f"unfiltered read: {sql}"
        assert str(ORG_A) in sql, f"filtered on the wrong tenant: {sql}"


async def test_delete_is_tenant_scoped(repo) -> None:
    """An unscoped delete is worse than an unscoped read: it destroys another tenant's row."""
    repository, session = repo
    await repository.delete(uuid.uuid4())
    sql = compiled(session.statements[0])
    assert sql.startswith("DELETE FROM findings")
    assert "organization_id" in sql
    assert str(ORG_A) in sql


async def test_get_or_404_raises_a_404_not_a_403(repo) -> None:
    """A 403 confirms the row exists, turning an id into an enumeration oracle."""
    repository, _ = repo
    with pytest.raises(TenantIsolationError) as excinfo:
        await repository.get_or_404(uuid.uuid4())
    assert excinfo.value.http_status == 404
    assert "does not exist" in excinfo.value.user_message


def test_add_overwrites_a_caller_supplied_organization_id() -> None:
    """A payload copied between tenants gets corrected, not persisted.

    The stamp is unconditional for exactly this reason: a service that builds a row from
    a request body could otherwise write into another organization by echoing its id.
    """
    session = RecordingSession()
    repository: TenantRepository[Finding] = TenantRepository(session, Finding, ORG_A)  # type: ignore[arg-type]
    smuggled = Finding(organization_id=ORG_B)
    repository.add(smuggled)
    assert smuggled.organization_id == ORG_A
    assert session.added == [smuggled]


# ---------------------------------------------------------------------------
# assert_tenant_owned -- the post-lookup check
# ---------------------------------------------------------------------------


def test_assert_tenant_owned_accepts_the_owner() -> None:
    assert_tenant_owned(Finding(organization_id=ORG_A), ORG_A, resource="Finding")


def test_assert_tenant_owned_rejects_another_tenant_as_404() -> None:
    with pytest.raises(TenantIsolationError) as excinfo:
        assert_tenant_owned(Finding(organization_id=ORG_B), ORG_A, resource="Finding")
    assert excinfo.value.http_status == 404


def test_assert_tenant_owned_rejects_none_and_unstamped_rows() -> None:
    """``None`` means "not found"; an unset ``organization_id`` means "unknown owner".

    Both must be refused. Treating a missing owner as a match is how a partially
    constructed row becomes readable by every tenant.
    """
    with pytest.raises(TenantIsolationError):
        assert_tenant_owned(None, ORG_A, resource="Finding")
    with pytest.raises(TenantIsolationError):
        assert_tenant_owned(Finding(), ORG_A, resource="Finding")


def test_tenant_mixin_is_the_single_marker() -> None:
    """``is_tenant_scoped`` must key off the mixin, not off a column name.

    A model that happened to define ``organization_id`` without the mixin would
    otherwise look scoped to the helper while sitting outside the convention.
    """
    assert is_tenant_scoped(Finding)
    assert issubclass(Finding, TenantMixin)
    assert not is_tenant_scoped(User)
    assert not is_tenant_scoped(object)
    assert not is_tenant_scoped("Finding")  # type: ignore[arg-type]
