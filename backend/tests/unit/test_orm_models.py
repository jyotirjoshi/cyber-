"""Runtime ORM checks that ``tools/verify.py`` cannot perform.

``tools/verify.py`` is AST-only: it never imports the models, so it cannot call
``configure_mappers()`` or read the runtime mapper registry.  That keeps it fast and
free of side effects, but it puts three kinds of correctness out of its reach.

**Mapper configuration.**  SQLAlchemy resolves the mapper graph lazily, so a typo in a
``back_populates`` string or a missing foreign key raises on the first query rather than
at import.  In an async session the resulting error is a greenlet failure far from the
attribute access that caused it.  :func:`test_configure_mappers_succeeds` forces the
resolution up front.

**The lazy-loading policy.**  AST verification confirms every ``relationship()`` call
passes ``lazy=LAZY``; only a runtime check confirms ``LAZY`` still *means*
``"raise_on_sql"``.

**The enum CHECK constraints.**  ``app.db.enums`` states the storage design: plain
``str`` enums in ``varchar`` columns "with a check constraint", chosen over native
``ENUM`` so that adding a value stays a one-line migration.  The CHECKs are therefore
not decoration -- they are the enum.  A column that has the varchar and not the check
accepts anything, and the failure is quiet: a case-wrong ``'scanning'`` written where
``'SCANNING'`` was meant leaves a row that reads as plausible while being invisible to
every ``status == 'SCANNING'`` query, including the one the cancellation path uses to
find running work.

Note that ``test_migration_matches_models.py`` cannot catch that gap.  It compares the
model metadata against the migration, so when *both* sides lack a constraint they agree
and it passes.  The registry below is the independent statement of what should exist.
"""

from __future__ import annotations

import re
from collections import deque
from itertools import pairwise
from typing import NamedTuple

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import configure_mappers

from app.db import models as _models  # noqa: F401 - imported for its mapper side effects
from app.db.base import LAZY, Base
from app.db.enums import (
    ALLOWED_TRANSITIONS,
    PERMISSIONS,
    AgentRunStatus,
    ApprovalDecision,
    ApprovalKind,
    ArtifactKind,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    AssetStatus,
    AuditOutcome,
    Criticality,
    CriticalitySource,
    EnrichmentStatus,
    FindingStatus,
    IntegrationKind,
    IntegrationStatus,
    JobStatus,
    MessageRole,
    NotificationChannel,
    NotificationEvent,
    NotificationStatus,
    Permission,
    Priority,
    ReportFormat,
    ReportStatus,
    RiskLevel,
    Role,
    ScannerName,
    Scope,
    Severity,
    StepStatus,
    StrEnum,
)


class EnumColumn(NamedTuple):
    """One enum-backed column and the value set its CHECK must accept."""

    table: str
    column: str
    enum: type[StrEnum]
    #: Set only where the column deliberately accepts fewer values than the enum has
    #: members.  The reason is required: a narrowing with no stated reason is
    #: indistinguishable from a value somebody forgot to add.
    narrowed_to: frozenset[str] | None = None
    reason: str = ""

    @property
    def expected(self) -> frozenset[str]:
        return self.narrowed_to or frozenset(self.enum.values())


#: Every column whose value space is a :class:`StrEnum`.
#:
#: Written out rather than derived.  Derivation was tried first -- reverse-look up the
#: enum from the column's Python default -- and it is quietly wrong: ``"pending"`` is a
#: member of six different enums, so the lookup is ambiguous exactly where enrichment
#: and approval statuses live, and a column with no default (``scanner_jobs.scanner``,
#: ``notifications.event``) is invisible to it altogether.  A derived registry that
#: skips the interesting columns passes while testing nothing.
ENUM_COLUMNS: tuple[EnumColumn, ...] = (
    # --- identity ---------------------------------------------------------
    EnumColumn("memberships", "role", Role),
    # --- assessment -------------------------------------------------------
    EnumColumn("assessments", "status", AssessmentStatus),
    EnumColumn("assessments", "current_stage", AssessmentStage),
    EnumColumn("assessments", "scope", Scope),
    EnumColumn("assessments", "depth", AssessmentDepth),
    EnumColumn("approvals", "decision", ApprovalDecision),
    EnumColumn("approvals", "kind", ApprovalKind),
    EnumColumn(
        "approvals",
        "risk_level",
        RiskLevel,
        narrowed_to=frozenset({"low", "medium", "high"}),
        reason=(
            "'forbidden' is excluded. A forbidden tool is registered but never callable "
            "(FR-034), so no operation exists for which an approval row could carry that "
            "level -- and if one could, granting it would be a route around the guardrail "
            "rather than through it. Excluding the value means the bypass cannot be "
            "represented, let alone approved."
        ),
    ),
    # --- assets -----------------------------------------------------------
    EnumColumn("assets", "status", AssetStatus),
    EnumColumn("assets", "criticality", Criticality),
    EnumColumn("assets", "criticality_source", CriticalitySource),
    # --- scanners ---------------------------------------------------------
    EnumColumn("scanner_jobs", "scanner", ScannerName),
    EnumColumn("scanner_jobs", "status", JobStatus),
    EnumColumn("scanner_artifacts", "kind", ArtifactKind),
    # --- findings ---------------------------------------------------------
    EnumColumn("findings", "severity", Severity),
    EnumColumn("findings", "status", FindingStatus),
    EnumColumn("findings", "priority", Priority),
    EnumColumn("findings", "asset_criticality", Criticality),
    EnumColumn("finding_enrichments", "status", EnrichmentStatus),
    EnumColumn("finding_enrichments", "nvd_status", EnrichmentStatus),
    EnumColumn("finding_enrichments", "kev_status", EnrichmentStatus),
    EnumColumn("finding_enrichments", "epss_status", EnrichmentStatus),
    EnumColumn("finding_enrichments", "misp_status", EnrichmentStatus),
    EnumColumn(
        "ticket_links",
        "provider",
        IntegrationKind,
        narrowed_to=frozenset({"jira", "github", "gitlab"}),
        reason=(
            "Only the three issue trackers of IntegrationKind's nine can hold a ticket. "
            "The column is half of unique_ticket_per_finding, so a variant spelling is a "
            "second row for the same finding -- the duplicate the table exists to prevent."
        ),
    ),
    # --- agent ------------------------------------------------------------
    EnumColumn("agent_messages", "role", MessageRole),
    EnumColumn("agent_runs", "status", AgentRunStatus),
    EnumColumn("agent_steps", "status", StepStatus),
    # --- integrations -----------------------------------------------------
    EnumColumn("integrations", "kind", IntegrationKind),
    EnumColumn("integrations", "status", IntegrationStatus),
    # --- notifications ----------------------------------------------------
    EnumColumn("notifications", "event", NotificationEvent),
    EnumColumn("notifications", "channel", NotificationChannel),
    EnumColumn("notifications", "status", NotificationStatus),
    # --- audit / reports --------------------------------------------------
    EnumColumn("audit_events", "outcome", AuditOutcome),
    EnumColumn("reports", "format", ReportFormat),
    EnumColumn("reports", "status", ReportStatus),
)

#: Columns constrained by a CHECK but with no enum behind them, so the sweep below does
#: not demand a registry entry.  Both are small closed vocabularies that only the
#: database and one service module ever name, which is why an enum would be ceremony.
UNBACKED_CHECKS: frozenset[tuple[str, str]] = frozenset(
    {
        ("audit_events", "actor_type"),  # user / agent / system / worker
        ("reports", "audience"),  # executive / technical
    }
)

ENUM_COLUMN_IDS = [f"{e.table}.{e.column}" for e in ENUM_COLUMNS]

#: ``<column> IN ('a','b')``, also matching the ``<col> IS NULL OR <col> IN (...)`` form
#: used for nullable columns -- the capture is the name immediately before ``IN``.
_IN_CHECK = re.compile(r"(\w+)\s+IN\s+\(([^)]*)\)", re.IGNORECASE)


def _check_texts(table: sa.Table) -> list[str]:
    return [
        str(c.sqltext) for c in table.constraints if isinstance(c, sa.CheckConstraint) and c.name
    ]


# ---------------------------------------------------------------------------
# Mapper configuration
# ---------------------------------------------------------------------------


def test_configure_mappers_succeeds() -> None:
    """Resolves every relationship, foreign key and join condition in the model layer."""
    configure_mappers()


def test_the_registry_is_populated() -> None:
    """Guards every sweep below against passing vacuously on a failed import."""
    assert len(Base.registry.mappers) >= 20
    assert len(Base.metadata.tables) >= 20


def test_every_relationship_raises_rather_than_lazy_loading() -> None:
    """``lazy="raise_on_sql"`` turns an accidental lazy load into a loud exception.

    The AST verifier checks that every ``relationship()`` passes ``lazy=LAZY``; it cannot
    check what ``LAZY`` evaluates to.  Both halves are needed.
    """
    assert LAZY == "raise_on_sql"

    offenders = [
        f"{mapper.class_.__name__}.{rel.key} is lazy={rel.lazy!r}"
        for mapper in Base.registry.mappers
        for rel in mapper.relationships
        if rel.lazy != "raise_on_sql"
    ]
    assert not offenders, "\n".join(offenders)

    total = sum(len(m.relationships) for m in Base.registry.mappers)
    assert total >= 50, f"only {total} relationships found; the sweep is not seeing the models"


def test_every_table_has_a_primary_key() -> None:
    """SQLAlchemy cannot map a table without one, and Postgres cannot replicate it."""
    missing = [
        name for name, table in Base.metadata.tables.items() if not table.primary_key.columns
    ]
    assert not missing, f"tables with no primary key: {missing}"


# ---------------------------------------------------------------------------
# Enum-backed columns carry their CHECK
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", ENUM_COLUMNS, ids=ENUM_COLUMN_IDS)
def test_enum_backed_column_has_a_check_constraint(spec: EnumColumn) -> None:
    table = Base.metadata.tables[spec.table]
    assert spec.column in table.columns, f"{spec.table}.{spec.column} does not exist"

    matches = [
        values
        for text in _check_texts(table)
        for column, values in _IN_CHECK.findall(text)
        if column == spec.column
    ]
    assert matches, (
        f"{spec.table}.{spec.column} is backed by {spec.enum.__name__} but has no "
        f"'{spec.column} IN (...)' CHECK constraint. The enum is only enforced if the "
        f"constraint exists."
    )
    assert len(matches) == 1, (
        f"{spec.table}.{spec.column} has {len(matches)} IN-constraints; two overlapping "
        f"sets means the effective vocabulary is their intersection, which nobody reads"
    )

    accepted = frozenset(re.findall(r"'([^']*)'", matches[0]))
    assert accepted == spec.expected, (
        f"{spec.table}.{spec.column}: CHECK accepts {sorted(accepted)}, "
        f"expected {sorted(spec.expected)}"
        + (f"\nnarrowing reason: {spec.reason}" if spec.narrowed_to else "")
    )


@pytest.mark.parametrize("spec", ENUM_COLUMNS, ids=ENUM_COLUMN_IDS)
def test_a_narrowed_column_states_why(spec: EnumColumn) -> None:
    """Narrowing is a security decision twice over here, so it is never implicit.

    Without a reason, a narrowed set is indistinguishable from a set somebody forgot to
    extend when the enum grew -- and the fix for those two is opposite.
    """
    if spec.narrowed_to is not None:
        assert spec.narrowed_to < frozenset(
            spec.enum.values()
        ), f"{spec.table}.{spec.column} declares a narrowing that is not a strict subset"
        assert len(spec.reason) > 40, f"{spec.table}.{spec.column} narrows with no stated reason"


def test_every_in_check_is_registered() -> None:
    """The self-maintaining half: a new ``col IN (...)`` CHECK must be declared above.

    Without this, the registry silently stops describing the schema -- the sweep keeps
    passing on the 35 columns it knows about while a 36th goes unchecked.
    """
    registered = {(e.table, e.column) for e in ENUM_COLUMNS} | UNBACKED_CHECKS
    unregistered = {
        (name, column)
        for name, table in Base.metadata.tables.items()
        for text in _check_texts(table)
        for column, _ in _IN_CHECK.findall(text)
        if (name, column) not in registered
    }
    assert not unregistered, (
        f"CHECK constraints on unregistered columns: {sorted(unregistered)}. "
        f"Add each to ENUM_COLUMNS, or to UNBACKED_CHECKS if it has no enum behind it."
    )


def test_no_native_postgres_enum_is_used() -> None:
    """``enums.py`` chose varchar + CHECK so adding a value stays a one-line migration.

    A native ``ENUM`` slipping in would need ``ALTER TYPE`` and could not be added inside
    a transaction alongside the rest of a migration.
    """
    native = [
        f"{name}.{col.name}"
        for name, table in Base.metadata.tables.items()
        for col in table.columns
        if isinstance(col.type, sa.Enum)
    ]
    assert not native, f"native Postgres enums found: {native}"


def test_json_columns_are_non_nullable_and_defaulted() -> None:
    """A JSONB column that is neither nullable nor defaulted fails every plain INSERT.

    The models use ``default=dict`` / ``default=list`` so callers never have to remember
    an empty container; the pairing is what makes that safe.
    """
    broken = [
        f"{name}.{col.name}"
        for name, table in Base.metadata.tables.items()
        for col in table.columns
        if isinstance(col.type, JSONB)
        and not col.nullable
        and col.default is None
        and col.server_default is None
    ]
    assert not broken, f"non-nullable JSONB columns with no default: {broken}"


# ---------------------------------------------------------------------------
# The FR-007 state machine
# ---------------------------------------------------------------------------


def test_every_status_has_a_transition_entry() -> None:
    """A status missing from the table raises ``KeyError`` on the first transition out of
    it, which turns a state the agent legitimately reached into a crash."""
    assert set(ALLOWED_TRANSITIONS) == set(AssessmentStatus)


def test_terminal_statuses_have_no_outgoing_transitions() -> None:
    """FR-039: a cancel arriving after completion is recorded, not applied.

    If a terminal state had an outgoing edge, a late worker callback could move a
    finished assessment back into SCANNING and the UI would show it as running forever.
    """
    for status in AssessmentStatus:
        if status.is_terminal:
            assert ALLOWED_TRANSITIONS[status] == frozenset(), (
                f"{status.value} is terminal but can transition to "
                f"{sorted(s.value for s in ALLOWED_TRANSITIONS[status])}"
            )


def test_every_status_is_reachable_from_created() -> None:
    """An unreachable status is dead vocabulary: the UI renders a label for a state the
    state machine cannot produce."""
    seen = {AssessmentStatus.CREATED}
    queue = deque([AssessmentStatus.CREATED])
    while queue:
        for nxt in ALLOWED_TRANSITIONS[queue.popleft()]:
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    unreachable = set(AssessmentStatus) - seen
    assert not unreachable, f"unreachable statuses: {sorted(s.value for s in unreachable)}"


def test_every_non_terminal_status_can_reach_a_terminal_one() -> None:
    """Otherwise an assessment can enter a state it can never leave, and the only way out
    is a manual UPDATE."""
    for status in AssessmentStatus:
        if status.is_terminal:
            continue
        seen, queue = {status}, deque([status])
        while queue and not any(s.is_terminal for s in seen):
            for nxt in ALLOWED_TRANSITIONS[queue.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        assert any(s.is_terminal for s in seen), f"{status.value} cannot reach a terminal status"


def test_cancellation_is_reachable_from_every_active_status() -> None:
    """FR-039 requires an in-flight assessment to be cancellable at any point.

    Checked against ``CANCELLING`` rather than ``CANCELLED``: cancellation is
    cooperative, so the reachable state is the request, not the outcome.
    """
    for status in AssessmentStatus:
        if status.is_terminal or status is AssessmentStatus.CANCELLING:
            continue
        assert (
            AssessmentStatus.CANCELLING in ALLOWED_TRANSITIONS[status]
        ), f"{status.value} cannot be cancelled"


def test_every_stage_is_a_legal_column_value() -> None:
    """``STAGE_ORDER`` drives the FR-038 progress tracker, and each entry is written to
    ``assessments.current_stage``. A stage the CHECK rejects would fail the update that
    reports progress, failing the assessment for a cosmetic reason."""
    from app.db.enums import STAGE_ORDER

    accepted = frozenset(
        re.findall(
            r"'([^']*)'",
            next(
                values
                for text in _check_texts(Base.metadata.tables["assessments"])
                for column, values in _IN_CHECK.findall(text)
                if column == "current_stage"
            ),
        )
    )
    assert {s.value for s in STAGE_ORDER} <= accepted
    assert AssessmentStage.QUEUED.value in accepted
    assert AssessmentStage.DONE.value in accepted


# ---------------------------------------------------------------------------
# FR-002 role permissions
# ---------------------------------------------------------------------------


def test_permissions_are_monotonic_by_role_rank() -> None:
    """A higher-ranked role holds everything the rank below it does.

    Without this, "promote the user" can silently remove a capability, and the person who
    gained authority loses access -- the least expected outcome of a promotion.
    """
    ordered = sorted(Role, key=lambda r: r.rank)
    for lower, higher in pairwise(ordered):
        assert PERMISSIONS[lower] <= PERMISSIONS[higher], (
            f"{higher.value} (rank {higher.rank}) is missing "
            f"{sorted(p.value for p in PERMISSIONS[lower] - PERMISSIONS[higher])} "
            f"held by {lower.value}"
        )


def test_every_role_has_a_permission_set() -> None:
    assert set(PERMISSIONS) == set(Role)


def test_viewer_holds_no_write_permission() -> None:
    """Pinned as a negative because the monotonicity test above cannot catch it: adding a
    write permission to VIEWER keeps every superset relation intact and silently grants
    it to all five roles."""
    writes = {
        p
        for p in Permission
        if any(
            verb in p.value
            for verb in (
                "manage",
                "create",
                "approve",
                "cancel",
                "tag",
                "analyze",
                "remediate",
                "generate",
                "chat",
            )
        )
    }
    granted = PERMISSIONS[Role.VIEWER] & writes
    assert not granted, f"viewer holds write permissions: {sorted(p.value for p in granted)}"


def test_only_senior_roles_can_approve_a_scan() -> None:
    """FR-011's gate is only meaningful if approving is not something everyone can do."""
    holders = {
        role for role, perms in PERMISSIONS.items() if Permission.ASSESSMENT_APPROVE in perms
    }
    assert holders == {Role.SECURITY_ENGINEER, Role.ADMIN, Role.OWNER}


def test_org_manage_belongs_to_the_owner_alone() -> None:
    """Admin is deliberately everything-except-this, so that an admin cannot rename,
    transfer or delete the organization that granted them the role."""
    holders = {role for role, perms in PERMISSIONS.items() if Permission.ORG_MANAGE in perms}
    assert holders == {Role.OWNER}
    assert PERMISSIONS[Role.ADMIN] == set(Permission) - {Permission.ORG_MANAGE}


def test_check_constraints_are_all_named() -> None:
    """An unnamed constraint gets a fresh generated name on every autogenerate, producing
    a drop/create pair in each migration that never converges."""
    unnamed = [
        f"{name}: {c.sqltext}"
        for name, table in Base.metadata.tables.items()
        for c in table.constraints
        if isinstance(c, sa.CheckConstraint) and not c.name
    ]
    assert not unnamed, "\n".join(unnamed)
