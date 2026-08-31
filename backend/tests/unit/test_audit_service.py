"""Audit service invariants (FR-032, SEC-002).

Three of these tests exist because the alternative to writing them is a comment that
claims something nobody checks.

``_MAX_LENGTHS`` in ``app/services/audit.py`` restates the column widths so truncation
happens in Python rather than as a ``StringDataRightTruncation``.  A restated constant
drifts the moment somebody widens a column, and the failure mode is invisible: the
service keeps truncating to the old width and the extra space is never used.
:func:`test_max_lengths_matches_the_table` reads the widths back off
``AuditEvent.__table__`` so the two cannot disagree.

The ``actor_type`` vocabulary is written down in three places -- the check constraint,
:data:`~app.services.context.ACTOR_TYPES`, and the ``Literal`` on ``AuditFilter`` -- and
they were genuinely out of sync: the filter omitted ``worker``, which made every audit
row produced by queued work unfilterable.  Two tests pin all three together.

Finally, redaction: ``detail`` is the one field that carries arbitrary structured
context into a durable table, so it goes through the logger's redactor.  The test asserts
on both halves of that -- key-based (``{"api_key": ...}``) and value-based
(``"...?token=..."``) -- because a payload built from a tool result carries secrets in
values, not in field names.
"""

from __future__ import annotations

import re
import uuid
from types import TracebackType
from typing import Any, Literal, Union, get_args, get_origin

import pytest
from sqlalchemy import CheckConstraint, String

from app.core.errors import IntegrationError, PermissionDeniedError
from app.core.logging_conf import REDACTED
from app.db.enums import AuditOutcome, Role
from app.db.models import AuditEvent
from app.schemas.audit import AuditFilter
from app.services import audit
from app.services.audit import AuditAction
from app.services.context import ACTOR_SYSTEM, ACTOR_TYPES, Principal

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class RecordingSession:
    """The two ``AsyncSession`` methods :func:`audit.record` actually uses.

    Not a mock of the audit service -- the code under test is real, and every assertion
    below reads the ``AuditEvent`` it constructed.  Only the database is absent, which is
    the point: truncation and redaction must happen before the insert, so they must be
    observable without one.
    """

    def __init__(self) -> None:
        self.added: list[AuditEvent] = []
        self.flushes = 0

    def add(self, obj: AuditEvent) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushes += 1

    @property
    def only(self) -> AuditEvent:
        assert len(self.added) == 1, f"expected exactly one audit row, got {len(self.added)}"
        return self.added[0]


class ExplodingScope:
    """A ``session_scope`` replacement that fails the way a dead database does."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.entered = 0

    def __call__(self, *args: Any, **kwargs: Any) -> ExplodingScope:
        return self

    async def __aenter__(self) -> RecordingSession:
        self.entered += 1
        raise self.exc

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        return False


@pytest.fixture
def session() -> RecordingSession:
    return RecordingSession()


@pytest.fixture
def principal() -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=Role.OWNER,
        email="operator@example.com",
        source_ip="203.0.113.7",
        user_agent="cynux-tests/1.0",
        request_id="req-1234",
        trace_id="trace-1234",
    )


def _check_values(declared_name: str) -> set[str]:
    """The quoted literals of a named ``IN (...)`` check constraint.

    Looked up under the generated name, not the declared one: ``NAMING_CONVENTION`` in
    ``app/db/base.py`` rewrites ``valid_outcome`` to ``ck_audit_events_valid_outcome``,
    and a lookup on the declared name silently finds nothing.
    """
    table = AuditEvent.__table__
    generated = f"ck_{table.name}_{declared_name}"
    for constraint in table.constraints:
        if isinstance(constraint, CheckConstraint) and constraint.name == generated:
            return set(re.findall(r"'([^']+)'", str(constraint.sqltext)))
    raise AssertionError(f"no check constraint named {generated!r} on {table.name}")


# ---------------------------------------------------------------------------
# Column widths
# ---------------------------------------------------------------------------


def test_max_lengths_matches_the_table() -> None:
    """Every restated width equals the real ``String`` length, and none is missing.

    The reverse direction matters as much as the forward one. A new ``String`` column
    that the service writes but ``_MAX_LENGTHS`` does not know about would raise
    ``KeyError`` in ``_fit`` -- or, if written without ``_fit``, would be the exact
    unbounded insert this table's truncation exists to prevent.
    """
    columns = AuditEvent.__table__.c
    for field, declared in audit._MAX_LENGTHS.items():
        column = columns[field]
        assert isinstance(column.type, String), f"{field} is not a String column"
        assert column.type.length == declared, (
            f"audit_events.{field} is String({column.type.length}) but _MAX_LENGTHS "
            f"says {declared}; widening a column without updating the service means it "
            f"keeps truncating to the old width"
        )

    #: ``detail`` is JSONB and ``reason`` is ``Text``; both are bounded by
    #: ``_MAX_DETAIL_CHARS`` / ``_MAX_REASON`` instead, which is why they are absent.
    unbounded = {"detail", "reason"}
    string_columns = {c.name for c in columns if isinstance(c.type, String)}
    assert string_columns - unbounded == set(
        audit._MAX_LENGTHS
    ), "every String column on audit_events needs a _MAX_LENGTHS entry"


@pytest.mark.parametrize(
    ("field", "value_length"),
    [("source_ip", 200), ("user_agent", 4000), ("request_id", 300), ("trace_id", 300)],
)
def test_oversized_request_metadata_is_truncated(field: str, value_length: int) -> None:
    """A client controls all four of these headers; none may reach the insert unbounded."""
    limit = audit._MAX_LENGTHS[field]
    fitted = audit._fit("x" * value_length, field)
    assert fitted is not None
    assert len(fitted) == limit


def test_fit_passes_short_values_through_unchanged() -> None:
    assert audit._fit("203.0.113.7", "source_ip") == "203.0.113.7"
    assert audit._fit(None, "source_ip") is None


async def test_record_truncates_principal_provenance(session: RecordingSession) -> None:
    """End to end: an absurd ``User-Agent`` produces a row, not a failed transaction.

    An audit write that raises does not merely lose one row -- it poisons the caller's
    transaction, so the audited request fails too. An attacker who can reliably make
    audit writes fail can act unobserved.
    """
    hostile = Principal(
        user_id=None,
        organization_id=uuid.uuid4(),
        role=Role.VIEWER,
        email="e" * 500,
        user_agent="A" * 9000,
        source_ip="f" * 200,
        actor_type="worker",
    )
    event = await audit.record(
        session,  # type: ignore[arg-type]
        action=AuditAction.LOGIN,
        principal=hostile,
    )
    assert len(event.user_agent or "") == audit._MAX_LENGTHS["user_agent"]
    assert len(event.actor_email or "") == audit._MAX_LENGTHS["actor_email"]
    assert len(event.source_ip or "") == audit._MAX_LENGTHS["source_ip"]
    assert session.flushes == 1


async def test_record_bounds_reason(session: RecordingSession) -> None:
    await audit.record(
        session,  # type: ignore[arg-type]
        action=AuditAction.SCANNER_FAIL,
        reason="z" * 50_000,
    )
    assert len(session.only.reason or "") == audit._MAX_REASON


# ---------------------------------------------------------------------------
# The action vocabulary
# ---------------------------------------------------------------------------


def _action_values() -> dict[str, str]:
    return {
        name: value
        for name, value in vars(AuditAction).items()
        if not name.startswith("_") and isinstance(value, str)
    }


def test_every_action_fits_the_column() -> None:
    limit = audit._MAX_LENGTHS["action"]
    for name, value in _action_values().items():
        assert len(value) <= limit, f"AuditAction.{name} is {len(value)} chars, limit {limit}"


def test_actions_are_unique() -> None:
    """Two constants sharing a value make one of them unqueryable."""
    values = _action_values()
    duplicates = {v for v in values.values() if list(values.values()).count(v) > 1}
    assert not duplicates, f"duplicate audit actions: {sorted(duplicates)}"


def test_actions_are_lower_case_dotted() -> None:
    """``list_audit_events`` prefix-matches with ``like``, not ``ilike``.

    A single upper-case action would be silently unreachable through the API's action
    filter, because the index-friendly case-sensitive match would never hit it.
    """
    for name, value in _action_values().items():
        assert value == value.lower(), f"AuditAction.{name} is not lower-case"
        assert "." in value, f"AuditAction.{name} has no subject prefix"
        assert re.fullmatch(
            r"[a-z0-9_]+(\.[a-z0-9_]+)+", value
        ), f"AuditAction.{name} = {value!r} is not a dotted verb"


def test_frs_that_name_an_event_have_an_action() -> None:
    """FR-032 enumerates what must be recorded; each needs a verb to record it with."""
    values = set(_action_values().values())
    required = {
        "auth.login",
        "auth.login.failed",
        "assessment.create",
        "assessment.cancel",
        "approval.granted",
        "approval.rejected",
        "scanner.start",
        "scanner.complete",
        "integration.configure",
        "finding.status.change",
        "ticket.create",
        "report.generate",
        "authz.permission.denied",
        "agent.tool.invoke",
    }
    assert required <= values, f"FR-032 events with no action: {sorted(required - values)}"


# ---------------------------------------------------------------------------
# The actor_type vocabulary, in all three places it is written down
# ---------------------------------------------------------------------------


def test_actor_types_match_the_check_constraint() -> None:
    assert _check_values("valid_actor_type") == set(ACTOR_TYPES)


def test_audit_filter_can_express_every_actor_type() -> None:
    """The regression this file was written for.

    ``AuditFilter.actor_type`` was ``Literal["user", "agent", "system"]`` while the
    column legally holds ``worker`` -- so every row written by the queue was invisible to
    the audit API's filter. A filter that cannot name a value the column holds is not a
    narrower filter, it is a blind spot.
    """
    annotation = AuditFilter.model_fields["actor_type"].annotation
    literals: set[str] = set()
    for arg in get_args(annotation) if get_origin(annotation) in (Union,) else (annotation,):
        if get_origin(arg) is Literal:
            literals |= set(get_args(arg))
    assert literals == set(ACTOR_TYPES)


def test_outcomes_match_the_check_constraint() -> None:
    assert _check_values("valid_outcome") == set(AuditOutcome.values())


async def test_record_without_a_principal_is_attributed_to_the_system(
    session: RecordingSession,
) -> None:
    """A failed login has no principal and no organization; it is still an audit row."""
    event = await audit.record(
        session,  # type: ignore[arg-type]
        action=AuditAction.LOGIN_FAILED,
        outcome=AuditOutcome.FAILURE,
        reason="invalid credentials",
    )
    assert event.actor_type == ACTOR_SYSTEM
    assert event.organization_id is None
    assert event.actor_id is None
    assert event.outcome == AuditOutcome.FAILURE.value


# ---------------------------------------------------------------------------
# Redaction and size bounds on ``detail`` (SEC-002, SEC-006)
# ---------------------------------------------------------------------------


async def test_detail_is_key_redacted(session: RecordingSession, principal: Principal) -> None:
    await audit.record(
        session,  # type: ignore[arg-type]
        action=AuditAction.INTEGRATION_CONFIGURE,
        principal=principal,
        detail={"provider": "jira", "api_token": "hunter2-real-token", "base_url": "https://j"},
    )
    detail = session.only.detail
    assert detail["api_token"] == REDACTED
    assert detail["provider"] == "jira"


async def test_detail_is_value_redacted(session: RecordingSession, principal: Principal) -> None:
    """A tool result carries credentials in values, not in field names.

    ``{"url": ".../v1?api_key=..."}`` has an innocent key. Key-based scrubbing alone
    would write the credential to a table that outlives every log rotation.
    """
    await audit.record(
        session,  # type: ignore[arg-type]
        action=AuditAction.AGENT_TOOL_INVOKE,
        principal=principal,
        detail={"url": "https://nvd.example/api?apiKey=abc123def456", "tool": "nvd_lookup"},
    )
    detail = session.only.detail
    assert "abc123def456" not in detail["url"]
    assert REDACTED in detail["url"]
    assert detail["tool"] == "nvd_lookup"


async def test_detail_redacts_nested_structures(
    session: RecordingSession, principal: Principal
) -> None:
    await audit.record(
        session,  # type: ignore[arg-type]
        action=AuditAction.INTEGRATION_CREDENTIAL_UPDATE,
        principal=principal,
        detail={"config": {"jira": {"password": "s3cret", "user": "svc"}}},
    )
    assert session.only.detail["config"]["jira"]["password"] == REDACTED
    assert session.only.detail["config"]["jira"]["user"] == "svc"


def test_bounded_replaces_oversized_values_with_a_marker() -> None:
    """The row still records that something large was there, and how large.

    Dropping the key would leave a reader unable to tell a small event from a truncated
    one -- and an audit trail whose omissions are invisible is worse than one with gaps
    it admits to.
    """
    huge = "L" * (audit._MAX_DETAIL_CHARS + 1)
    out = audit._bounded({"stdout": huge, "exit_code": 1})
    assert out["stdout"].startswith("[omitted:")
    assert str(len(huge)) in out["stdout"]
    assert out["exit_code"] == 1


def test_bounded_keeps_small_keys_after_a_large_one() -> None:
    """The regression this fix was written for.

    Charging the omission marker against the budget instead of zeroing it is what keeps
    ``exit_code`` in the row. In a scanner failure ``exit_code: 137`` is the field that
    says "OOM-killed" -- the single most useful thing in the event -- and an
    implementation that spent the whole budget on the preceding 8 KB of stdout would
    write a row that recorded only that stdout was long.
    """
    out = audit._bounded(
        {
            "stdout": "L" * (audit._MAX_DETAIL_CHARS + 1),
            "exit_code": 137,
            "scanner": "nuclei",
            "duration_seconds": 42,
        }
    )
    assert out["exit_code"] == 137
    assert out["scanner"] == "nuclei"
    assert out["duration_seconds"] == 42


def test_bounded_keeps_payloads_under_budget_intact() -> None:
    payload = {"a": "x" * 100, "b": "y" * 100, "n": 7}
    assert audit._bounded(payload) == payload


def test_bounded_budget_is_cumulative() -> None:
    """Many medium values add up to the same problem one huge value causes."""
    half = "m" * (audit._MAX_DETAIL_CHARS // 2 + 10)
    out = audit._bounded({"first": half, "second": half})
    assert out["first"] == half
    assert out["second"].startswith("[omitted:")


def test_bounded_stops_rather_than_filling_the_row_with_markers() -> None:
    """Once the budget cannot fit even a marker, it counts the rest and stops.

    Without this, a payload of a thousand oversized keys would produce a thousand
    omission notices -- roughly 48 KB of text explaining that nothing was recorded, which
    is a worse row than the one it was protecting against.
    """
    oversized = {f"k{i}": "z" * 2000 for i in range(20)}
    out = audit._bounded(oversized)
    assert "_truncated_keys" in out
    assert out["_truncated_keys"] > 0
    assert len(out) < len(oversized)
    # Total serialized size stays within a small multiple of the budget rather than
    # scaling with the input.
    assert len(repr(out)) < audit._MAX_DETAIL_CHARS * 2


async def test_empty_detail_is_a_dict_not_none(session: RecordingSession) -> None:
    """The column is ``nullable=False``; ``None`` would be an insert error, not a no-op."""
    await audit.record(session, action=AuditAction.LOGOUT)  # type: ignore[arg-type]
    assert session.only.detail == {}


# ---------------------------------------------------------------------------
# Denials, errors and independent writes
# ---------------------------------------------------------------------------


async def test_record_denial_forces_the_denied_outcome(
    session: RecordingSession, principal: Principal
) -> None:
    event = await audit.record_denial(
        session,  # type: ignore[arg-type]
        action=AuditAction.PERMISSION_DENIED,
        principal=principal,
        reason="viewer lacks assessment:create",
    )
    assert event.outcome == AuditOutcome.DENIED.value


async def test_record_error_writes_the_user_safe_message(
    session: RecordingSession, principal: Principal
) -> None:
    """``reason`` must be ``user_message``, never ``str(error)`` (SEC-002).

    The internal message here embeds a token in a provider URL, the way a real driver
    error does; the audit trail is readable by anyone with ``audit:read``.
    """
    error = IntegrationError("401 from https://jira.internal?token=abcdef", provider="jira")
    assert "abcdef" in str(error), "the fixture must actually carry a secret to be a test"

    event = await audit.record_error(
        session,  # type: ignore[arg-type]
        action=AuditAction.INTEGRATION_TEST,
        principal=principal,
        error=error,
    )
    assert event.reason == error.user_message
    assert "abcdef" not in (event.reason or "")
    assert "abcdef" not in repr(event.detail)
    assert event.outcome == AuditOutcome.FAILURE.value
    assert event.detail["error_category"] == "integration_error"


async def test_record_independently_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """It is called from exception handlers.

    An audit failure that propagated would replace the error being reported -- the caller
    would see ``OperationalError`` where it meant to raise ``PermissionDeniedError``, and
    the actual denial would never reach the client.
    """
    boom = ExplodingScope(RuntimeError("database is gone"))
    monkeypatch.setattr(audit, "session_scope", boom)
    ok = await audit.record_independently(
        action=AuditAction.TENANT_VIOLATION,
        reason="cross-tenant read attempt",
    )
    assert ok is False
    assert boom.entered == 1


async def test_record_independently_reports_success(monkeypatch: pytest.MonkeyPatch) -> None:
    written = RecordingSession()

    class Scope:
        def __call__(self, *args: Any, **kwargs: Any) -> Scope:
            return self

        async def __aenter__(self) -> RecordingSession:
            return written

        async def __aexit__(self, *exc: Any) -> bool:
            return False

    monkeypatch.setattr(audit, "session_scope", Scope())
    ok = await audit.record_independently(
        action=AuditAction.LOGIN_FAILED,
        reason="invalid credentials",
        outcome=AuditOutcome.FAILURE,
    )
    assert ok is True
    assert written.only.action == AuditAction.LOGIN_FAILED


# ---------------------------------------------------------------------------
# Query construction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("100%", "100\\%"),
        ("a_b", "a\\_b"),
        ("back\\slash", "back\\\\slash"),
        ("plain", "plain"),
    ],
)
def test_escape_like_neutralizes_wildcards(raw: str, expected: str) -> None:
    """``%`` alone matches every row: a full scan of the largest table, on request."""
    assert audit._escape_like(raw) == expected


def test_escape_like_escapes_the_backslash_first() -> None:
    """Order matters: escaping ``%`` before ``\\`` would double-escape the introducer."""
    assert audit._escape_like("\\%") == "\\\\\\%"


async def test_reads_require_the_audit_permission() -> None:
    """A viewer cannot read the trail, and the check precedes any query construction.

    ``None`` is passed as the session on purpose: if the permission check ever moved
    below the first ``session.execute``, these would fail with ``AttributeError``
    instead of passing, which is a louder signal than a mocked session would give.
    """
    viewer = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        await audit.list_audit_events(None, viewer)  # type: ignore[arg-type]
    with pytest.raises(PermissionDeniedError):
        await audit.resource_history(
            None,  # type: ignore[arg-type]
            viewer,
            resource_type="assessment",
            resource_id=uuid.uuid4(),
        )
