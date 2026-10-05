"""Local triage must be isolated from source-owned alert state."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from app.core.errors import ConflictError, PermissionDeniedError, TenantIsolationError
from app.db.enums import Role
from app.db.models.external_alert import ExternalSecurityAlert
from app.services.context import Principal


class _Result:
    def __init__(self, row: ExternalSecurityAlert | None) -> None:
        self.row = row

    def scalar_one_or_none(self) -> ExternalSecurityAlert | None:
        return self.row


class _Session:
    def __init__(self, row: ExternalSecurityAlert | None) -> None:
        self.row = row
        self.statements: list[Any] = []
        self.added: list[Any] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return _Result(self.row)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass


def _principal(role: Role = Role.SECURITY_ENGINEER) -> Principal:
    return Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=role,
        email="analyst@example.test",
    )


def _alert(principal: Principal) -> ExternalSecurityAlert:
    return ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=principal.organization_id,
        provider="github", external_id="dependabot:7", category="dependabot",
        title="Vulnerable package", severity="high", status="open",
        triage_status="new", triage_version=0,
        cve_ids=["CVE-2026-1234"], evidence={}, raw_payload={},
    )


def test_risk_acceptance_requires_a_rationale() -> None:
    """A risk acceptance without an operator rationale cannot be audited meaningfully."""
    from app.schemas.external_alert import ExternalAlertTriageIn

    with pytest.raises(ValidationError):
        ExternalAlertTriageIn(status="risk_accepted", expected_version=0)
    with pytest.raises(ValidationError):
        ExternalAlertTriageIn(status="false_positive", note="  ", expected_version=0)
    assert ExternalAlertTriageIn(status="investigating", expected_version=0).note is None


@pytest.mark.asyncio
async def test_triage_updates_local_state_and_audits_without_changing_provider_status() -> None:
    """A source resync must never be confused with an operator's local disposition."""
    from app.services.external_alert import triage_external_alert

    principal = _principal()
    row = _alert(principal)
    session = _Session(row)

    result = await triage_external_alert(
        session, principal, row.id,
        status="risk_accepted", note="Mitigated by network isolation.", expected_version=0,
    )

    assert result is row
    assert row.status == "open"
    assert row.triage_status == "risk_accepted"
    assert row.triage_note == "Mitigated by network isolation."
    assert row.triage_version == 1
    assert row.triaged_by_user_id == principal.user_id
    assert row.triaged_at is not None
    sql = str(session.statements[0].compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert f"organization_id = '{principal.organization_id}'" in sql
    assert f"external_security_alerts.id = '{row.id}'" in sql
    assert "FOR UPDATE" in sql
    assert len(session.added) == 1
    assert session.added[0].action == "external_alert.triage"
    assert session.added[0].detail == {"from": "new", "to": "risk_accepted", "version": 1}


@pytest.mark.asyncio
async def test_triage_rejects_stale_edits_and_other_tenant_ids() -> None:
    """A stale screen must not silently overwrite another analyst's decision."""
    from app.services.external_alert import triage_external_alert

    principal = _principal()
    row = _alert(principal)
    row.triage_version = 3
    session = _Session(row)
    with pytest.raises(ConflictError):
        await triage_external_alert(
            session, principal, row.id,
            status="investigating", note=None, expected_version=2,
        )
    assert row.triage_status == "new"
    assert session.added == []

    with pytest.raises(TenantIsolationError):
        await triage_external_alert(
            _Session(None), principal, uuid.uuid4(),
            status="investigating", note=None, expected_version=0,
        )


@pytest.mark.asyncio
async def test_viewer_cannot_triage_an_external_alert() -> None:
    """Read-only users must not change local decisions or audit state."""
    from app.services.external_alert import triage_external_alert

    principal = _principal(Role.VIEWER)
    session = _Session(_alert(principal))
    with pytest.raises(PermissionDeniedError):
        await triage_external_alert(
            session, principal, session.row.id,  # type: ignore[union-attr]
            status="investigating", note=None, expected_version=0,
        )
    assert session.statements == []
