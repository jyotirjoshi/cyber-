"""Dashboard counts for connected-tool alert triage."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.db.models.audit import AuditEvent


class _Result:
    def one(self) -> tuple[int, int]:
        return (9, 4)


class _Session:
    def __init__(self) -> None:
        self.statement: Any = None

    async def execute(self, statement: Any) -> _Result:
        self.statement = statement
        return _Result()


class _ActivityResult:
    def __init__(self, event: AuditEvent) -> None:
        self.event = event

    def scalars(self) -> _ActivityResult:
        return self

    def all(self) -> list[AuditEvent]:
        return [self.event]


class _ActivitySession:
    def __init__(self, event: AuditEvent) -> None:
        self.event = event
        self.statement: Any = None

    async def execute(self, statement: Any) -> _ActivityResult:
        self.statement = statement
        return _ActivityResult(self.event)


@pytest.mark.asyncio
async def test_dashboard_external_counts_include_only_tenant_actionable_alerts() -> None:
    """Counting closed/accepted or another tenant's alerts inflates the action queue."""
    from app.services.dashboard import _external_alert_counts

    org_id = uuid.uuid4()
    session = _Session()

    assert await _external_alert_counts(session, org_id) == (9, 4)
    sql = str(session.statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert f"external_security_alerts.organization_id = '{org_id}'" in sql
    assert sql.count("external_security_alerts.status = 'open'") == 2
    assert "external_security_alerts.triage_status NOT IN ('closed', 'false_positive', 'risk_accepted')" in sql
    assert "external_security_alerts.triage_status = 'new'" in sql


@pytest.mark.asyncio
async def test_dashboard_activity_names_external_alert_triage() -> None:
    """An analyst decision should be visible as an intelligible activity event."""
    from app.services.dashboard import _activity

    org_id = uuid.uuid4()
    event = AuditEvent(
        id=uuid.uuid4(), organization_id=org_id, actor_email="analyst@example.test",
        actor_type="user", action="external_alert.triage",
        resource_type="external_security_alert", resource_id=str(uuid.uuid4()),
        outcome="success", created_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
    )
    session = _ActivitySession(event)

    activity = await _activity(session, org_id)

    assert activity[0].summary == "analyst@example.test triaged an external alert"
    sql = str(session.statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "'external_alert.triage'" in sql
