"""Dashboard counts for connected-tool alert triage."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.db.models.assessment import Assessment, AssessmentTarget
from app.db.models.audit import AuditEvent
from app.db.models.identity import User


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
    sql = str(
        session.statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert f"external_security_alerts.organization_id = '{org_id}'" in sql
    assert sql.count("external_security_alerts.status = 'open'") == 2
    assert (
        "external_security_alerts.triage_status NOT IN ('closed', 'false_positive', 'risk_accepted')"
        in sql
    )
    assert "external_security_alerts.triage_status = 'new'" in sql


@pytest.mark.asyncio
async def test_dashboard_activity_names_external_alert_triage() -> None:
    """An analyst decision should be visible as an intelligible activity event."""
    from app.services.dashboard import _activity

    org_id = uuid.uuid4()
    event = AuditEvent(
        id=uuid.uuid4(),
        organization_id=org_id,
        actor_email="analyst@example.test",
        actor_type="user",
        action="external_alert.triage",
        resource_type="external_security_alert",
        resource_id=str(uuid.uuid4()),
        outcome="success",
        created_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
    )
    session = _ActivitySession(event)

    activity = await _activity(session, org_id)

    assert activity[0].summary == "analyst@example.test triaged an external alert"
    sql = str(
        session.statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "'external_alert.triage'" in sql


def test_dashboard_projects_recent_assessment_relationships() -> None:
    """A demo assessment must render instead of exposing ORM relationships to Pydantic."""
    from app.services import dashboard

    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    now = dt.datetime(2026, 10, 23, tzinfo=dt.UTC)
    user = User(
        id=user_id,
        email="owner@example.com",
        password_hash="test-only",
        is_active=True,
        is_email_verified=True,
        created_at=now,
        updated_at=now,
    )
    target = AssessmentTarget(
        id=uuid.uuid4(),
        organization_id=org_id,
        assessment_id=uuid.uuid4(),
        raw_value="https://shop.example.com",
        canonical_value="https://shop.example.com/",
        target_type="url",
        host="shop.example.com",
        port=443,
        host_count=1,
        target_metadata={},
        created_at=now,
        updated_at=now,
    )
    assessment = Assessment(
        id=target.assessment_id,
        organization_id=org_id,
        reference=1,
        created_by_id=user_id,
        title="Synthetic storefront review",
        scope="external",
        depth="standard",
        engagement_type="web_application",
        execution_mode="supervised",
        status="COMPLETED",
        current_stage="done",
        progress_percent=100,
        findings_total=3,
        findings_critical=1,
        findings_high=1,
        findings_medium=1,
        findings_low=0,
        findings_info=0,
        assets_discovered=3,
        assets_in_scope=3,
        degradations=[],
        plan=[],
        request_interpretation={},
        extra_data={},
        created_at=now,
        updated_at=now,
    )
    assessment.created_by = user
    assessment.targets = [target]

    result = dashboard._project_recent_assessments([assessment])

    assert result[0].created_by == "owner@example.com"
    assert result[0].targets[0].host == "shop.example.com"
