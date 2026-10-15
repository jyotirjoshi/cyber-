"""Automation rule safety contracts."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest


def test_automation_rule_payload_allows_only_declared_trigger_condition_and_action() -> None:
    from app.services.automation import validate_rule_definition

    rule = validate_rule_definition(
        trigger="finding.created",
        conditions={"severity_at_least": "high", "asset_environment": "production"},
        actions=[{"type": "create_ticket", "provider": "jira"}],
    )
    assert rule["trigger"] == "finding.created"
    with pytest.raises(ValueError):
        validate_rule_definition(
            trigger="shell.execute", conditions={}, actions=[{"type": "create_ticket"}]
        )
    with pytest.raises(ValueError):
        validate_rule_definition(
            trigger="finding.created",
            conditions={"severity_at_least": "urgent"},
            actions=[{"type": "create_ticket", "provider": "jira"}],
        )
    with pytest.raises(ValueError):
        validate_rule_definition(
            trigger="finding.created",
            conditions={"in_kev": "yes"},
            actions=[{"type": "create_ticket", "provider": "jira"}],
        )
    with pytest.raises(ValueError, match="ticket provider"):
        validate_rule_definition(
            trigger="finding.created",
            conditions={},
            actions=[{"type": "create_ticket", "provider": "untrusted_tracker"}],
        )


def test_ticket_close_retest_schedule_requires_recorded_authorization_reference() -> None:
    """The change that would break this is allowing a ticket event to schedule a scan without evidence."""
    from app.services.automation import validate_rule_definition

    rule = validate_rule_definition(
        trigger="ticket.closed",
        conditions={},
        actions=[{"type": "schedule_retest", "authorization_reference": "CHG-2481"}],
    )

    assert rule["actions"] == [{"type": "schedule_retest", "authorization_reference": "CHG-2481"}]
    with pytest.raises(ValueError, match="authorization_reference"):
        validate_rule_definition(
            trigger="ticket.closed", conditions={}, actions=[{"type": "schedule_retest"}]
        )


def test_notify_action_can_route_to_pagerduty_without_arbitrary_channels() -> None:
    """The change that would break this is silently dropping a PagerDuty escalation route."""
    from app.services.automation import validate_rule_definition

    rule = validate_rule_definition(
        trigger="finding.created",
        conditions={"severity_at_least": "critical"},
        actions=[{"type": "notify", "channels": ["pagerduty"]}],
    )

    assert rule["actions"] == [{"type": "notify", "channels": ["pagerduty"]}]


def test_notify_action_can_export_to_splunk() -> None:
    from app.services.automation import validate_rule_definition

    rule = validate_rule_definition(
        trigger="finding.created",
        conditions={"severity_at_least": "high"},
        actions=[{"type": "notify", "channels": ["splunk"]}],
    )

    assert rule["actions"] == [{"type": "notify", "channels": ["splunk"]}]
    with pytest.raises(ValueError, match="notification channel"):
        validate_rule_definition(
            trigger="finding.created",
            conditions={},
            actions=[{"type": "notify", "channels": ["webhook://untrusted"]}],
        )


@pytest.mark.parametrize("provider", ["github", "gitlab", "servicenow", "azure_devops"])
def test_automation_ticket_action_accepts_implemented_trackers(provider: str) -> None:
    from app.services.automation import validate_rule_definition

    assert validate_rule_definition(
        trigger="finding.created",
        conditions={},
        actions=[{"type": "create_ticket", "provider": provider}],
    )["actions"] == [{"type": "create_ticket", "provider": provider}]


def test_retest_schedule_action_is_limited_to_ticket_close_events() -> None:
    """The change that would break this is allowing a generic finding update to create an active retest."""
    from app.services.automation import validate_rule_definition

    with pytest.raises(ValueError, match="ticket.closed"):
        validate_rule_definition(
            trigger="finding.updated",
            conditions={},
            actions=[{"type": "schedule_retest", "authorization_reference": "CHG-2481"}],
        )


def test_automation_conditions_only_match_the_intended_finding_context() -> None:
    from app.services.automation import conditions_match

    conditions = {
        "severity_at_least": "high",
        "asset_environment": "production",
        "in_kev": True,
        "asset_group": "payments",
    }
    assert conditions_match(
        conditions,
        severity="critical",
        asset_environment="production",
        in_kev=True,
        asset_groups={"payments", "internet-facing"},
    )
    assert not conditions_match(
        conditions,
        severity="high",
        asset_environment="staging",
        in_kev=True,
        asset_groups={"payments"},
    )


def test_automation_rule_schema_rejects_unsafe_action_fields() -> None:
    from app.schemas.automation import AutomationRuleIn

    rule = AutomationRuleIn.model_validate(
        {
            "name": "Critical production tickets",
            "trigger": "finding.created",
            "conditions": {"severity_at_least": "critical"},
            "actions": [{"type": "create_ticket", "provider": "jira"}],
        }
    )
    assert rule.name == "Critical production tickets"

    with pytest.raises(ValueError, match="five-field cron"):
        AutomationRuleIn.model_validate({**rule.model_dump(), "cron_expression": "not-a-cron"})
    with pytest.raises(ValueError):
        AutomationRuleIn.model_validate(
            {
                "name": "Unsafe",
                "trigger": "finding.created",
                "conditions": {},
                "actions": [{"type": "shell.execute"}],
            }
        )


@pytest.mark.asyncio
async def test_create_rule_persists_validated_tenant_owned_definition() -> None:
    from app.db.enums import Role
    from app.schemas.automation import AutomationRuleIn
    from app.services.automation import create_rule
    from app.services.context import Principal

    recorded: list[object] = []

    class Session:
        def add(self, value: object) -> None:
            recorded.append(value)

        async def flush(self) -> None:
            return None

    principal = Principal(
        user_id=uuid4(), organization_id=uuid4(), role=Role.OWNER, email="owner@example.test"
    )
    rule = await create_rule(
        Session(),
        principal,
        AutomationRuleIn(
            name="High findings to Jira",
            trigger="finding.created",
            conditions={"severity_at_least": "high"},
            actions=[{"type": "create_ticket", "provider": "jira"}],
        ),
    )
    assert rule.organization_id == principal.organization_id
    assert rule.created_by_id == principal.user_id
    assert rule.actions == [{"type": "create_ticket", "provider": "jira"}]
    assert any(value is rule for value in recorded)


@pytest.mark.asyncio
async def test_update_rule_is_tenant_scoped_and_revalidates_definition(monkeypatch) -> None:
    import datetime as dt

    from app.db.enums import Role
    from app.schemas.automation import AutomationRuleIn
    from app.services import automation
    from app.services.context import Principal

    principal = Principal(user_id=uuid4(), organization_id=uuid4(), role=Role.OWNER)
    rule = SimpleNamespace(
        id=uuid4(),
        organization_id=principal.organization_id,
        name="Old rule",
        trigger="finding.created",
        conditions={},
        actions=[{"type": "create_ticket", "provider": "jira"}],
        is_enabled=True,
        dry_run=False,
        cron_expression=None,
        timezone="UTC",
        next_run_at=None,
    )

    class Session:
        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: rule)

        def add(self, row):
            return None

        async def flush(self):
            return None

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(automation.audit_service, "record", fake_audit)
    monkeypatch.setattr(automation, "utcnow", lambda: dt.datetime(2026, 10, 9, tzinfo=dt.UTC))
    updated = await automation.update_rule(
        Session(),
        principal,
        rule.id,
        AutomationRuleIn(
            name="Critical ticket rule",
            trigger="finding.created",
            conditions={"severity_at_least": "critical"},
            actions=[{"type": "create_ticket", "provider": "jira"}],
            is_enabled=False,
            dry_run=True,
            cron_expression="0 12 * * *",
        ),
    )
    assert updated is rule
    assert rule.name == "Critical ticket rule"
    assert rule.conditions == {"severity_at_least": "critical"}
    assert rule.is_enabled is False
    assert rule.dry_run is True
    assert rule.next_run_at == dt.datetime(2026, 10, 9, 12, 0, tzinfo=dt.UTC)


@pytest.mark.asyncio
async def test_queue_finding_event_creates_durable_matching_execution() -> None:
    from app.services.automation import queue_finding_event

    organization_id, finding_id, rule_id = uuid4(), uuid4(), uuid4()
    rule = SimpleNamespace(
        id=rule_id,
        organization_id=organization_id,
        trigger="finding.created",
        conditions={"severity_at_least": "high", "asset_environment": "production"},
        is_enabled=True,
        dry_run=False,
    )
    finding = SimpleNamespace(id=finding_id, organization_id=organization_id, severity="critical")
    asset = SimpleNamespace(
        organization_id=organization_id, environment="production", groups=["payments"]
    )
    statements: list[object] = []

    class Result:
        def scalars(self):
            return SimpleNamespace(all=lambda: [rule])

    class Session:
        async def execute(self, statement):
            statements.append(statement)
            return Result() if len(statements) == 1 else SimpleNamespace(rowcount=1)

    queued = await queue_finding_event(
        Session(), finding=finding, asset=asset, trigger="finding.created"
    )
    assert queued == 1
    assert len(statements) == 2
    compiled = statements[1].compile()
    assert compiled.params["organization_id"] == organization_id
    assert compiled.params["rule_id"] == rule_id
    assert compiled.params["canonical_finding_id"] == finding_id
    assert compiled.params["event_key"] == f"finding.created:{finding_id}"


@pytest.mark.asyncio
async def test_queue_finding_event_uses_unique_execution_key_for_retries() -> None:
    from app.services.automation import queue_finding_event

    organization_id, finding_id = uuid4(), uuid4()
    rule = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        trigger="finding.created",
        conditions={},
        is_enabled=True,
        dry_run=False,
    )
    finding = SimpleNamespace(id=finding_id, organization_id=organization_id, severity="high")
    asset = SimpleNamespace(organization_id=organization_id, environment="production", groups=[])
    statements: list[object] = []

    class Result:
        def scalars(self):
            return SimpleNamespace(all=lambda: [rule])

    class Session:
        async def execute(self, statement):
            statements.append(statement)
            if len(statements) == 1:
                return Result()
            return SimpleNamespace(rowcount=0)

    assert (
        await queue_finding_event(
            Session(), finding=finding, asset=asset, trigger="finding.created"
        )
        == 0
    )
    assert len(statements) == 2


@pytest.mark.asyncio
async def test_pending_ticket_automation_executes_against_its_tenant_finding(monkeypatch) -> None:
    from app.services import automation

    organization_id, finding_id, rule_id = uuid4(), uuid4(), uuid4()
    execution = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        rule_id=rule_id,
        canonical_finding_id=finding_id,
        status="pending",
        dry_run=False,
        result={},
    )
    rule = SimpleNamespace(
        id=rule_id,
        organization_id=organization_id,
        is_enabled=True,
        dry_run=False,
        actions=[{"type": "create_ticket", "provider": "jira"}],
    )
    finding = SimpleNamespace(id=finding_id, organization_id=organization_id)

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def scalars(self):
            return SimpleNamespace(
                all=lambda: self.rows,
                one_or_none=lambda: self.rows[0] if self.rows else None,
            )

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            return Result([[execution], [rule], [finding]][self.calls - 1])

    created: list[tuple[uuid4, uuid4]] = []

    async def fake_ticket(session, principal, actual_id, **kwargs):
        created.append((principal.organization_id, actual_id))
        return SimpleNamespace(external_key="SEC-101")

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(automation, "_create_canonical_ticket", fake_ticket)
    monkeypatch.setattr(automation.audit_service, "record", fake_audit)
    count = await automation.execute_pending_automations(Session(), settings=object(), redis=None)
    assert count == 1
    assert created == [(organization_id, finding_id)]
    assert execution.status == "executed"
    assert execution.result == {
        "actions": [{"type": "create_ticket", "provider": "jira", "ticket_key": "SEC-101"}]
    }


@pytest.mark.asyncio
async def test_pending_retest_automation_creates_system_attributed_request(monkeypatch) -> None:
    from app.services import automation

    organization_id, finding_id, rule_id = uuid4(), uuid4(), uuid4()
    execution = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        rule_id=rule_id,
        canonical_finding_id=finding_id,
        status="pending",
        dry_run=False,
        result={},
    )
    rule = SimpleNamespace(
        id=rule_id,
        organization_id=organization_id,
        is_enabled=True,
        dry_run=False,
        actions=[{"type": "request_retest"}],
    )
    finding = SimpleNamespace(id=finding_id, organization_id=organization_id)

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def scalars(self):
            return SimpleNamespace(
                all=lambda: self.rows,
                one_or_none=lambda: self.rows[0] if self.rows else None,
            )

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            return Result([[execution], [rule], [finding]][self.calls - 1])

        def add(self, row):
            return None

        async def flush(self):
            return None

    called: list[tuple[uuid4, uuid4, object]] = []

    async def fake_retest(session, principal, actual_id, *, note):
        called.append((principal.organization_id, actual_id, principal.user_id))
        return SimpleNamespace(id=uuid4())

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(
        automation.remediation_governance, "request_retest", fake_retest, raising=False
    )
    monkeypatch.setattr(automation.audit_service, "record", fake_audit)
    assert (
        await automation.execute_pending_automations(Session(), settings=object(), redis=None) == 1
    )
    assert called == [(organization_id, finding_id, None)]
    assert execution.status == "executed"
    assert execution.result["actions"][0]["type"] == "request_retest"


@pytest.mark.asyncio
async def test_ticket_close_retest_schedule_creates_authorized_assessment_and_links_request(
    monkeypatch,
) -> None:
    """The change that would break this is bypassing the assessment authorization workflow."""
    from app.services import automation

    organization_id, finding_id, asset_id = uuid4(), uuid4(), uuid4()
    finding = SimpleNamespace(
        id=finding_id, asset_id=asset_id, title="SQL injection", organization_id=organization_id
    )
    asset = SimpleNamespace(
        id=asset_id,
        organization_id=organization_id,
        asset_type="url",
        name="https://app.example.test",
    )

    class Session:
        async def execute(self, statement):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(one_or_none=lambda: asset))

    created: list[object] = []
    linked: list[tuple[uuid4, uuid4]] = []

    async def fake_create(session, principal, payload, settings):
        created.extend([principal, payload])
        return SimpleNamespace(id=uuid4())

    def fake_stage(session, principal, assessment):
        return uuid4(), uuid4()

    async def fake_request(session, principal, actual_finding_id, *, note):
        assert actual_finding_id == finding_id
        return SimpleNamespace(id=uuid4())

    async def fake_schedule(session, *, organization_id, request_id, assessment_id):
        linked.append((request_id, assessment_id))

    monkeypatch.setattr(automation, "_create_scheduled_assessment", fake_create)
    monkeypatch.setattr(automation, "stage_assessment_run", fake_stage, raising=False)
    monkeypatch.setattr(automation.remediation_governance, "request_retest", fake_request)
    monkeypatch.setattr(automation.remediation_governance, "schedule_retest", fake_schedule)

    outcome = await automation._schedule_ticket_close_retest(
        Session(),
        principal=automation.Principal.for_system(organization_id=organization_id),
        finding=finding,
        authorization_reference="CHG-2481",
        settings=object(),
    )

    assert created[1].targets == ["https://app.example.test"]
    assert created[1].authorization.evidence_reference == "CHG-2481"
    assert linked == [(UUID(outcome["request_id"]), UUID(outcome["assessment_id"]))]


@pytest.mark.asyncio
async def test_pending_notify_automation_queues_finding_notification(monkeypatch) -> None:
    """A notify rule must perform a durable notification action, not silently fail."""
    from app.services import automation

    organization_id, finding_id, rule_id = uuid4(), uuid4(), uuid4()
    execution = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        rule_id=rule_id,
        canonical_finding_id=finding_id,
        status="pending",
        dry_run=False,
        result={},
    )
    rule = SimpleNamespace(
        id=rule_id,
        organization_id=organization_id,
        is_enabled=True,
        dry_run=False,
        actions=[{"type": "notify"}],
    )
    finding = SimpleNamespace(
        id=finding_id,
        organization_id=organization_id,
        severity="critical",
        title="SQL injection",
    )

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def scalars(self):
            return SimpleNamespace(
                all=lambda: self.rows,
                one_or_none=lambda: self.rows[0] if self.rows else None,
            )

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            return Result([[execution], [rule], [finding]][self.calls - 1])

    notifications = []

    async def fake_dispatch(session, principal, **kwargs):
        notifications.append(
            (principal.organization_id, kwargs["resource_id"], kwargs["severity"].value)
        )
        return []

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(automation, "dispatch", fake_dispatch, raising=False)
    monkeypatch.setattr(automation.audit_service, "record", fake_audit)
    assert (
        await automation.execute_pending_automations(Session(), settings=object(), redis=None) == 1
    )
    assert notifications == [(organization_id, str(finding_id), "critical")]
    assert execution.status == "executed"
    assert execution.result == {"actions": [{"type": "notify"}]}


@pytest.mark.asyncio
async def test_pending_assignment_automation_uses_canonical_work_validation(monkeypatch) -> None:
    """Ownership rules must go through the versioned tenant-scoped work service."""
    from app.services import automation

    organization_id, finding_id, rule_id, assignee_id = uuid4(), uuid4(), uuid4(), uuid4()
    execution = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        rule_id=rule_id,
        canonical_finding_id=finding_id,
        status="pending",
        dry_run=False,
        result={},
    )
    rule = SimpleNamespace(
        id=rule_id,
        organization_id=organization_id,
        is_enabled=True,
        dry_run=False,
        actions=[{"type": "assign_owner", "assignee_user_id": str(assignee_id)}],
    )
    finding = SimpleNamespace(id=finding_id, organization_id=organization_id, status_version=4)

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def scalars(self):
            return SimpleNamespace(
                all=lambda: self.rows, one_or_none=lambda: self.rows[0] if self.rows else None
            )

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            return Result([[execution], [rule], [finding]][self.calls - 1])

    updates = []

    async def fake_update(session, principal, actual_finding_id, payload):
        updates.append(
            (
                principal.organization_id,
                actual_finding_id,
                payload.expected_version,
                payload.assignee_user_id,
            )
        )
        return finding

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(
        automation.canonical_work_service, "update_work", fake_update, raising=False
    )
    monkeypatch.setattr(automation.audit_service, "record", fake_audit)

    assert (
        await automation.execute_pending_automations(Session(), settings=object(), redis=None) == 1
    )
    assert updates == [(organization_id, finding_id, 4, assignee_id)]
    assert execution.result == {
        "actions": [{"type": "assign_owner", "assignee_user_id": str(assignee_id)}]
    }


@pytest.mark.asyncio
async def test_ticket_refresh_queues_closed_event_for_its_canonical_finding(monkeypatch) -> None:
    from app.db.enums import Role
    from app.services import ticket
    from app.services.context import Principal

    organization_id, ticket_id, finding_id, asset_id = uuid4(), uuid4(), uuid4(), uuid4()
    link = SimpleNamespace(
        id=ticket_id,
        provider="jira",
        external_key="SEC-1",
        external_status="In Progress",
        canonical_finding_id=finding_id,
        url=None,
    )
    finding = SimpleNamespace(id=finding_id, organization_id=organization_id, asset_id=asset_id)
    asset = SimpleNamespace(id=asset_id, organization_id=organization_id)

    class Result:
        def __init__(self, item):
            self.item = item

        def scalar_one_or_none(self):
            return self.item

    class Session:
        def __init__(self):
            self.items = iter((link, finding, asset))

        async def execute(self, statement):
            return Result(next(self.items))

    class Jira:
        def __init__(self, *args):
            pass

        async def get_issue(self, key):
            return SimpleNamespace(status="Done", url="https://jira.test/SEC-1")

        async def aclose(self):
            pass

    queued = []

    async def scoped(*args, **kwargs):
        return object()

    async def queue(session, *, finding, asset, trigger):
        queued.append((finding.id, asset.id, trigger))
        return 1

    monkeypatch.setattr(ticket, "resolve_settings", scoped)
    monkeypatch.setattr(ticket, "JiraClient", Jira)
    monkeypatch.setattr(ticket, "queue_finding_event", queue)

    principal = Principal(user_id=uuid4(), organization_id=organization_id, role=Role.OWNER)
    await ticket.refresh_ticket_status(Session(), principal, ticket_id, settings=object())
    assert queued == [(finding_id, asset_id, "ticket.closed")]
    assert link.external_status == "Done"


def test_automation_api_exposes_rule_management_routes() -> None:
    from app.api.v1.automation import router

    routes = {route.path for route in router.routes}
    assert "/automation-rules" in routes
    assert "/automation-rules/executions" in routes


def test_ticket_terminal_status_recognizes_closed_workflows() -> None:
    """Only a real terminal tracker status may initiate retest automation."""
    from app.services.ticket import is_terminal_ticket_status

    assert is_terminal_ticket_status("Done") is True
    assert is_terminal_ticket_status("Resolved") is True
    assert is_terminal_ticket_status("In Progress") is False
    assert is_terminal_ticket_status("") is False


def test_ticket_terminal_transition_only_fires_once() -> None:
    from app.services.ticket import became_terminal_ticket_status

    assert became_terminal_ticket_status("In Progress", "Done") is True
    assert became_terminal_ticket_status("Done", "Done") is False
    assert became_terminal_ticket_status(None, "Resolved") is True
    assert became_terminal_ticket_status("Open", "In Progress") is False


def test_automation_rule_model_persists_schedule_cursor() -> None:
    from app.db.models.canonical import AutomationRule

    assert {"cron_expression", "timezone", "next_run_at"} <= set(AutomationRule.__table__.c.keys())


@pytest.mark.asyncio
async def test_create_scheduled_rule_sets_first_due_time(monkeypatch) -> None:
    import datetime as dt

    from app.db.enums import Role
    from app.schemas.automation import AutomationRuleIn
    from app.services import automation
    from app.services.context import Principal

    class Session:
        def add(self, row):
            self.row = row

        async def flush(self):
            return None

    async def audit(*args, **kwargs):
        return None

    now = dt.datetime(2026, 10, 9, tzinfo=dt.UTC)
    monkeypatch.setattr(automation, "utcnow", lambda: now, raising=False)
    monkeypatch.setattr(automation.audit_service, "record", audit)
    rule = await automation.create_rule(
        Session(),
        Principal(user_id=uuid4(), organization_id=uuid4(), role=Role.OWNER),
        AutomationRuleIn(
            name="Daily notice",
            trigger="finding.created",
            actions=[{"type": "notify"}],
            cron_expression="0 9 * * *",
        ),
    )
    assert rule.next_run_at == dt.datetime(2026, 10, 9, 9, 0, tzinfo=dt.UTC)


@pytest.mark.asyncio
async def test_due_schedule_queues_once_and_advances_cursor(monkeypatch) -> None:
    import datetime as dt

    from app.services import automation

    due = dt.datetime(2026, 10, 9, 9, tzinfo=dt.UTC)
    rule = SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        cron_expression="0 9 * * *",
        timezone="UTC",
        next_run_at=due,
        is_enabled=True,
        dry_run=False,
    )

    class Result:
        def scalars(self):
            return SimpleNamespace(all=lambda: [rule])

    class Session:
        def __init__(self):
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            return Result() if self.calls == 1 else SimpleNamespace(rowcount=1)

    next_due = due + dt.timedelta(days=1)
    monkeypatch.setattr(automation, "next_cron_time", lambda *args: next_due)
    assert await automation.queue_due_automation_schedules(Session(), now=due) == 1
    assert rule.next_run_at == next_due
