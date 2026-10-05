"""Explicit chat instructions become real, approval-bound action records."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.core.crypto import Secret
from app.db.enums import IntegrationKind, Role
from app.services.context import Principal


def test_sync_request_plans_only_sources_explicitly_named_by_user() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    plans = plan_chat_actions("Please sync GitHub and Wazuh alerts now")
    assert [(item.action, item.payload) for item in plans] == [
        ("sync_github_alerts", {}),
        ("sync_wazuh_alerts", {}),
    ]
    assert plan_chat_actions("What integrations are connected?") == []
    assert plan_chat_actions("Do not sync GitHub yet") == []
    assert plan_chat_actions("I want you to not sync GitHub") == []
    assert plan_chat_actions("I can't sync GitHub, why?") == []
    assert plan_chat_actions("Why did the GitHub sync fail yesterday?") == []
    assert plan_chat_actions("I tried to sync GitHub but it failed") == []


def test_tenable_sync_request_becomes_a_bounded_approved_action() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    plans = plan_chat_actions("Please sync Tenable vulnerabilities now")
    assert [(item.action, item.payload) for item in plans] == [
        ("sync_tenable_vulnerabilities", {}),
    ]
    assert plan_chat_actions("Why did the Tenable sync fail?") == []


def test_explicit_all_connected_sync_is_distinct_from_an_unbounded_request() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    plans = plan_chat_actions("Please sync all connected security sources")
    assert [(item.action, item.payload) for item in plans] == [
        ("sync_connected_sources", {}),
    ]
    assert plan_chat_actions("Sync all") == []
    assert plan_chat_actions("Sync all connected sources except GitHub") == []


def test_jira_request_requires_one_explicit_finding_id() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    finding_id = uuid.uuid4()
    plans = plan_chat_actions(f"Create a Jira ticket for finding {finding_id} in project SEC")
    assert [(item.action, item.payload) for item in plans] == [
        ("create_jira_ticket", {"finding_id": str(finding_id), "project_key": "SEC"}),
    ]
    assert plan_chat_actions("Create Jira tickets for all findings") == []
    assert plan_chat_actions(f"I tried to create a Jira ticket for {finding_id}") == []
    assert plan_chat_actions(f"Create Jira tickets for {finding_id} and {uuid.uuid4()}") == []


def test_jira_request_can_select_one_highest_risk_finding() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    plans = plan_chat_actions("Create a Jira ticket for the highest-risk finding in project SEC")
    assert [(plan.action, plan.payload) for plan in plans] == [
        ("create_jira_ticket", {"selector": "highest_risk", "project_key": "SEC"}),
    ]
    assert plan_chat_actions("Create Jira tickets for all findings") == []
    assert plan_chat_actions("Do not create a Jira ticket for the highest-risk finding") == []


@pytest.mark.asyncio
async def test_highest_risk_jira_request_resolves_tenant_finding_before_approval(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_id = uuid.uuid4()

    class _TopJiraSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return _Result([finding_id, None, None, finding_id, None][len(self.statements) - 1])

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _TopJiraSession()
    outcomes = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Create a Jira ticket for the highest-risk finding in project SEC",
    )
    assert outcomes[0]["status"] == "pending_approval"
    assert session.added[0].label == "Create Jira ticket for highest-risk finding"
    assert session.added[0].payload == {
        "canonical_finding_id": str(finding_id), "project_key": "SEC",
    }
    selection = session.statements[0].compile(dialect=postgresql.dialect())
    assert principal.organization_id in selection.params.values()
    assert "risk_score DESC" in str(selection)
    assert "LIMIT" in str(selection)


@pytest.mark.asyncio
async def test_highest_risk_jira_request_without_open_finding_does_not_queue() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session = _Session()
    outcomes = await propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Create a Jira ticket for the highest-risk finding",
    )
    assert outcomes == [{"action": "create_jira_ticket", "status": "finding_not_found"}]
    assert not session.added


def test_triage_request_requires_one_explicit_finding_id() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    finding_id = uuid.uuid4()
    plans = plan_chat_actions(f"Triage finding {finding_id} and assign it to me")
    assert [(item.action, item.payload) for item in plans] == [
        ("update_canonical_work", {"finding_id": str(finding_id)}),
    ]
    assert plan_chat_actions("Triage all findings") == []
    assert plan_chat_actions(f"Why was finding {finding_id} triaged?") == []
    assert plan_chat_actions(f"Do not triage finding {finding_id} yet") == []


def test_triage_highest_risk_request_uses_a_bounded_selector() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    plans = plan_chat_actions("Triage my highest-risk finding and assign it to me")
    assert [(item.action, item.payload) for item in plans] == [
        ("update_canonical_work", {"selector": "highest_risk", "mine": True}),
    ]
    assert plan_chat_actions("Triage all findings") == []
    assert plan_chat_actions("Do not triage my highest-risk finding") == []


def test_triage_top_three_findings_creates_three_bounded_work_items() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    plans = plan_chat_actions("Triage my top 3 risk findings and assign them to me")
    assert [(item.action, item.payload) for item in plans] == [
        ("update_canonical_work", {"selector": "highest_risk", "mine": True, "rank": 0}),
        ("update_canonical_work", {"selector": "highest_risk", "mine": True, "rank": 1}),
        ("update_canonical_work", {"selector": "highest_risk", "mine": True, "rank": 2}),
    ]
    assert plan_chat_actions("Triage top 100 findings") == []


def test_explicit_self_assignment_is_a_bounded_work_action() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    finding_id = uuid.uuid4()
    assert [(plan.action, plan.payload) for plan in plan_chat_actions(
        f"Assign finding {finding_id} to me"
    )] == [
        ("update_canonical_work", {"finding_id": str(finding_id), "assign_self": True})
    ]
    assert [(plan.action, plan.payload) for plan in plan_chat_actions(
        "Assign the highest-risk finding to me"
    )] == [
        ("update_canonical_work", {"selector": "highest_risk", "mine": False,
                                    "assign_self": True})
    ]
    assert plan_chat_actions("Assign all findings to me") == []
    assert plan_chat_actions(f"Do not assign finding {finding_id} to me") == []
    assert plan_chat_actions(f"Assign finding {finding_id} not to me") == []
    assert plan_chat_actions(f"Assign findings {finding_id} and {uuid.uuid4()} to me") == []


def test_reopen_github_alert_requires_explicit_single_alert() -> None:
    from app.services.agent_chat_actions import plan_chat_actions

    alert_id = uuid.uuid4()
    plans = plan_chat_actions(f"Reopen GitHub alert {alert_id}")
    assert [(plan.action, plan.payload) for plan in plans] == [
        ("update_github_alert", {"alert_id": str(alert_id), "decision": "reopen"}),
    ]
    assert plan_chat_actions("Reopen every GitHub alert") == []
    assert plan_chat_actions(f"Do not reopen GitHub alert {alert_id}") == []
    assert plan_chat_actions(f"Why was GitHub alert {alert_id} reopened?") == []
    assert plan_chat_actions(f"Reopen GitHub alerts {alert_id} and {uuid.uuid4()}") == []


@pytest.mark.asyncio
async def test_reopen_github_alert_queues_tenant_scoped_approval_without_provider(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    alert_id = uuid.uuid4()
    row = SimpleNamespace(id=alert_id, provider="github", status="dismissed")

    class _AlertSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return _Result([row, None][len(self.statements) - 1])

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _AlertSession()
    outcomes = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question=f"Reopen GitHub alert {alert_id}",
    )
    assert outcomes[0]["status"] == "pending_approval"
    assert session.added[0].payload == {"alert_id": str(alert_id), "decision": "reopen"}
    params = session.statements[0].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in params
    assert alert_id in params


@pytest.mark.asyncio
async def test_reopen_github_alert_rejects_other_provider_or_open_state() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    alert_id = uuid.uuid4()
    for provider, status, expected in (
        ("gitlab", "dismissed", "alert_not_found"),
        ("github", "open", "alert_not_reopenable"),
    ):
        session = _Session(finding=SimpleNamespace(
            id=alert_id, provider=provider, status=status,
        ))
        outcomes = await propose_chat_actions(
            session, principal, session_id=uuid.uuid4(),
            question=f"Reopen GitHub alert {alert_id}",
        )
        assert outcomes == [{"action": "update_github_alert", "status": expected}]
        assert not session.added


@pytest.mark.asyncio
async def test_self_assignment_queues_versioned_approval_without_model(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(id=finding_id, status="open", status_version=7)

    class _AssignmentSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return _Result([finding, None][len(self.statements) - 1])

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _AssignmentSession()
    result = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question=f"Assign finding {finding_id} to me",
    )
    assert result[0]["status"] == "pending_approval"
    assert session.added[0].payload == {
        "finding_id": str(finding_id), "expected_version": 7,
        "assignee_user_id": str(principal.user_id),
    }
    params = session.statements[0].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in params
    assert finding_id in params


@pytest.mark.asyncio
async def test_self_assignment_rejects_inactive_finding() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    session = _Session(finding=SimpleNamespace(
        id=finding_id, status="accepted_risk", status_version=7,
    ))
    result = await propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question=f"Assign finding {finding_id} to me",
    )
    assert result == [{"action": "update_canonical_work", "status": "finding_inactive"}]
    assert not session.added


@pytest.mark.asyncio
async def test_self_assignment_selects_highest_risk_open_tenant_finding(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(id=finding_id, status="open", status_version=3)

    class _TopAssignmentSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return _Result([finding_id, finding, None][len(self.statements) - 1])

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _TopAssignmentSession()
    result = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Assign the highest-risk finding to me",
    )
    assert result[0]["status"] == "pending_approval"
    assert session.added[0].payload == {
        "finding_id": str(finding_id), "expected_version": 3,
        "assignee_user_id": str(principal.user_id),
    }
    selection = session.statements[0].compile(dialect=postgresql.dialect())
    assert principal.organization_id in selection.params.values()
    assert "risk_score DESC" in str(selection)
    assert "LIMIT" in str(selection)


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def one_or_none(self):
        return self.value


class _Session:
    def __init__(self, existing=None, finding=None):
        self.existing = existing
        self.finding = finding
        self.statements = []
        self.added = []

    async def execute(self, statement):
        self.statements.append(statement)
        if self.finding is not None and len(self.statements) == 1:
            return _Result(self.finding)
        return _Result(self.existing)

    def add(self, item):
        self.added.append(item)

    async def flush(self):
        return None


@pytest.mark.asyncio
async def test_top_three_triage_resolves_distinct_tenant_findings(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_ids = [uuid.uuid4() for _ in range(3)]

    class _RankedSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            index = len(self.statements) - 1
            return _Result(finding_ids[index // 2] if index % 2 == 0 else None)

    async def draft(session, actor, finding_id, gateway):
        return {"finding_id": str(finding_id), "expected_version": 1,
                "remediation_plan": "Review and patch the affected dependency, then retest."}, "drafted"

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions, "_draft_triage", draft)
    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", audit)
    session = _RankedSession()
    outcomes = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Triage top 3 risk findings",
    )
    assert [item["status"] for item in outcomes] == ["pending_approval"] * 3
    assert [item.payload["finding_id"] for item in session.added] == [
        str(item) for item in finding_ids
    ]
    for rank, statement in enumerate(session.statements[::2]):
        compiled = statement.compile(dialect=postgresql.dialect())
        assert principal.organization_id in compiled.params.values()
        assert rank in compiled.params.values()


@pytest.mark.asyncio
async def test_chat_does_not_request_approval_for_unconfigured_github_sync() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)

    class _NoIntegrationSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: []),
                scalar_one_or_none=lambda: None,
            )

    session = _NoIntegrationSession()
    result = await propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Sync GitHub alerts",
        settings=Settings(github={"api_token": None, "organization": None}),
    )
    assert result == [{"action": "sync_github_alerts", "status": "integration_not_ready"}]
    assert not session.added
    assert principal.organization_id in session.statements[0].compile().params.values()


@pytest.mark.asyncio
async def test_chat_queues_configured_github_sync_without_touching_provider(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)

    class _NoIntegrationSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: []),
                scalar_one_or_none=lambda: None,
            )

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _NoIntegrationSession()
    result = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Sync GitHub alerts",
        settings=Settings(github={"api_token": "test-token", "organization": "acme"}),
    )
    assert result[0]["status"] == "pending_approval"
    assert session.added[0].action == "sync_github_alerts"


@pytest.mark.asyncio
async def test_all_connected_sync_excludes_enabled_source_with_missing_key() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    connection = SimpleNamespace(
        kind="github", kind_enum=IntegrationKind.GITHUB, is_usable=True,
        credentials=[], config={"organization": "acme"}, base_url=None, name="GitHub",
    )

    class _ConnectionsSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [connection]))

    session = _ConnectionsSession()
    outcome = await propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Sync all connected security sources",
        settings=Settings(github={"api_token": None, "organization": None}),
    )
    assert outcome == [{"action": "sync_connected_sources", "status": "no_connected_sources"}]
    assert not session.added
    assert principal.organization_id in session.statements[0].compile().params.values()


@pytest.mark.asyncio
async def test_chat_accepts_wazuh_indexer_only_configuration(monkeypatch) -> None:
    from app.services import agent_chat_actions
    from app.services import integration as integration_service

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    connection = SimpleNamespace(
        kind="wazuh", kind_enum=IntegrationKind.WAZUH, is_usable=True,
        credentials=[], config={"indexer_base_url": "https://wazuh-indexer.example:9200"},
        base_url=None, name="Wazuh Indexer",
    )

    class _ConnectionsSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: [connection]),
                scalar_one_or_none=lambda: None,
            )

    def credentials_for(*_args, **_kwargs):
        return {
            "indexer_username": Secret("reader"),
            "indexer_password": Secret("indexer-password"),
        }

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(integration_service, "credentials_for", credentials_for)
    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _ConnectionsSession()
    outcome = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question="Sync Wazuh alerts", settings=Settings(),
    )
    assert outcome[0]["status"] == "pending_approval"
    assert session.added[0].action == "sync_wazuh_alerts"


@pytest.mark.asyncio
async def test_chat_queues_one_approved_capability_without_executing_provider(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session = _Session()

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    result = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(), question="Sync GitHub alerts"
    )
    assert len(session.added) == 1
    assert session.added[0].action == "sync_github_alerts"
    assert session.added[0].status == "pending"
    assert result[0]["status"] == "pending_approval"
    assert len(session.statements) == 1
    params = session.statements[0].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in params


@pytest.mark.asyncio
async def test_all_connected_sync_queues_only_usable_supported_tenant_sources(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    rows = [
        SimpleNamespace(kind="github", is_usable=False),
        SimpleNamespace(kind="github", is_usable=True),
        SimpleNamespace(kind="gitlab", is_usable=False),
        SimpleNamespace(kind="tenable", is_usable=True),
        SimpleNamespace(kind="jira", is_usable=True),
    ]
    statements = []
    added = []

    class _ConnectedSession:
        async def execute(self, statement):
            statements.append(statement)
            if len(statements) == 1:
                return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
            return _Result(None)

        def add(self, action):
            added.append(action)

        async def flush(self):
            return None

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    result = await agent_chat_actions.propose_chat_actions(
        _ConnectedSession(), principal, session_id=uuid.uuid4(),
        question="Please sync all connected security sources",
    )
    assert [action.action for action in added] == [
        "sync_github_alerts", "sync_tenable_vulnerabilities",
    ]
    assert all(action.organization_id == principal.organization_id for action in added)
    assert result[0] == {
        "action": "sync_connected_sources", "status": "selected", "count": "2",
        "sources": "GitHub, Tenable",
    }
    assert [item["status"] for item in result[1:]] == [
        "pending_approval", "pending_approval",
    ]
    compiled = statements[0].compile(dialect=postgresql.dialect())
    assert principal.organization_id in compiled.params.values()


@pytest.mark.asyncio
async def test_chat_does_not_queue_action_without_permission() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _Session()
    result = await propose_chat_actions(
        session, principal, session_id=uuid.uuid4(), question="Sync GitHub alerts"
    )
    assert result[0]["status"] == "permission_denied"
    assert not session.statements
    assert not session.added


@pytest.mark.asyncio
async def test_chat_checks_jira_finding_belongs_to_caller_tenant(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_id = uuid.uuid4()
    session = _Session(finding=SimpleNamespace(id=finding_id))

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    result = await agent_chat_actions.propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question=f"Create a Jira ticket for finding {finding_id}",
    )
    assert result[0]["status"] == "pending_approval"
    assert session.added[0].payload["finding_id"] == str(finding_id)
    values = session.statements[0].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in values
    assert finding_id in values


@pytest.mark.asyncio
async def test_chat_maps_canonical_finding_to_native_jira_target(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    canonical_id = uuid.uuid4()
    native_id = uuid.uuid4()

    class _MappedSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            values = [None, native_id, None]
            return _Result(values[len(self.statements) - 1])

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _MappedSession()
    result = await agent_chat_actions.propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question=f"Create a Jira ticket for finding {canonical_id}",
    )
    assert result[0]["status"] == "pending_approval"
    assert session.added[0].payload["finding_id"] == str(native_id)
    assert str(canonical_id) in session.added[0].rationale
    values = session.statements[1].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in values
    assert canonical_id in values


@pytest.mark.asyncio
async def test_chat_queues_canonical_only_jira_target_for_approval(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    canonical_id = uuid.uuid4()

    class _CanonicalSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            values = [None, None, canonical_id, None]
            return _Result(values[len(self.statements) - 1])

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _CanonicalSession()
    outcomes = await agent_chat_actions.propose_chat_actions(
        session, principal, session_id=uuid.uuid4(),
        question=f"Create Jira ticket for finding {canonical_id}",
    )
    assert outcomes[0]["status"] == "pending_approval"
    assert session.added[0].payload == {"canonical_finding_id": str(canonical_id)}
    assert principal.organization_id in session.statements[2].compile().params.values()



@pytest.mark.asyncio
async def test_chat_does_not_duplicate_an_open_action() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    existing = SimpleNamespace(id=uuid.uuid4(), status="pending", action="sync_github_alerts")
    session = _Session(existing=existing)
    result = await propose_chat_actions(
        session, principal, session_id=uuid.uuid4(), question="Sync GitHub alerts"
    )
    assert result[0]["id"] == str(existing.id)
    assert result[0]["status"] == "already_pending"
    assert not session.added


@pytest.mark.asyncio
async def test_triage_drafts_versioned_work_from_tenant_finding_and_queues_approval(
    monkeypatch,
) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        status="open",
        status_version=6,
        title="Outdated package",
        severity="high",
        cve_ids=["CVE-2026-1234"],
        risk_score=83.0,
        risk_factors={"inputs": {"in_kev": True}, "raw_secret": "must not leak"},
    )

    class _TriageSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) == 1:
                return _Result((finding, "api.example.org"))
            return _Result(None)

    class _Gateway:
        async def complete_json(self, role, messages, *, schema, model_cls, max_attempts):
            context = " ".join(item.content for item in messages)
            assert "Outdated package" in context
            assert "api.example.org" in context
            assert "must not leak" not in context
            return model_cls.model_validate(
                {
                    "remediation_plan": "Upgrade the affected package, then rescan the asset and "
                    "confirm the CVE is absent from a complete scan.",
                }
            )

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _TriageSession()
    outcomes = await agent_chat_actions.propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question=f"Triage finding {finding_id} and assign it to me",
        gateway=_Gateway(),
    )
    assert outcomes[0]["status"] == "pending_approval"
    assert session.added[0].payload == {
        "finding_id": str(finding_id),
        "expected_version": 6,
        "remediation_plan": "Upgrade the affected package, then rescan the asset and "
        "confirm the CVE is absent from a complete scan.",
        "assignee_user_id": str(principal.user_id),
    }
    values = session.statements[0].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in values
    assert finding_id in values


@pytest.mark.asyncio
async def test_triage_missing_finding_never_calls_model_or_queues_action() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()

    class _NoModel:
        async def complete_json(self, *args, **kwargs):
            raise AssertionError("model called for missing finding")

    session = _Session()
    outcomes = await propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question=f"Triage finding {finding_id}",
        gateway=_NoModel(),
    )
    assert outcomes == [{"action": "update_canonical_work", "status": "finding_not_found"}]
    assert not session.added


@pytest.mark.asyncio
async def test_triage_highest_risk_selects_only_active_tenant_finding(monkeypatch) -> None:
    from app.services import agent_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        status="open",
        status_version=4,
        title="Critical package issue",
        severity="critical",
        cve_ids=[],
        risk_score=96.0,
        risk_factors={},
    )

    class _TopFindingSession(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            results = [finding_id, (finding, "prod.example.org"), None]
            return _Result(results[len(self.statements) - 1])

    class _Gateway:
        async def complete_json(self, role, messages, *, schema, model_cls, max_attempts):
            return model_cls.model_validate(
                {
                    "remediation_plan": "Patch the affected component, then run a complete "
                    "authorized rescan and verify the finding is absent."
                }
            )

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_chat_actions.agent_action_service.audit_service, "record", fake_audit)
    session = _TopFindingSession()
    outcomes = await agent_chat_actions.propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question="Triage my highest-risk finding and assign it to me",
        gateway=_Gateway(),
    )
    assert outcomes[0]["status"] == "pending_approval"
    assert session.added[0].payload["finding_id"] == str(finding_id)
    assert session.added[0].payload["assignee_user_id"] == str(principal.user_id)
    selection = session.statements[0].compile(dialect=postgresql.dialect())
    assert principal.organization_id in selection.params.values()
    assert principal.user_id in selection.params.values()
    assert "risk_score DESC" in str(selection)
    assert "LIMIT" in str(selection)


@pytest.mark.asyncio
async def test_triage_highest_risk_empty_queue_does_not_call_model() -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)

    class _NoModel:
        async def complete_json(self, *args, **kwargs):
            raise AssertionError("model called with no selected finding")

    session = _Session()
    outcomes = await propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question="Triage highest-risk finding",
        gateway=_NoModel(),
    )
    assert outcomes == [{"action": "update_canonical_work", "status": "finding_not_found"}]
    assert not session.added


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plan",
    [
        "                                        ",
        "Upgrade for CVE-2026-9999 and verify the fix in a full rescan.",
    ],
)
async def test_triage_rejects_blank_or_unsupported_model_claims(plan: str) -> None:
    from app.services.agent_chat_actions import propose_chat_actions

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        status="open",
        status_version=1,
        title="Package issue",
        severity="high",
        cve_ids=["CVE-2026-1234"],
        risk_score=50.0,
        risk_factors={},
    )

    class _OneFinding(_Session):
        async def execute(self, statement):
            self.statements.append(statement)
            return _Result((finding, "example.org"))

    class _Gateway:
        async def complete_json(self, role, messages, *, schema, model_cls, max_attempts):
            return model_cls.model_validate({"remediation_plan": plan})

    session = _OneFinding()
    outcomes = await propose_chat_actions(
        session,
        principal,
        session_id=uuid.uuid4(),
        question=f"Triage finding {finding_id}",
        gateway=_Gateway(),
    )
    assert outcomes == [{"action": "update_canonical_work", "status": "analysis_unavailable"}]
    assert not session.added
