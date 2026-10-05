"""Behavioral tests for single-use, exact-payload agent approvals."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.core.errors import ConflictError, IntegrationNotConfiguredError, PermissionDeniedError
from app.db.enums import Role
from app.services.context import Principal


def test_action_digest_is_stable_across_payload_key_order() -> None:
    from app.services.agent_action import action_payload_digest

    assert action_payload_digest(
        "sync_github_alerts", {"provider": "github", "scope": {"repo": "api"}}
    ) == action_payload_digest(
        "sync_github_alerts", {"scope": {"repo": "api"}, "provider": "github"}
    )


def test_action_digest_binds_the_action_name() -> None:
    from app.services.agent_action import action_payload_digest

    assert action_payload_digest("sync_github_alerts", {}) != action_payload_digest(
        "sync_gitlab_alerts", {}
    )


@pytest.mark.asyncio
async def test_approved_tenable_action_syncs_vulnerabilities_and_records_result(monkeypatch) -> None:
    from app.db.base import utcnow
    from app.services import agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id, session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id, action="sync_tenable_vulnerabilities",
        label="Sync Tenable", rationale=None, payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()
    calls = []

    async def fake_sync(session, actor, *, settings, redis):
        calls.append((actor.organization_id, settings, redis))
        return SimpleNamespace(total=7)

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_action.external_alert_service, "sync_tenable_vulnerabilities", fake_sync)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    settings = object()
    await agent_action.execute_approved_action(
        object(), principal, row, settings=settings, redis=None,
    )
    assert calls == [(principal.organization_id, settings, None)]
    assert row.status == "executed"
    assert row.result_summary == "7 vulnerabilities synced"


@pytest.mark.asyncio
async def test_worker_drains_approved_action_with_current_member_authority(monkeypatch) -> None:
    from app.services import agent_action

    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=org_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=user_id,
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = user_id
    seen = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalars(self):
            return self

        def all(self):
            return self.value

        def one_or_none(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            seen.append(statement)
            if len(seen) == 1:
                return _Result([row])
            return _Result(("owner",))

        @asynccontextmanager
        async def begin_nested(self):
            yield

    async def fake_execute(session, principal, action, *, settings, redis):
        assert principal.organization_id == org_id
        assert principal.user_id == user_id
        assert principal.role == Role.OWNER
        assert principal.actor_type == "agent"
        assert action is row
        row.status = "executed"
        return row

    monkeypatch.setattr(agent_action, "execute_approved_action", fake_execute)
    assert await agent_action.execute_approved_batch(_Session(), settings=object(), redis=None) == 1
    assert row.status == "executed"
    assert seen[0]._for_update_arg.skip_locked is True
    assert "agent_actions.status" in str(seen[0])


@pytest.mark.asyncio
async def test_worker_refuses_approved_action_after_membership_revocation(monkeypatch) -> None:
    from app.services import agent_action

    row = agent_action.new_agent_action(
        organization_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(),
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = row.requested_by_user_id
    reads = 0
    audits = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalars(self):
            return self

        def all(self):
            return self.value

        def one_or_none(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            nonlocal reads
            reads += 1
            return _Result([row] if reads == 1 else None)

    async def forbidden_execute(*args, **kwargs):
        raise AssertionError("revoked user must not execute an action")

    async def fake_audit(*args, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(agent_action, "execute_approved_action", forbidden_execute)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    assert await agent_action.execute_approved_batch(_Session(), settings=object(), redis=None) == 1
    assert row.status == "failed"
    assert "active" in row.result_summary.lower()
    assert audits[0]["action"] == agent_action.audit_service.AuditAction.AGENT_ACTION_FAILED


@pytest.mark.asyncio
async def test_worker_marks_provider_error_failed_without_repeating_approval(monkeypatch) -> None:
    from app.services import agent_action

    row = agent_action.new_agent_action(
        organization_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(),
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = row.requested_by_user_id
    reads = 0
    audits = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalars(self):
            return self

        def all(self):
            return self.value

        def one_or_none(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            nonlocal reads
            reads += 1
            return _Result([row] if reads == 1 else ("owner",))

        @asynccontextmanager
        async def begin_nested(self):
            yield

    async def broken_provider(*args, **kwargs):
        raise IntegrationNotConfiguredError("GitHub")

    async def fake_audit(*args, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(agent_action, "execute_approved_action", broken_provider)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    assert await agent_action.execute_approved_batch(_Session(), settings=object(), redis=None) == 1
    assert row.status == "failed"
    assert "GitHub" in row.result_summary
    assert audits[0]["action"] == agent_action.audit_service.AuditAction.AGENT_ACTION_FAILED


@pytest.mark.asyncio
async def test_worker_isolates_unexpected_action_failure_without_leaking_details(monkeypatch) -> None:
    from app.services import agent_action

    user_id = uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=uuid.uuid4(), session_id=uuid.uuid4(),
        requested_by_user_id=user_id, action="sync_github_alerts",
        label="Sync", rationale=None, payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = user_id
    reads = 0
    audits = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalars(self):
            return self

        def all(self):
            return self.value

        def one_or_none(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            nonlocal reads
            reads += 1
            return _Result([row] if reads == 1 else ("owner",))

        @asynccontextmanager
        async def begin_nested(self):
            yield

    async def broken_provider(*args, **kwargs):
        raise RuntimeError("secret-response-token")

    async def fake_audit(*args, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(agent_action, "execute_approved_action", broken_provider)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    assert await agent_action.execute_approved_batch(_Session(), settings=object(), redis=None) == 1
    assert row.status == "failed"
    assert "secret-response-token" not in row.result_summary
    assert audits[0]["action"] == agent_action.audit_service.AuditAction.AGENT_ACTION_FAILED


def test_action_payload_rejects_unknown_or_secret_bearing_fields() -> None:
    from app.services.agent_action import validate_action_payload

    with pytest.raises(ValueError, match="Unsupported"):
        validate_action_payload("delete_everything", {})
    with pytest.raises(ValueError, match="credentials"):
        validate_action_payload("sync_github_alerts", {"api_token": "not-allowed"})


def test_jira_payload_accepts_project_key_but_requires_finding_id() -> None:
    from app.services.agent_action import validate_action_payload

    finding_id = uuid.uuid4()
    assert validate_action_payload(
        "create_jira_ticket", {"finding_id": str(finding_id), "project_key": "SEC"}
    ) == {"finding_id": str(finding_id), "project_key": "SEC"}
    with pytest.raises(ValueError, match="finding_id"):
        validate_action_payload("create_jira_ticket", {"project_key": "SEC"})
    with pytest.raises(ValueError, match="finding_id"):
        validate_action_payload("create_jira_ticket", {"finding_id": "not-a-uuid"})


def test_jira_payload_accepts_canonical_target_but_not_both_targets() -> None:
    from app.services.agent_action import validate_action_payload

    canonical_id = str(uuid.uuid4())
    assert validate_action_payload(
        "create_jira_ticket", {"canonical_finding_id": canonical_id, "project_key": "SEC"}
    ) == {"canonical_finding_id": canonical_id, "project_key": "SEC"}
    with pytest.raises(ValueError):
        validate_action_payload(
            "create_jira_ticket",
            {"finding_id": str(uuid.uuid4()), "canonical_finding_id": canonical_id},
        )


def test_jira_payload_rejects_nested_or_oversized_values() -> None:
    from app.services.agent_action import validate_action_payload

    finding_id = str(uuid.uuid4())
    with pytest.raises(ValueError, match="project_key"):
        validate_action_payload(
            "create_jira_ticket", {"finding_id": finding_id, "project_key": {"token": "x"}}
        )
    with pytest.raises(ValueError, match="assignee"):
        validate_action_payload(
            "create_jira_ticket", {"finding_id": finding_id, "assignee": "a" * 201}
        )
    with pytest.raises(ValueError, match="project_key"):
        validate_action_payload(
            "create_jira_ticket",
            {"finding_id": finding_id, "project_key": 'SEC" OR project != "SEC'},
        )


def test_canonical_work_action_requires_versioned_bounded_change() -> None:
    from app.services.agent_action import validate_action_payload

    finding_id = str(uuid.uuid4())
    assert validate_action_payload(
        "update_canonical_work",
        {
            "finding_id": finding_id,
            "expected_version": 3,
            "remediation_plan": "Upgrade the affected package and verify with a rescan.",
        },
    ) == {
        "finding_id": finding_id,
        "expected_version": 3,
        "remediation_plan": "Upgrade the affected package and verify with a rescan.",
    }
    for payload in (
        {"finding_id": finding_id, "expected_version": 3},
        {"finding_id": finding_id, "expected_version": -1, "remediation_plan": "Patch"},
        {"finding_id": "bad", "expected_version": 3, "remediation_plan": "Patch"},
        {"finding_id": finding_id, "expected_version": 3, "remediation_plan": " "},
        {
            "finding_id": finding_id,
            "expected_version": 3,
            "remediation_plan": "Patch",
            "raw_evidence": {"token": "secret"},
        },
    ):
        with pytest.raises(ValueError):
            validate_action_payload("update_canonical_work", payload)


def test_canonical_work_action_requires_remediation_permission() -> None:
    from app.services.agent_action import require_action_permission

    viewer = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        require_action_permission(viewer, "update_canonical_work")
    developer = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    require_action_permission(developer, "update_canonical_work")


@pytest.mark.asyncio
async def test_approved_canonical_work_executes_versioned_update_once(monkeypatch) -> None:
    from app.db.base import utcnow
    from app.services import agent_action, canonical_work

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="update_canonical_work",
        label="Triage finding",
        rationale="Grounded draft",
        payload={
            "finding_id": str(finding_id),
            "expected_version": 4,
            "remediation_plan": "Upgrade and verify.",
        },
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()
    seen = []

    async def fake_update(session, actor, actual_id, body):
        seen.append(
            (actor.organization_id, actual_id, body.expected_version, body.remediation_plan)
        )
        return SimpleNamespace(status_version=5)

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(canonical_work, "update_work", fake_update)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    await agent_action.execute_approved_action(
        object(),
        principal,
        row,
        settings=object(),
        redis=None,
    )
    assert seen == [(principal.organization_id, finding_id, 4, "Upgrade and verify.")]
    assert row.status == "executed"
    assert row.result_summary == "Remediation work updated to version 5"
    with pytest.raises(ConflictError):
        await agent_action.execute_approved_action(
            object(),
            principal,
            row,
            settings=object(),
            redis=None,
        )


@pytest.mark.asyncio
async def test_approved_canonical_jira_action_calls_canonical_ticket_service(monkeypatch) -> None:
    from app.db.base import utcnow
    from app.services import agent_action, ticket

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_id = uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id, session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id, action="create_jira_ticket",
        label="Jira", rationale=None, payload={"canonical_finding_id": str(finding_id)},
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()
    called = []

    async def fake_ticket(session, actor, actual_id, **kwargs):
        called.append((actor.organization_id, actual_id, kwargs["by_agent"]))
        return SimpleNamespace(external_key="SEC-42")

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(ticket, "create_canonical_ticket", fake_ticket)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    await agent_action.execute_approved_action(
        object(), principal, row, settings=object(), redis=None,
    )
    assert called == [(principal.organization_id, finding_id, True)]
    assert row.status == "executed"
    assert row.result_summary == "Jira ticket SEC-42 linked"


def test_propose_action_requires_its_actual_permission() -> None:
    from app.services.agent_action import require_action_permission

    developer = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    with pytest.raises(PermissionDeniedError):
        require_action_permission(developer, "sync_github_alerts")


def test_github_alert_action_requires_exact_identity_decision_and_rationale() -> None:
    from app.services.agent_action import validate_action_payload

    alert_id = str(uuid.uuid4())
    assert validate_action_payload(
        "update_github_alert",
        {
            "alert_id": alert_id,
            "decision": "dismiss",
            "reason": "tolerable_risk",
            "comment": "Accepted until the pinned dependency is upgraded.",
        },
    ) == {
        "alert_id": alert_id,
        "decision": "dismiss",
        "reason": "tolerable_risk",
        "comment": "Accepted until the pinned dependency is upgraded.",
    }
    for payload in (
        {"alert_id": "not-a-uuid", "decision": "reopen"},
        {"alert_id": alert_id, "decision": "dismiss", "reason": "tolerable_risk"},
        {"alert_id": alert_id, "decision": "reopen", "comment": "surprise"},
        {"alert_id": alert_id, "decision": "reopen", "api_token": "secret"},
    ):
        with pytest.raises(ValueError):
            validate_action_payload("update_github_alert", payload)


def test_github_alert_action_requires_integration_and_validation_permissions() -> None:
    from app.services.agent_action import require_action_permission

    engineer = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.SECURITY_ENGINEER
    )
    with pytest.raises(PermissionDeniedError):
        require_action_permission(engineer, "update_github_alert")
    admin = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.ADMIN)
    require_action_permission(admin, "update_github_alert")


def test_new_action_binds_the_validated_payload_digest() -> None:
    from app.services.agent_action import new_agent_action

    org_id = uuid.uuid4()
    action = new_agent_action(
        organization_id=org_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(),
        action="sync_gitlab_alerts",
        label="Sync GitLab alerts",
        rationale="Refresh the external alert inbox.",
        payload={},
    )

    assert action.organization_id == org_id
    assert action.status == "pending"
    assert len(action.payload_digest) == 64


@pytest.mark.asyncio
async def test_execute_action_refuses_unapproved_or_changed_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.agent_action import execute_approved_action, new_agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
    )
    with pytest.raises(ConflictError):
        await execute_approved_action(object(), principal, row, settings=object(), redis=None)
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    from app.db.base import utcnow

    row.resolved_at = utcnow()
    row.action = "sync_gitlab_alerts"
    with pytest.raises(ConflictError):
        await execute_approved_action(object(), principal, row, settings=object(), redis=None)


@pytest.mark.asyncio
async def test_execute_approved_sync_records_result(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import agent_action, external_alert

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    from app.db.base import utcnow

    row.resolved_at = utcnow()
    calls = 0

    async def fake_sync(session, actor, *, settings, redis):
        nonlocal calls
        calls += 1
        assert actor.organization_id == row.organization_id
        return SimpleNamespace(total=3)

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(external_alert, "sync_github_alerts", fake_sync)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    await agent_action.execute_approved_action(
        object(), principal, row, settings=object(), redis=None
    )
    assert row.status == "executed"
    assert row.result_summary == "3 alerts synced"
    assert calls == 1
    with pytest.raises(ConflictError):
        await agent_action.execute_approved_action(
            object(), principal, row, settings=object(), redis=None
        )
    assert calls == 1


@pytest.mark.asyncio
async def test_execute_approved_github_alert_change_uses_exact_approved_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db.base import utcnow
    from app.services import agent_action, external_alert

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.ADMIN)
    alert_id = uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="update_github_alert",
        label="Dismiss GitHub alert",
        rationale="Analyst reviewed risk",
        payload={
            "alert_id": str(alert_id),
            "decision": "dismiss",
            "reason": "tolerable_risk",
            "comment": "Reviewed and accepted for 30 days.",
        },
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()

    async def fake_update(session, actor, actual_alert_id, **kwargs):
        assert actor.organization_id == principal.organization_id
        assert actual_alert_id == alert_id
        assert kwargs["decision"] == "dismiss"
        assert kwargs["reason"] == "tolerable_risk"
        assert kwargs["comment"] == "Reviewed and accepted for 30 days."
        return SimpleNamespace(status="dismissed")

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(external_alert, "set_github_alert_state", fake_update)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    await agent_action.execute_approved_action(
        object(), principal, row, settings=object(), redis=None
    )
    assert row.status == "executed"
    assert row.result_summary == "GitHub alert dismissed"
    with pytest.raises(ConflictError):
        await agent_action.execute_approved_action(
            object(), principal, row, settings=object(), redis=None
        )


@pytest.mark.asyncio
async def test_execute_jira_uses_the_approved_finding_and_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db.base import utcnow
    from app.services import agent_action, ticket

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_id = uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="create_jira_ticket",
        label="Create Jira ticket",
        rationale=None,
        payload={"finding_id": str(finding_id), "project_key": "SEC"},
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()

    async def fake_create(session, actor, actual_finding_id, **kwargs):
        assert actual_finding_id == finding_id
        assert kwargs["project_key"] == "SEC"
        assert kwargs["by_agent"] is True
        return SimpleNamespace(external_key="SEC-42")

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(ticket, "create_ticket", fake_create)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    await agent_action.execute_approved_action(
        object(), principal, row, settings=object(), redis=None
    )
    assert row.status == "executed"
    assert row.result_summary == "Jira ticket SEC-42 linked"


@pytest.mark.asyncio
async def test_jira_client_uses_requested_project_for_duplicate_check_and_creation() -> None:
    from app.integrations.jira import JiraClient

    class FakeHttp:
        def __init__(self) -> None:
            self.fields = None

        async def post_json(self, path, *, json, idempotency_key=None):
            self.fields = json["fields"]
            return {"key": "ALT-1", "id": "1"}

    client = object.__new__(JiraClient)
    client._cfg = SimpleNamespace(
        project_key="DEFAULT", issue_type="Task", base_url="https://jira.example"
    )
    http = FakeHttp()
    client._require = lambda: http
    searched = []

    async def fake_search(jql, *, max_results):
        searched.append(jql)
        return []

    client.search = fake_search
    await client.create_issue(
        summary="Finding", description="Detail", finding_id=str(uuid.uuid4()), project_key="ALT"
    )
    assert 'project = "ALT"' in searched[0]
    assert http.fields["project"] == {"key": "ALT"}


@pytest.mark.asyncio
async def test_jira_client_never_creates_issue_when_duplicate_lookup_fails() -> None:
    from app.core.errors import IntegrationError
    from app.integrations.jira import JiraClient

    class FakeHttp:
        async def post_json(self, path, *, json, idempotency_key=None):
            raise AssertionError("issue creation must not follow an uncertain duplicate check")

    client = object.__new__(JiraClient)
    client._cfg = SimpleNamespace(
        project_key="SEC", issue_type="Task", base_url="https://jira.example"
    )
    client._require = lambda: FakeHttp()

    async def failed_search(jql, *, max_results):
        raise IntegrationError("Jira search unavailable", provider="Jira")

    client.search = failed_search
    with pytest.raises(IntegrationError, match="Jira search unavailable"):
        await client.create_issue(
            summary="Finding", description="Detail", finding_id=str(uuid.uuid4())
        )


@pytest.mark.asyncio
async def test_jira_timeout_does_not_retry_create_with_or_without_optional_fields() -> None:
    from app.core.errors import IntegrationTimeoutError
    from app.db.enums import Priority
    from app.integrations.jira import JiraClient

    attempts = []

    class FakeHttp:
        async def post_json(self, path, *, json, idempotency_key=None):
            attempts.append((path, idempotency_key))
            raise IntegrationTimeoutError("Jira timed out", provider="Jira")

    client = object.__new__(JiraClient)
    client._cfg = SimpleNamespace(
        project_key="SEC", issue_type="Task", base_url="https://jira.example"
    )
    client._require = lambda: FakeHttp()

    async def no_existing(jql, *, max_results):
        return []

    client.search = no_existing
    with pytest.raises(IntegrationTimeoutError):
        await client.create_issue(
            summary="Finding", description="Detail", finding_id=str(uuid.uuid4()),
            priority=Priority.P1,
        )
    assert attempts == [("/rest/api/3/issue", None)]


@pytest.mark.asyncio
async def test_jira_client_rejects_unsafe_project_key_before_network() -> None:
    from app.core.errors import InvalidConfigurationError
    from app.integrations.jira import JiraClient

    client = object.__new__(JiraClient)
    client._cfg = SimpleNamespace(
        project_key="DEFAULT", issue_type="Task", base_url="https://jira.example"
    )
    client._require = lambda: (_ for _ in ()).throw(AssertionError("network touched"))
    with pytest.raises(InvalidConfigurationError):
        await client.find_for_finding(str(uuid.uuid4()), project_key='SEC" OR project != "SEC')
