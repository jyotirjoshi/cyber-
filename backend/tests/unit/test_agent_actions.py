"""Behavioral tests for single-use, exact-payload agent approvals."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.core.errors import ConflictError, IntegrationNotConfiguredError, PermissionDeniedError
from app.db.enums import Role
from app.services.context import Principal


def test_dependency_is_bound_to_exact_approved_action_digest() -> None:
    from app.services.agent_action import action_payload_digest, new_agent_action

    prerequisite_a, prerequisite_b = uuid.uuid4(), uuid.uuid4()
    payload = {"canonical_finding_id": str(uuid.uuid4())}
    action = new_agent_action(
        organization_id=uuid.uuid4(), session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(), action="create_jira_ticket",
        label="File ticket", rationale=None, payload=payload,
        depends_on_action_id=prerequisite_a,
    )
    assert action.payload_digest == action_payload_digest(
        "create_jira_ticket", payload, depends_on_action_id=prerequisite_a,
    )
    assert action.payload_digest != action_payload_digest(
        "create_jira_ticket", payload, depends_on_action_id=prerequisite_b,
    )


@pytest.mark.asyncio
async def test_action_dependency_is_tenant_and_conversation_scoped() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.agent_action import action_dependency_state, new_agent_action

    action = new_agent_action(
        organization_id=uuid.uuid4(), session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(), action="create_jira_ticket",
        label="File ticket", rationale=None, payload={"canonical_finding_id": str(uuid.uuid4())},
        depends_on_action_id=uuid.uuid4(),
    )

    class Session:
        def __init__(self, dependency):
            self.dependency = dependency
            self.statement = None

        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalar_one_or_none=lambda: self.dependency)

    for dependency_status, expected in (("pending", "waiting"), ("approved", "waiting"),
                                        ("executed", "ready"), ("failed", "failed"),
                                        ("rejected", "failed"), (None, "failed")):
        dependency = (
            SimpleNamespace(
                action="update_canonical_work", status=dependency_status,
                payload={"finding_id": action.payload["canonical_finding_id"]},
            ) if dependency_status else None
        )
        session = Session(dependency)
        assert await action_dependency_state(session, action) == expected
        compiled = session.statement.compile(dialect=postgresql.dialect())
        assert action.organization_id in compiled.params.values()
        assert action.session_id in compiled.params.values()
        assert action.depends_on_action_id in compiled.params.values()

    for bad_dependency in (
        SimpleNamespace(
            action="update_canonical_work", status="executed",
            payload={"finding_id": str(uuid.uuid4())},
        ),
        SimpleNamespace(
            action="sync_github_alerts", status="executed",
            payload={"finding_id": action.payload["canonical_finding_id"]},
        ),
    ):
        assert await action_dependency_state(Session(bad_dependency), action) == "failed"


@pytest.mark.asyncio
async def test_waiting_ticket_is_not_executed_or_failed(monkeypatch) -> None:
    from app.services import agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    action = agent_action.new_agent_action(
        organization_id=principal.organization_id, session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id, action="create_jira_ticket",
        label="File ticket", rationale=None, payload={"canonical_finding_id": str(uuid.uuid4())},
        depends_on_action_id=uuid.uuid4(),
    )
    action.status = "approved"
    called = False

    async def dependency_state(session, row):
        return "waiting"

    async def execute(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent_action, "action_dependency_state", dependency_state)
    monkeypatch.setattr(agent_action, "execute_approved_action", execute)
    with pytest.raises(ConflictError):
        await agent_action.execute_and_settle_action(
            object(), principal, action, settings=object(), redis=None,
        )
    assert action.status == "approved"
    assert not called


@pytest.mark.asyncio
async def test_rejected_triage_prevents_ticket_provider_call(monkeypatch) -> None:
    from app.services import agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    action = agent_action.new_agent_action(
        organization_id=principal.organization_id, session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id, action="create_jira_ticket",
        label="File ticket", rationale=None, payload={"canonical_finding_id": str(uuid.uuid4())},
        depends_on_action_id=uuid.uuid4(),
    )
    action.status = "approved"
    calls = []

    class Session:
        @asynccontextmanager
        async def begin_nested(self):
            yield

    async def dependency_state(session, row):
        return "failed"

    async def execute(*args, **kwargs):
        calls.append("provider")

    async def fail(session, row, reason):
        row.status = "failed"
        row.result_summary = reason

    async def receipt(session, row):
        calls.append("receipt")

    monkeypatch.setattr(agent_action, "action_dependency_state", dependency_state)
    monkeypatch.setattr(agent_action, "execute_approved_action", execute)
    monkeypatch.setattr(agent_action, "_fail_approved_action", fail)
    monkeypatch.setattr(agent_action, "append_action_receipt", receipt)
    await agent_action.execute_and_settle_action(
        Session(), principal, action, settings=object(), redis=None,
    )
    assert action.status == "failed"
    assert calls == ["receipt"]


def test_action_receipt_reports_verified_outcome_without_claiming_scan_finished() -> None:
    from app.services.agent_action import format_action_receipt

    queued = SimpleNamespace(
        action="start_assessment", label="Assess example.org", status="executed",
        result_summary="Assessment queued", run_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
    )
    content = format_action_receipt(queued)
    assert "queued" in content.lower()
    assert "11111111-1111-1111-1111-111111111111" in content
    assert "scan completed" not in content.lower()

    failed = SimpleNamespace(
        action="sync_github_alerts", label="Sync GitHub", status="failed",
        result_summary="GitHub unavailable", run_id=None,
    )
    assert "failed" in format_action_receipt(failed).lower()
    assert "GitHub unavailable" in format_action_receipt(failed)
    with pytest.raises(ValueError):
        format_action_receipt(SimpleNamespace(status="pending"))


@pytest.mark.asyncio
async def test_terminal_action_receipt_is_tenant_scoped_and_idempotent() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.agent_action import append_action_receipt, new_agent_action

    tenant = uuid.uuid4()
    action = new_agent_action(
        organization_id=tenant, session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(), action="sync_github_alerts",
        label="Sync GitHub", rationale=None, payload={},
    )
    action.status = "executed"
    action.result_summary = "3 alerts synced"

    class Session:
        def __init__(self):
            self.statements = []
            self.added = []

        async def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) in {1, 5}:
                return SimpleNamespace(scalar_one_or_none=lambda: action.session_id)
            if len(self.statements) == 2:
                return SimpleNamespace(scalar_one_or_none=lambda: None)
            if len(self.statements) == 3:
                return SimpleNamespace(scalar_one=lambda: 7)
            if len(self.statements) == 4:
                return SimpleNamespace()
            return SimpleNamespace(scalar_one_or_none=lambda: self.added[0])

        def add(self, row):
            self.added.append(row)

        async def flush(self):
            return None

    session = Session()
    created = await append_action_receipt(session, action)
    again = await append_action_receipt(session, action)
    assert created is again
    assert len(session.added) == 1
    assert created.organization_id == tenant
    assert created.session_id == action.session_id
    assert created.source_action_id == action.id
    assert created.seq == 7
    assert created.content == "Action completed: Sync GitHub. 3 alerts synced"
    lookup = session.statements[1].compile(dialect=postgresql.dialect())
    assert tenant in lookup.params.values()
    assert action.id in lookup.params.values()
    count_update = session.statements[3].compile(dialect=postgresql.dialect())
    assert "agent_sessions" in str(count_update)
    assert tenant in count_update.params.values()
    assert action.session_id in count_update.params.values()


@pytest.mark.asyncio
async def test_action_receipt_refuses_a_session_outside_the_action_tenant() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.agent_action import append_action_receipt, new_agent_action

    action = new_agent_action(
        organization_id=uuid.uuid4(), session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(), action="sync_github_alerts",
        label="Sync GitHub", rationale=None, payload={},
    )
    action.status = "executed"
    action.result_summary = "3 alerts synced"

    class Session:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            return SimpleNamespace(scalar_one_or_none=lambda: None, scalar_one=lambda: 0)

        def add(self, row):
            raise AssertionError("No cross-tenant receipt may be inserted")

    session = Session()
    with pytest.raises(PermissionDeniedError):
        await append_action_receipt(session, action)
    scope_lookup = session.statements[0].compile(dialect=postgresql.dialect())
    assert "agent_sessions" in str(scope_lookup)
    assert action.organization_id in scope_lookup.params.values()
    assert action.session_id in scope_lookup.params.values()


@pytest.mark.asyncio
async def test_settled_action_appends_verified_receipt_to_conversation(monkeypatch) -> None:
    from app.services import agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    action = agent_action.new_agent_action(
        organization_id=principal.organization_id, session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id, action="sync_github_alerts",
        label="Sync GitHub", rationale=None, payload={},
    )
    action.status = "approved"

    class Session:
        def __init__(self):
            self.calls = 0
            self.messages = []

        @asynccontextmanager
        async def begin_nested(self):
            yield

        async def execute(self, statement):
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(scalar_one_or_none=lambda: action.session_id)
            if self.calls == 2:
                return SimpleNamespace(scalar_one_or_none=lambda: None)
            if self.calls == 3:
                return SimpleNamespace(scalar_one=lambda: 4)
            return SimpleNamespace()

        def add(self, row):
            self.messages.append(row)

        async def flush(self):
            return None

    async def provider_action(session, actor, row, *, settings, redis):
        row.status = "executed"
        row.result_summary = "3 alerts synced"
        return row

    monkeypatch.setattr(agent_action, "execute_approved_action", provider_action)
    session = Session()
    settled = await agent_action.execute_and_settle_action(
        session, principal, action, settings=object(), redis=None,
    )
    assert settled is action
    assert len(session.messages) == 1
    assert session.messages[0].source_action_id == action.id
    assert session.messages[0].content == "Action completed: Sync GitHub. 3 alerts synced"


@pytest.mark.asyncio
async def test_completed_assessment_updates_its_action_receipt_with_verified_counts() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.agent_action import complete_assessment_action_receipt, new_agent_action

    tenant, run_id = uuid.uuid4(), uuid.uuid4()
    action = new_agent_action(
        organization_id=tenant, session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(), action="start_assessment",
        label="Assess example.org", rationale=None,
        payload={"target": "https://example.org", "authorization_reference": "AUTH-1"},
    )
    action.status = "executed"
    action.run_id = run_id
    receipt = SimpleNamespace(content="Assessment queued: Assess example.org")
    assessment = SimpleNamespace(
        organization_id=tenant, id=uuid.uuid4(), findings_total=5,
        findings_critical=1, findings_high=2, assets_discovered=3,
        degradations=[{"scanner": "zap"}],
    )

    class Session:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) == 1:
                return SimpleNamespace(scalar_one_or_none=lambda: action)
            if len(self.statements) == 2:
                return SimpleNamespace(scalar_one_or_none=lambda: action.session_id)
            return SimpleNamespace(scalar_one_or_none=lambda: receipt)

    session = Session()
    changed = await complete_assessment_action_receipt(session, assessment, run_id)
    assert changed is True
    assert receipt.content == (
        f"Assessment completed: {assessment.id}. 5 findings (1 critical, 2 high) "
        "across 3 discovered assets. Some scanner coverage was degraded; review the report."
    )
    lookup = session.statements[0].compile(dialect=postgresql.dialect())
    assert tenant in lookup.params.values()
    assert run_id in lookup.params.values()


@pytest.mark.asyncio
async def test_assessment_receipt_update_ignores_other_tenants_run() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.agent_action import complete_assessment_action_receipt

    tenant, run_id = uuid.uuid4(), uuid.uuid4()
    assessment = SimpleNamespace(
        organization_id=tenant, id=uuid.uuid4(), findings_total=0,
        findings_critical=0, findings_high=0, assets_discovered=0, degradations=[],
    )

    class Session:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            return SimpleNamespace(scalar_one_or_none=lambda: None)

    session = Session()
    assert await complete_assessment_action_receipt(session, assessment, run_id) is False
    assert len(session.statements) == 1
    lookup = session.statements[0].compile(dialect=postgresql.dialect())
    assert tenant in lookup.params.values()
    assert run_id in lookup.params.values()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("failed", "Assessment failed. No completed scan result is available; review run details."),
        ("cancelled", "Assessment cancelled. No completed scan result is available."),
    ],
)
async def test_terminal_worker_outcome_replaces_stale_queued_receipt(outcome, expected) -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.agent_action import new_agent_action, settle_assessment_action_receipt

    tenant, run_id = uuid.uuid4(), uuid.uuid4()
    action = new_agent_action(
        organization_id=tenant, session_id=uuid.uuid4(),
        requested_by_user_id=uuid.uuid4(), action="start_assessment",
        label="Assess example.org", rationale=None,
        payload={"target": "https://example.org", "authorization_reference": "AUTH-1"},
    )
    action.status = "executed"
    action.run_id = run_id
    receipt = SimpleNamespace(content="Assessment queued: Assess example.org")

    class Session:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) == 1:
                return SimpleNamespace(scalar_one_or_none=lambda: action)
            if len(self.statements) == 2:
                return SimpleNamespace(scalar_one_or_none=lambda: action.session_id)
            return SimpleNamespace(scalar_one_or_none=lambda: receipt)

    session = Session()
    assert await settle_assessment_action_receipt(
        session, organization_id=tenant, run_id=run_id, outcome=outcome,
    ) is True
    assert receipt.content == expected
    lookup = session.statements[0].compile(dialect=postgresql.dialect())
    assert tenant in lookup.params.values()
    assert run_id in lookup.params.values()


@pytest.mark.asyncio
async def test_terminal_worker_receipt_refuses_unrecognized_outcome() -> None:
    from app.services.agent_action import settle_assessment_action_receipt

    class NoQuery:
        async def execute(self, statement):
            raise AssertionError("Unverified outcomes must not query or change receipts")

    with pytest.raises(ValueError):
        await settle_assessment_action_receipt(
            NoQuery(), organization_id=uuid.uuid4(), run_id=uuid.uuid4(),
            outcome="running",
        )


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


def test_assessment_action_requires_exact_authorized_target() -> None:
    from app.services.agent_action import validate_action_payload

    payload = validate_action_payload(
        "start_assessment",
        {"target": "https://example.org", "authorization_reference": "ENG-42"},
    )
    assert payload == {"target": "https://example.org", "authorization_reference": "ENG-42"}
    with pytest.raises(ValueError):
        validate_action_payload("start_assessment", {"target": "https://example.org"})
    with pytest.raises(ValueError):
        validate_action_payload(
            "start_assessment",
            {
                "target": "https://example.org",
                "authorization_reference": "ENG-42",
                "api_key": "secret",
            },
        )
    with pytest.raises(ValueError):
        validate_action_payload(
            "start_assessment",
            {"target": "https://example.org/?token=hidden", "authorization_reference": "ENG-42"},
        )
    with pytest.raises(ValueError):
        validate_action_payload(
            "start_assessment",
            {
                "target": "https://example.org\nother.example.org",
                "authorization_reference": "ENG-42",
            },
        )


@pytest.mark.parametrize(
    "target",
    [
        "https://example.org",
        "aws:123456789012",
        "gcp:example-project-1",
    ],
)
@pytest.mark.asyncio
async def test_approved_assessment_action_stages_a_durable_worker_run(monkeypatch, target) -> None:
    from app.db.base import utcnow
    from app.services import agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="start_assessment",
        label="Scan example.org",
        rationale=None,
        payload={"target": target, "authorization_reference": "ENG-42"},
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()
    assessment_id = uuid.uuid4()
    run_id = uuid.uuid4()
    calls = []

    async def fake_create(session, actor, payload, settings):
        calls.append(
            (
                "create",
                actor.organization_id,
                payload.targets,
                payload.authorization.confirmed,
                payload.authorization.evidence_reference,
            )
        )
        return SimpleNamespace(id=assessment_id)

    def fake_stage(session, actor, assessment):
        calls.append(("stage", actor.organization_id, assessment.id))
        return run_id, uuid.uuid4()

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_action.assessment_service, "create_assessment", fake_create)
    monkeypatch.setattr(agent_action, "stage_assessment_run", fake_stage)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    await agent_action.execute_approved_action(
        object(),
        principal,
        row,
        settings=object(),
        redis=None,
    )
    assert calls == [
        ("create", principal.organization_id, [target], True, "ENG-42"),
        ("stage", principal.organization_id, assessment_id),
    ]
    assert row.status == "executed"
    assert row.run_id == run_id
    assert str(assessment_id) in row.result_summary


@pytest.mark.asyncio
async def test_approved_tenable_action_syncs_vulnerabilities_and_records_result(
    monkeypatch,
) -> None:
    from app.db.base import utcnow
    from app.services import agent_action

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="sync_tenable_vulnerabilities",
        label="Sync Tenable",
        rationale=None,
        payload={},
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

    monkeypatch.setattr(
        agent_action.external_alert_service, "sync_tenable_vulnerabilities", fake_sync
    )
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    settings = object()
    await agent_action.execute_approved_action(
        object(),
        principal,
        row,
        settings=settings,
        redis=None,
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
async def test_worker_settles_permission_revocation_and_continues_next_action(monkeypatch) -> None:
    from app.services import agent_action

    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    denied = agent_action.new_agent_action(
        organization_id=org_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=user_id,
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
    )
    permitted = agent_action.new_agent_action(
        organization_id=org_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=user_id,
        action="update_canonical_work",
        label="Assign",
        rationale=None,
        payload={
            "finding_id": str(uuid.uuid4()),
            "expected_version": 1,
            "assignee_user_id": str(user_id),
        },
    )
    for row in (denied, permitted):
        row.status = "approved"
        row.approved_by_user_id = user_id
    reads = 0
    executed = []

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
            return _Result([denied, permitted] if reads == 1 else ("developer",))

        @asynccontextmanager
        async def begin_nested(self):
            yield

    async def fake_execute(session, principal, action, *, settings, redis):
        executed.append(action.id)
        action.status = "executed"

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(agent_action, "execute_approved_action", fake_execute)
    monkeypatch.setattr(agent_action.audit_service, "record", fake_audit)
    assert await agent_action.execute_approved_batch(_Session(), settings=object(), redis=None) == 2
    assert denied.status == "failed"
    assert "permission" in denied.result_summary.lower()
    assert permitted.status == "executed"
    assert executed == [permitted.id]


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
async def test_worker_isolates_unexpected_action_failure_without_leaking_details(
    monkeypatch,
) -> None:
    from app.services import agent_action

    user_id = uuid.uuid4()
    row = agent_action.new_agent_action(
        organization_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        requested_by_user_id=user_id,
        action="sync_github_alerts",
        label="Sync",
        rationale=None,
        payload={},
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
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="create_jira_ticket",
        label="Jira",
        rationale=None,
        payload={"canonical_finding_id": str(finding_id)},
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
        object(),
        principal,
        row,
        settings=object(),
        redis=None,
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
            summary="Finding",
            description="Detail",
            finding_id=str(uuid.uuid4()),
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
