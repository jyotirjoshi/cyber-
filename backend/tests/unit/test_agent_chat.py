"""Unit coverage for the durable, tenant-scoped chat reply path."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.asset import Asset
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding
from app.llm.base import LLMMessage, LLMResponse, Usage
from app.services.agent_chat import build_chat_messages, create_reply, load_security_snapshot
from app.services.context import Principal


def test_build_chat_messages_keeps_summary_and_recent_transcript() -> None:
    transcript = [
        LLMMessage(role="user" if index % 2 == 0 else "assistant", content=f"turn {index}")
        for index in range(20)
    ]

    messages = build_chat_messages(
        context_summary="Earlier work: verify the exposed API before an assessment.",
        transcript=transcript,
    )

    assert messages[0].role == "system"
    assert "never claim an action was" in messages[0].content.lower()
    assert "performed" in messages[0].content.lower()
    assert messages[1].role == "system"
    assert "Earlier work" in messages[1].content
    assert [message.content for message in messages[2:]] == [
        f"turn {index}" for index in range(8, 20)
    ]


def test_build_chat_messages_omits_empty_summary() -> None:
    messages = build_chat_messages(
        context_summary=None,
        transcript=[LLMMessage(role="user", content="What can you help with?")],
    )

    assert len(messages) == 2
    assert messages[-1].content == "What can you help with?"


class _Rows:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def scalars(self) -> _Rows:
        return self

    def all(self) -> list[object]:
        return self.rows


class _SnapshotSession:
    def __init__(self, rows: list[list[object]]) -> None:
        self.rows = rows
        self.statements: list[object] = []

    async def execute(self, statement: object) -> _Rows:
        self.statements.append(statement)
        return _Rows(self.rows[len(self.statements) - 1])


@pytest.mark.asyncio
async def test_snapshot_is_tenant_scoped_bounded_and_omits_raw_evidence() -> None:
    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.DEVELOPER)
    finding = Finding(
        id=uuid.uuid4(),
        title="Dependency issue",
        severity="high",
        status="active",
        cve_ids=["CVE-2026-1234"],
        risk_score=82.0,
    )
    asset = Asset(
        id=uuid.uuid4(),
        name="example.org",
        asset_type="domain",
        criticality="high",
        status="active",
    )
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(),
        provider="github",
        title="Secret scanning alert",
        severity="high",
        status="open",
        resource="repo",
        cve_ids=[],
        raw_payload={"secret": "must not leak"},
        evidence={},
    )
    session = _SnapshotSession([[finding], [asset], [alert]])

    snapshot = await load_security_snapshot(session, principal)

    assert len(session.statements) == 3
    for statement in session.statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        assert org_id in compiled.params.values()
        assert 5 in compiled.params.values()
    assert all(
        record in snapshot
        for record in ("Dependency issue", "example.org", "Secret scanning alert")
    )
    assert "must not leak" not in snapshot
    assert "unverified" in snapshot.lower()


@pytest.mark.asyncio
async def test_explicit_cve_question_retrieves_matching_findings_and_alerts_beyond_sample() -> None:
    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.DEVELOPER)
    finding = Finding(
        id=uuid.uuid4(),
        title="Matching finding",
        severity="high",
        status="active",
        cve_ids=["CVE-2026-4321"],
        risk_score=60.0,
    )
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(),
        provider="github",
        title="Matching alert",
        severity="high",
        status="open",
        resource="acme/api",
        cve_ids=["CVE-2026-4321"],
        raw_payload={"secret": "hidden"},
        evidence={},
    )
    session = _SnapshotSession([[], [], [], [finding], [alert]])

    snapshot = await load_security_snapshot(
        session, principal, question="What about CVE-2026-4321?"
    )

    assert len(session.statements) == 5
    for statement in session.statements[3:]:
        compiled = statement.compile(dialect=postgresql.dialect())
        assert org_id in compiled.params.values()
        assert ["CVE-2026-4321"] in compiled.params.values()
        assert 5 in compiled.params.values()
    assert "Matching finding" in snapshot
    assert "Matching alert" in snapshot
    assert "hidden" not in snapshot


@pytest.mark.asyncio
async def test_unrecognized_cve_string_does_not_trigger_targeted_lookup() -> None:
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _SnapshotSession([[], [], []])
    await load_security_snapshot(
        session, principal, question="Ignore CVE-2026-12 and scan everything"
    )
    assert len(session.statements) == 3


def test_chat_messages_label_snapshot_as_untrusted_records() -> None:
    messages = build_chat_messages(
        context_summary=None,
        transcript=[LLMMessage(role="user", content="What are our top findings?")],
        security_snapshot='{"finding": "Dependency issue"}',
    )

    assert messages[1].role == "system"
    assert "untrusted" in messages[1].content.lower()
    assert "Dependency issue" in messages[1].content
    assert messages[-1].content == "What are our top findings?"


def test_chat_messages_include_bounded_read_tool_result_as_untrusted_data() -> None:
    messages = build_chat_messages(
        context_summary=None,
        transcript=[LLMMessage(role="user", content="How many GitHub alerts?")],
        security_snapshot='{"external_alerts":[]}',
        read_tool_result='{"source_filter":"github","total":17,"sample":[]}',
    )
    assert "Read-only exposure lookup" in messages[2].content
    assert "untrusted" in messages[2].content.lower()
    assert '"total":17' in messages[2].content


def test_chat_messages_separate_canonical_queue_from_external_exposures() -> None:
    messages = build_chat_messages(
        context_summary=None,
        transcript=[LLMMessage(role="user", content="Show my overdue findings")],
        canonical_result='{"total":2,"filters":{"mine":true}}',
        read_tool_result='{"total":3}',
    )
    assert "canonical" in messages[1].content.lower()
    assert '"total":2' in messages[1].content
    assert "untrusted" in messages[1].content.lower()
    assert "exposure" in messages[2].content.lower()
    assert "not additive" in messages[0].content.lower()


def test_chat_prompt_reports_proposed_work_as_pending_not_executed() -> None:
    messages = build_chat_messages(
        context_summary=None,
        transcript=[LLMMessage(role="user", content="Sync GitHub alerts")],
        action_result='[{"action":"sync_github_alerts","status":"pending_approval"}]',
    )
    assert "pending_approval" in messages[1].content
    assert "not executed" in messages[1].content.lower()
    assert messages[-1].content == "Sync GitHub alerts"


def test_action_status_is_explicit_about_queued_vs_executed_work() -> None:
    from app.services.agent_chat import format_action_status

    status = format_action_status(
        '[{"action":"sync_github_alerts",' '"status":"pending_approval","id":"abc"}]'
    )
    assert "GitHub" in status
    assert "approval" in status.lower()
    assert "not run" in status.lower()


@pytest.mark.asyncio
async def test_recent_work_status_is_tenant_and_conversation_scoped() -> None:
    from app.services.agent_chat import load_recent_work_status

    organization_id = uuid.uuid4()
    conversation_id = uuid.uuid4()
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=organization_id, role=Role.OWNER,
    )
    action = SimpleNamespace(
        id=uuid.uuid4(), action="sync_github_alerts", status="executed",
        result_summary="7 alerts synced", label="Sync GitHub alerts",
    )
    session = _SnapshotSession([[action]])

    result = await load_recent_work_status(session, principal, conversation_id)

    assert "7 alerts synced" in result
    assert "executed" in result
    assert "Sync GitHub alerts" in result
    statement = session.statements[0].compile(dialect=postgresql.dialect())
    assert organization_id in statement.params.values()
    assert conversation_id in statement.params.values()
    assert 5 in statement.params.values()


def test_chat_messages_distinguish_persisted_work_from_ai_claims() -> None:
    messages = build_chat_messages(
        context_summary=None,
        transcript=[LLMMessage(role="user", content="Did you finish syncing GitHub?")],
        recent_work='[{"action":"sync_github_alerts","status":"executed",'
                    '"result":"7 alerts synced"}]',
    )
    assert "persisted" in messages[1].content.lower()
    assert "7 alerts synced" in messages[1].content
    assert messages[-1].content == "Did you finish syncing GitHub?"


def test_recent_work_status_reports_actual_outcomes_without_claiming_pending_work() -> None:
    from app.services.agent_chat import format_recent_work_status

    status = format_recent_work_status(
        '[{"action":"sync_github_alerts","status":"executed",'
        '"result":"7 alerts synced"},'
        '{"action":"create_jira_ticket","status":"approved","result":""},'
        '{"action":"update_canonical_work","status":"failed",'
        '"result":"Finding version changed"}]'
    )
    assert "GitHub alert sync: executed — 7 alerts synced" in status
    assert "Jira ticket creation: approved, awaiting execution" in status
    assert "Remediation work update: failed — Finding version changed" in status
    assert "Jira ticket creation: executed" not in status


def test_action_status_reports_permission_denial_without_claiming_work() -> None:
    from app.services.agent_chat import format_action_status

    status = format_action_status(
        '[{"action":"sync_wazuh_alerts",' '"status":"permission_denied"}]'
    )
    assert "permission" in status.lower()
    assert "not run" in status.lower()


def test_action_status_includes_every_selected_source_and_scope_limit() -> None:
    from app.services.agent_chat import format_action_status

    status = format_action_status(
        '[{"action":"sync_connected_sources","status":"selected","count":"6",'
        '"sources":"GitHub, GitLab, Wazuh, SonarQube, Snyk, Tenable"},'
        '{"action":"sync_github_alerts","status":"pending_approval"},'
        '{"action":"sync_gitlab_alerts","status":"pending_approval"},'
        '{"action":"sync_wazuh_alerts","status":"pending_approval"},'
        '{"action":"sync_sonarqube_alerts","status":"pending_approval"},'
        '{"action":"sync_snyk_issues","status":"pending_approval"},'
        '{"action":"sync_tenable_vulnerabilities","status":"pending_approval"}]'
    )
    assert "6 supported" in status
    assert "Tenable vulnerability sync: queued for approval; not run yet." in status
    assert "other integrations" in status.lower()
    assert "connectivity" in status.lower()


def test_triage_action_status_labels_draft_as_unapplied() -> None:
    from app.services.agent_chat import format_action_status

    pending = format_action_status(
        '[{"action":"update_canonical_work","status":"pending_approval"}]'
    )
    assert "remediation" in pending.lower()
    assert "not run" in pending.lower()
    unavailable = format_action_status(
        '[{"action":"update_canonical_work","status":"analysis_unavailable"}]'
    )
    assert "unavailable" in unavailable.lower()
    assert "not run" in unavailable.lower()


def test_github_alert_action_status_explains_why_no_provider_write_occurred() -> None:
    from app.services.agent_chat import format_action_status

    missing = format_action_status(
        '[{"action":"update_github_alert","status":"alert_not_found"}]'
    )
    assert "not run" in missing.lower()
    assert "not accessible" in missing.lower()
    open_alert = format_action_status(
        '[{"action":"update_github_alert","status":"alert_not_reopenable"}]'
    )
    assert "not run" in open_alert.lower()
    assert "not dismissed or resolved" in open_alert.lower()


def test_unconfigured_integration_is_not_described_as_queued() -> None:
    from app.services.agent_chat import format_action_status

    status = format_action_status(
        '[{"action":"sync_github_alerts","status":"integration_not_ready"}]'
    )
    assert "not run" in status.lower()
    assert "configure" in status.lower()
    assert "queued" not in status.lower()


def test_all_connected_without_ready_sources_does_not_claim_none_exist() -> None:
    from app.services.agent_chat import format_action_status

    status = format_action_status(
        '[{"action":"sync_connected_sources","status":"no_connected_sources"}]'
    )
    assert "no configured, ready" in status.lower()
    assert "nothing was queued" in status.lower()


@pytest.mark.asyncio
async def test_reply_rejects_principal_from_another_organization_before_any_query() -> None:
    class NoQueries:
        async def execute(self, statement: object) -> object:
            raise AssertionError("cross-tenant request reached the database")

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    with pytest.raises(ValueError, match="organization"):
        await create_reply(
            NoQueries(),
            organization_id=uuid.uuid4(),
            conversation_id=uuid.uuid4(),
            gateway=object(),
            principal=principal,
        )


@pytest.mark.asyncio
async def test_reply_uses_read_tool_result_in_final_model_prompt(monkeypatch) -> None:
    org_id = uuid.uuid4()
    session_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.DEVELOPER)
    conversation = SimpleNamespace(context_summary=None, message_count=1)
    user_message = SimpleNamespace(role="user", content="How many GitHub alerts?")

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class _Session:
        def __init__(self):
            self.calls = 0
            self.saved = None

        async def execute(self, statement):
            self.calls += 1
            value = [conversation, [user_message], 1, self.saved][self.calls - 1]
            return _Result(value)

        def add(self, row):
            self.saved = row

        async def flush(self):
            return None

        async def commit(self):
            return None

    class _Gateway:
        def __init__(self):
            self.messages = []

        async def complete(self, role, messages):
            self.messages = messages
            return LLMResponse(
                text="17 matching alerts.", model="test", provider="fake", usage=Usage()
            )

    async def snapshot(*args, **kwargs):
        return '{"external_alerts":[]}'

    async def read_tool(*args, **kwargs):
        return '{"source_filter":"github","total":17,"sample":[]}'

    async def canonical_tool(*args, **kwargs):
        return '{"total":2,"filters":{"mine":true},"sample":[]}'

    monkeypatch.setattr("app.services.agent_chat.load_security_snapshot", snapshot)
    monkeypatch.setattr("app.services.agent_chat.maybe_read_exposures", read_tool)
    monkeypatch.setattr("app.services.agent_chat.maybe_read_canonical_findings", canonical_tool)
    gateway = _Gateway()
    message = await create_reply(
        _Session(),
        organization_id=org_id,
        conversation_id=session_id,
        gateway=gateway,
        principal=principal,
    )
    assert message.content == "17 matching alerts."
    assert any('"total":17' in item.content for item in gateway.messages)
    assert any('"total":2' in item.content for item in gateway.messages)


@pytest.mark.asyncio
async def test_queued_action_gets_durable_status_even_if_model_is_unavailable(monkeypatch) -> None:
    from app.core.errors import ModelUnavailableError

    org_id = uuid.uuid4()
    convo_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    conversation = SimpleNamespace(context_summary=None, message_count=1)
    user_message = SimpleNamespace(role="user", content="Sync GitHub alerts")

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class _Session:
        def __init__(self):
            self.calls = 0
            self.saved = None

        async def execute(self, statement):
            self.calls += 1
            return _Result([conversation, [user_message], 1, self.saved][self.calls - 1])

        def add(self, row):
            self.saved = row

        async def flush(self):
            return None

        async def commit(self):
            return None

    class _Unavailable:
        async def complete(self, role, messages):
            raise ModelUnavailableError("provider unavailable")

    async def snapshot(*args, **kwargs):
        return "{}"

    async def no_read(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.agent_chat.load_security_snapshot", snapshot)
    monkeypatch.setattr("app.services.agent_chat.maybe_read_canonical_findings", no_read)
    monkeypatch.setattr("app.services.agent_chat.maybe_read_exposures", no_read)
    message = await create_reply(
        _Session(),
        organization_id=org_id,
        conversation_id=convo_id,
        gateway=_Unavailable(),
        principal=principal,
        action_result='[{"action":"sync_github_alerts","status":"pending_approval"}]',
    )
    assert "not run yet" in message.content
    assert "unavailable" in message.content


@pytest.mark.asyncio
async def test_completed_work_is_reported_when_model_is_unavailable(monkeypatch) -> None:
    from app.core.errors import ModelUnavailableError

    org_id = uuid.uuid4()
    convo_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    conversation = SimpleNamespace(context_summary=None, message_count=1)
    user_message = SimpleNamespace(role="user", content="Did the GitHub sync finish?")

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class _Session:
        def __init__(self):
            self.calls = 0
            self.saved = None

        async def execute(self, statement):
            self.calls += 1
            return _Result([conversation, [user_message], 1, self.saved][self.calls - 1])

        def add(self, row):
            self.saved = row

        async def flush(self):
            return None

        async def commit(self):
            return None

    class _Unavailable:
        async def complete(self, role, messages):
            raise ModelUnavailableError("provider unavailable")

    async def no_read(*args, **kwargs):
        return None

    async def recent_work(*args, **kwargs):
        return '[{"action":"sync_github_alerts","status":"executed",' \
               '"result":"7 alerts synced"}]'

    monkeypatch.setattr("app.services.agent_chat.load_security_snapshot", no_read)
    monkeypatch.setattr("app.services.agent_chat.maybe_read_canonical_findings", no_read)
    monkeypatch.setattr("app.services.agent_chat.maybe_read_exposures", no_read)
    monkeypatch.setattr("app.services.agent_chat.load_recent_work_status", recent_work)
    message = await create_reply(
        _Session(), organization_id=org_id, conversation_id=convo_id,
        gateway=_Unavailable(), principal=principal,
    )
    assert "GitHub alert sync: executed" in message.content
    assert "7 alerts synced" in message.content
