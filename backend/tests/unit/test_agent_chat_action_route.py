"""A chat turn wires persisted action proposals into the visible reply."""

from __future__ import annotations

import datetime as dt
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.db.enums import Role
from app.schemas.agent import AgentMessageIn
from app.services.context import Principal


@pytest.mark.asyncio
async def test_action_list_shows_actual_assessment_run_and_result() -> None:
    from app.api.v1 import agent as route

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    now = dt.datetime.now(dt.UTC)
    run_id, assessment_id = uuid.uuid4(), uuid.uuid4()
    action = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        run_id=run_id,
        action="start_assessment",
        label="Assess example.org",
        rationale=None,
        payload={"target": "https://example.org", "authorization_reference": "AUTH-123"},
        payload_digest="0" * 64,
        status="executed",
        resolution_note=None,
        resolved_at=now,
        executed_at=now,
        result_summary="Assessment queued",
        created_at=now,
    )

    class _Session:
        def __init__(self):
            self.calls = 0
            self.statements = []

        async def execute(self, statement):
            self.calls += 1
            self.statements.append(statement)
            if self.calls == 1:
                return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [action]))
            return SimpleNamespace(
                all=lambda: [
                    (
                        run_id,
                        "completed",
                        assessment_id,
                        "COMPLETED",
                        "completed",
                        100,
                        5,
                        1,
                        2,
                        3,
                        None,
                        [],
                    )
                ]
            )

    session = _Session()
    result = await route.list_agent_actions(principal, session)

    assert session.calls == 2
    assert result[0].run_status == "completed"
    assert result[0].assessment.id == assessment_id
    assert result[0].assessment.findings_total == 5
    worker_query = session.statements[1].compile(dialect=postgresql.dialect())
    assert principal.organization_id in worker_query.params.values()


@pytest.mark.asyncio
async def test_chat_request_queues_work_and_passes_status_to_reply(monkeypatch) -> None:
    from app.api.v1 import agent as route

    org_id = uuid.uuid4()
    conversation_id = uuid.uuid4()
    gateway_for_request = object()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    calls = []

    class _Session:
        def __init__(self):
            self.message = None

        def add(self, message):
            self.message = message

        async def flush(self):
            return None

        async def commit(self):
            calls.append("commit")

        async def execute(self, statement):
            row = SimpleNamespace(
                id=self.message.id,
                session_id=conversation_id,
                seq=0,
                role="user",
                content=self.message.content,
                created_at=dt.datetime.now(dt.UTC),
            )
            return SimpleNamespace(scalar_one=lambda: row)

    async def resolve(*args):
        return SimpleNamespace(id=conversation_id, message_count=0), False

    async def next_seq(*args):
        return 0

    async def audit(*args, **kwargs):
        return None

    request_settings = Settings()

    async def propose(session, actor, *, session_id, question, gateway, settings):
        calls.append("propose")
        assert session_id == conversation_id
        assert question == "Sync GitHub alerts"
        assert gateway is gateway_for_request
        assert settings is request_settings
        return [
            {"action": "sync_github_alerts", "status": "pending_approval", "id": str(uuid.uuid4())}
        ]

    async def reply(*args, action_result, **kwargs):
        calls.append("reply")
        assert "pending_approval" in action_result
        return SimpleNamespace(
            id=uuid.uuid4(),
            session_id=conversation_id,
            seq=1,
            role="assistant",
            content="Action queued for approval.",
            created_at=dt.datetime.now(dt.UTC),
        )

    class _Emitter:
        def __init__(self, *args, **kwargs):
            pass

        async def message(self, *args):
            pass

        async def thinking(self, *args, **kwargs):
            pass

        async def complete(self):
            pass

    monkeypatch.setattr(route, "_resolve_conversation", resolve)
    monkeypatch.setattr(route, "_next_message_seq", next_seq)
    monkeypatch.setattr(route.audit_service, "record", audit)
    monkeypatch.setattr(route, "propose_chat_actions", propose)
    monkeypatch.setattr(route, "create_reply", reply)
    monkeypatch.setattr(route, "EventEmitter", _Emitter)

    result = await route.post_message(
        AgentMessageIn(session_id=conversation_id, content="Sync GitHub alerts"),
        principal,
        _Session(),
        object(),
        gateway_for_request,
        request_settings,
    )
    assert result.content == "Sync GitHub alerts"
    assert calls == ["commit", "propose", "commit", "reply"]


@pytest.mark.asyncio
async def test_execute_route_returns_completed_action_when_worker_won_race(monkeypatch) -> None:
    from app.api.v1 import agent as route

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    action_id = uuid.uuid4()
    now = dt.datetime.now(dt.UTC)
    action = SimpleNamespace(
        id=action_id,
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        run_id=None,
        action="sync_github_alerts",
        label="Sync GitHub",
        rationale=None,
        payload={},
        payload_digest="0" * 64,
        status="executed",
        resolution_note=None,
        resolved_at=now,
        executed_at=now,
        result_summary="2 alerts synced",
        created_at=now,
    )

    class _Session:
        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: action)

        async def commit(self):
            raise AssertionError("idempotent read must not write")

    async def forbidden_execute(*args, **kwargs):
        raise AssertionError("completed action must not execute again")

    monkeypatch.setattr(route.agent_action_service, "execute_approved_action", forbidden_execute)
    result = await route.execute_agent_action(action_id, principal, _Session(), object(), None)
    assert result.status == "executed"
    assert result.result_summary == "2 alerts synced"


@pytest.mark.asyncio
async def test_execute_route_persists_provider_failure_instead_of_leaving_action_approved(
    monkeypatch,
) -> None:
    from app.api.v1 import agent as route
    from app.core.errors import IntegrationError

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    now = dt.datetime.now(dt.UTC)
    action = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        run_id=None,
        action="sync_github_alerts",
        label="Sync GitHub",
        rationale=None,
        payload={},
        payload_digest="0" * 64,
        depends_on_action_id=None,
        status="approved",
        approved_by_user_id=principal.user_id,
        resolution_note=None,
        resolved_at=now,
        executed_at=None,
        result_summary=None,
        created_at=now,
    )

    class _Session:
        def __init__(self):
            self.commits = 0

        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: action)

        @asynccontextmanager
        async def begin_nested(self):
            yield

        async def commit(self):
            self.commits += 1

    async def unavailable(*args, **kwargs):
        raise IntegrationError(
            "remote detail", provider="GitHub", user_message="GitHub unavailable"
        )

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(route.agent_action_service, "execute_approved_action", unavailable)
    monkeypatch.setattr(route.agent_action_service.audit_service, "record", no_audit)
    session = _Session()
    result = await route.execute_agent_action(
        action.id,
        principal,
        session,
        object(),
        None,
    )
    assert result.status == "failed"
    assert result.result_summary == "GitHub unavailable"
    assert session.commits == 1
