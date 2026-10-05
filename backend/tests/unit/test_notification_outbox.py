"""External notifications are sent only after their rows are committed."""

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.db.enums import NotificationChannel, NotificationEvent, NotificationStatus, Role, Severity
from app.db.models.notification import Notification
from app.services import notification as notifications
from app.services.audit import AuditAction
from app.services.context import ACTOR_WORKER, Principal


@pytest.mark.asyncio
async def test_dispatch_queues_email_without_sending_before_transaction_commit(monkeypatch):
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)

    class _Session:
        def __init__(self):
            self.rows = []

        def add(self, row):
            self.rows.append(row)

        @asynccontextmanager
        async def begin_nested(self):
            yield

        async def flush(self):
            pass

    async def fake_policy(*args):
        return SimpleNamespace(notify_min_severity=Severity.INFO, email_recipients=[])

    async def not_recorded(*args):
        return False

    async def must_not_deliver(*args, **kwargs):
        raise AssertionError("provider was called before commit")

    audits = []

    async def fake_audit(*args, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(notifications, "_policy", fake_policy)
    monkeypatch.setattr(notifications, "_already_recorded", not_recorded)
    monkeypatch.setattr(notifications, "_deliver", must_not_deliver)
    monkeypatch.setattr(notifications.audit_service, "record", fake_audit)

    session = _Session()
    rows = await notifications.dispatch(
        session, principal, event=NotificationEvent.CRITICAL_FINDING,
        content=notifications.NotificationContent(subject="Critical risk", body="Please review",
                                                  link="https://example.test/finding/1"),
        settings=Settings(), channels=(NotificationChannel.EMAIL,),
        extra_emails=("analyst@example.test",), severity=Severity.CRITICAL,
        resource_id="finding-1",
    )
    assert len(rows) == 1
    assert rows[0].status == NotificationStatus.PENDING.value
    assert rows[0].payload == {"link": "https://example.test/finding/1", "severity": "critical"}
    assert audits[0]["action"] == AuditAction.NOTIFICATION_QUEUE
    assert audits[0]["detail"]["queued"] == 1


@pytest.mark.asyncio
async def test_outbox_worker_delivers_committed_rows_with_original_content(monkeypatch):
    org_id = uuid.uuid4()
    row = Notification(
        id=uuid.uuid4(), organization_id=org_id,
        event=NotificationEvent.CRITICAL_FINDING.value,
        channel=NotificationChannel.EMAIL.value,
        status=NotificationStatus.PENDING.value,
        recipient="analyst@example.test", subject="Critical risk", body="Please review",
        payload={"link": "https://example.test/finding/1", "severity": "critical"},
        dedupe_key="finding-1", attempts=0,
    )

    class _Result:
        def scalars(self):
            return self

        def all(self):
            return [row]

    class _Session:
        async def execute(self, statement):
            self.statement = statement
            return _Result()

    delivered = []
    audited = []

    async def fake_deliver(session, principal, actual_row, content, *, severity, settings, redis):
        delivered.append((principal, actual_row, content, severity))
        actual_row.status = NotificationStatus.SENT.value

    async def fake_audit(*args, **kwargs):
        audited.append(kwargs)

    monkeypatch.setattr(notifications, "_deliver", fake_deliver)
    monkeypatch.setattr(notifications.audit_service, "record", fake_audit)
    session = _Session()
    assert await notifications.deliver_pending(session, settings=Settings()) == 1
    actor, actual_row, content, severity = delivered[0]
    assert actor.organization_id == org_id
    assert actor.actor_type == ACTOR_WORKER
    assert actual_row is row
    assert content.link == "https://example.test/finding/1"
    assert severity == Severity.CRITICAL
    assert row.status == NotificationStatus.SENT.value
    assert audited[0]["action"] == AuditAction.NOTIFICATION_SEND
    assert audited[0]["resource_id"] == row.id


@pytest.mark.asyncio
async def test_dispatch_dedupe_race_does_not_abort_caller_transaction(monkeypatch):
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    checks = 0

    class _Session:
        def __init__(self):
            self.savepoint_entered = False
            self.savepoint_rolled_back = False

        def add(self, row):
            pass

        @asynccontextmanager
        async def begin_nested(self):
            self.savepoint_entered = True
            try:
                yield
            except IntegrityError:
                self.savepoint_rolled_back = True
                raise

        async def flush(self):
            raise IntegrityError("INSERT", {}, Exception("unique_notification"))

    async def fake_policy(*args):
        return SimpleNamespace(notify_min_severity=Severity.INFO, email_recipients=[])

    async def recorded_after_race(*args):
        nonlocal checks
        checks += 1
        return checks > 1

    monkeypatch.setattr(notifications, "_policy", fake_policy)
    monkeypatch.setattr(notifications, "_already_recorded", recorded_after_race)
    session = _Session()
    rows = await notifications.dispatch(
        session, principal, event=NotificationEvent.CRITICAL_FINDING,
        content=notifications.NotificationContent(subject="Risk", body="Review"),
        settings=Settings(), channels=(NotificationChannel.EMAIL,),
        extra_emails=("analyst@example.test",), severity=Severity.CRITICAL,
        resource_id="finding-1",
    )
    assert rows == []
    assert session.savepoint_entered
    assert session.savepoint_rolled_back


@pytest.mark.asyncio
async def test_worker_maintenance_drains_notification_outbox(monkeypatch):
    from app.worker import worker as worker_module

    worker = object.__new__(worker_module.AgentWorker)
    worker._settings = Settings()
    worker._redis = None
    worker._stopping = False
    session = object()
    calls = []

    @asynccontextmanager
    async def fake_scope(*args):
        yield session

    async def fake_reclaim(actual_session):
        assert actual_session is session
        worker._stopping = True

    async def fake_deliver(actual_session, *, settings, redis):
        calls.append((actual_session, settings, redis))
        return 1

    async def fake_agent_actions(actual_session, *, settings, redis):
        calls.append(("agent_actions", actual_session, settings, redis))
        return 1

    monkeypatch.setattr(worker_module, "_MAINTENANCE_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(worker_module, "session_scope", fake_scope)
    monkeypatch.setattr(worker_module, "reclaim_orphans", fake_reclaim)
    monkeypatch.setattr(worker_module, "deliver_pending", fake_deliver, raising=False)
    monkeypatch.setattr(worker_module, "execute_approved_batch", fake_agent_actions, raising=False)
    await worker._maintenance_loop()
    assert len(calls) == 2
    assert calls[0][0] is session
    assert calls[1] == ("agent_actions", session, worker._settings, worker._redis)


@pytest.mark.asyncio
async def test_production_notification_never_uses_global_slack_credential_for_unconfigured_tenant(
    monkeypatch,
):
    org_id = uuid.uuid4()
    row = Notification(
        id=uuid.uuid4(), organization_id=org_id,
        event=NotificationEvent.CRITICAL_FINDING.value,
        channel=NotificationChannel.SLACK.value,
        status=NotificationStatus.PENDING.value, recipient="#security",
        subject="Critical risk", body="Review", payload={}, dedupe_key="risk", attempts=0,
    )
    actor = Principal(user_id=None, organization_id=org_id, role=Role.VIEWER,
                      actor_type=ACTOR_WORKER)
    sends = []

    class _Slack:
        def __init__(self, *args):
            pass

        async def notify(self, *args, **kwargs):
            sends.append(kwargs)

    async def no_connection(*args, **kwargs):
        return None

    async def global_fallback(*args, **kwargs):
        return Settings(environment="production", notify={"slack_bot_token": "global-token"})

    monkeypatch.setattr(notifications, "SlackClient", _Slack)
    monkeypatch.setattr(notifications, "resolve_settings", global_fallback)
    monkeypatch.setattr("app.services.integration.find_integration", no_connection)
    settings = Settings(environment="production", notify={"slack_bot_token": "global-token"})
    await notifications._deliver(
        object(), actor, row, notifications.NotificationContent(subject="Critical risk", body="Review"),
        severity=Severity.CRITICAL, settings=settings, redis=None,
    )
    assert sends == []
    assert row.status == NotificationStatus.FAILED.value
