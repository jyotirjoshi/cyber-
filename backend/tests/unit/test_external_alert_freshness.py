"""A complete source read can mark stale observations, never invent closure."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.db.enums import Role
from app.services.context import Principal


class _Result:
    rowcount = 2


class _Session:
    def __init__(self) -> None:
        self.statement = None

    async def execute(self, statement):
        self.statement = statement
        return _Result()


@pytest.mark.asyncio
async def test_github_absence_is_tenant_and_integration_scoped_without_closing() -> None:
    from app.services.external_alert import mark_missing_source_alerts

    session = _Session()
    org_id = uuid.uuid4()
    integration_id = uuid.uuid4()
    cutoff = dt.datetime(2026, 10, 2, tzinfo=dt.UTC)
    count = await mark_missing_source_alerts(
        session, organization_id=org_id, integration_id=integration_id,
        provider="github", sync_started_at=cutoff,
    )

    assert count == 2
    compiled = session.statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert org_id in compiled.params.values()
    assert integration_id in compiled.params.values()
    assert cutoff in compiled.params.values()
    assert "external_security_alerts.provider =" in sql
    assert "external_security_alerts.status =" in sql
    assert "last_seen_at <" in sql
    assert "missing_sync_count" in sql
    assert " SET status=" not in sql


@pytest.mark.asyncio
async def test_gitlab_absence_only_marks_configured_projects() -> None:
    from app.services.external_alert import mark_missing_source_alerts

    session = _Session()
    await mark_missing_source_alerts(
        session, organization_id=uuid.uuid4(), integration_id=None,
        provider="gitlab", sync_started_at=dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
        project_keys=["acme/api"],
    )
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert ["acme/api"] in compiled.params.values()
    assert "external_security_alerts.evidence" in str(compiled)


@pytest.mark.asyncio
async def test_gitlab_absence_with_no_project_scope_does_not_update_anything() -> None:
    from app.services.external_alert import mark_missing_source_alerts

    session = _Session()
    count = await mark_missing_source_alerts(
        session, organization_id=uuid.uuid4(), integration_id=None,
        provider="gitlab", sync_started_at=dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
        project_keys=[],
    )
    assert count == 0
    assert session.statement is None


@pytest.mark.asyncio
async def test_github_sync_marks_missing_only_after_successful_complete_fetch(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.services.external_alert import sync_github_alerts

    org_id = uuid.uuid4()
    integration_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    session = _Session()
    events: list[str] = []

    async def find(*args):
        return SimpleNamespace(id=integration_id)

    async def resolve(*args, **kwargs):
        return Settings(github={"api_token": "test", "organization": "acme"})

    class _Client:
        def __init__(self, *args):
            pass

        async def list_security_alerts(self):
            events.append("fetched")
            return [SimpleNamespace(kind=kind, alerts=[]) for kind in (
                "dependabot", "code_scanning", "secret_scanning"
            )]

    async def audit(*args, **kwargs):
        events.append("audited")

    monkeypatch.setattr("app.services.integration.find_integration", find)
    monkeypatch.setattr("app.services.integration.resolve_settings", resolve)
    monkeypatch.setattr("app.services.external_alert.GitHubClient", _Client)
    monkeypatch.setattr("app.services.external_alert.audit_service.record", audit)

    await sync_github_alerts(session, principal, settings=Settings())
    assert events == ["fetched", "audited"]
    assert session.statement is not None
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert org_id in compiled.params.values()
    assert integration_id in compiled.params.values()
    assert "missing_sync_count" in str(compiled)


@pytest.mark.asyncio
async def test_failed_github_fetch_never_marks_existing_alerts_absent(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.core.errors import IntegrationError
    from app.services.external_alert import sync_github_alerts

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session = _Session()

    async def find(*args):
        return SimpleNamespace(id=uuid.uuid4())

    async def resolve(*args, **kwargs):
        return Settings(github={"api_token": "test", "organization": "acme"})

    class _Client:
        def __init__(self, *args):
            pass

        async def list_security_alerts(self):
            raise IntegrationError("incomplete feed", provider="GitHub")

    monkeypatch.setattr("app.services.integration.find_integration", find)
    monkeypatch.setattr("app.services.integration.resolve_settings", resolve)
    monkeypatch.setattr("app.services.external_alert.GitHubClient", _Client)
    with pytest.raises(IntegrationError):
        await sync_github_alerts(session, principal, settings=Settings())
    assert session.statement is None


@pytest.mark.asyncio
async def test_gitlab_sync_marks_only_selected_project_after_complete_fetch(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.services.external_alert import sync_gitlab_alerts

    org_id = uuid.uuid4()
    integration_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.OWNER)
    session = _Session()

    async def find(*args):
        return SimpleNamespace(id=integration_id)

    async def resolve(*args, **kwargs):
        return Settings(gitlab={"api_token": "test", "project_ids": ["acme/api"]})

    class _Client:
        def __init__(self, *args):
            pass

        async def list_security_alerts(self):
            return [SimpleNamespace(project="acme/api", alerts=[])]

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.integration.find_integration", find)
    monkeypatch.setattr("app.services.integration.resolve_settings", resolve)
    monkeypatch.setattr("app.services.external_alert.GitLabClient", _Client)
    monkeypatch.setattr("app.services.external_alert.audit_service.record", audit)

    await sync_gitlab_alerts(session, principal, settings=Settings())
    assert session.statement is not None
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert org_id in compiled.params.values()
    assert integration_id in compiled.params.values()
    assert ["acme/api"] in compiled.params.values()
