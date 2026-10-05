"""SonarQube Server connector contracts: scoped, complete reads and honest normalization."""

from __future__ import annotations

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.core.errors import IntegrationError


class _Transport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, object], dict[str, str]]] = []

    async def get_json(self, path: str, *, params=None, headers=None):
        self.requests.append((path, dict(params or {}), dict(headers or {})))
        if path == "/api/authentication/validate":
            return {"valid": True}
        page = int(params["p"])
        return {
            "paging": {"pageIndex": page, "pageSize": 100, "total": 101},
            "issues": [
                {"key": f"issue-{number}", "project": "payments", "type": "VULNERABILITY"}
                for number in (range(100) if page == 1 else [100])
            ],
        }


@pytest.mark.asyncio
async def test_sonarqube_reads_every_page_with_tenant_token_and_project_scope(monkeypatch) -> None:
    from app.integrations.sonarqube import SonarQubeClient

    transport = _Transport()
    monkeypatch.setattr("app.integrations.sonarqube.build_client", lambda **kwargs: transport)
    client = SonarQubeClient(
        Settings(
            sonarqube={
                "base_url": "https://sonar.example",
                "api_token": "tenant-token",
                "project_keys": ["payments"],
            }
        )
    )

    assert await client.ping() is True
    issues = await client.list_vulnerabilities()

    assert len(issues) == 101
    assert [request[1]["p"] for request in transport.requests[1:]] == [1, 2]
    assert all(request[1]["componentKeys"] == "payments" for request in transport.requests[1:])
    assert all(request[1]["impactSoftwareQualities"] == "SECURITY" for request in transport.requests[1:])
    assert all(
        request[2]["Authorization"] == "Bearer tenant-token" for request in transport.requests
    )


@pytest.mark.asyncio
async def test_sonarqube_fails_on_truncated_provider_result(monkeypatch) -> None:
    from app.integrations.sonarqube import SonarQubeClient

    class _Truncated:
        async def get_json(self, path: str, *, params=None, headers=None):
            return {"paging": {"total": 101}, "issues": []}

    monkeypatch.setattr("app.integrations.sonarqube.build_client", lambda **kwargs: _Truncated())
    client = SonarQubeClient(
        Settings(
            sonarqube={
                "base_url": "https://sonar.example",
                "api_token": "tenant-token",
                "project_keys": ["payments"],
            }
        )
    )

    with pytest.raises(IntegrationError):
        await client.list_vulnerabilities()


@pytest.mark.asyncio
async def test_sonarqube_rejects_repeated_issue_across_pages(monkeypatch) -> None:
    from app.integrations.sonarqube import SonarQubeClient

    class _Repeated:
        async def get_json(self, path: str, *, params=None, headers=None):
            return {"paging": {"total": 2}, "issues": [{"key": "same", "project": "payments"}]}

    monkeypatch.setattr("app.integrations.sonarqube.build_client", lambda **kwargs: _Repeated())
    client = SonarQubeClient(
        Settings(
            sonarqube={
                "base_url": "https://sonar.example",
                "api_token": "tenant-token",
                "project_keys": ["payments"],
            }
        )
    )
    with pytest.raises(IntegrationError):
        await client.list_vulnerabilities()


@pytest.mark.asyncio
async def test_sonarqube_ignores_nonsecurity_issue_if_legacy_server_ignores_quality_filter(monkeypatch) -> None:
    from app.integrations.sonarqube import SonarQubeClient

    class _Mixed:
        async def get_json(self, path: str, *, params=None, headers=None):
            return {
                "paging": {"total": 2},
                "issues": [
                    {"key": "security", "project": "payments", "type": "VULNERABILITY"},
                    {"key": "maintainability", "project": "payments", "type": "CODE_SMELL"},
                ],
            }

    monkeypatch.setattr("app.integrations.sonarqube.build_client", lambda **kwargs: _Mixed())
    client = SonarQubeClient(
        Settings(sonarqube={"base_url": "https://sonar.example", "api_token": "tenant-token", "project_keys": ["payments"]})
    )
    assert [issue["key"] for issue in await client.list_vulnerabilities()] == ["security"]


@pytest.mark.asyncio
@pytest.mark.parametrize("project_keys", ["payments", ["payments", "payments"], [" "]])
async def test_sonarqube_rejects_invalid_project_keys_before_database_write(project_keys) -> None:
    import uuid

    from app.db.enums import IntegrationKind, Role
    from app.schemas.integration import IntegrationUpsertIn
    from app.services.context import Principal
    from app.services.integration import upsert_integration

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    payload = IntegrationUpsertIn(
        kind=IntegrationKind.SONARQUBE, config={"project_keys": project_keys}
    )
    from app.core.errors import InvalidConfigurationError

    with pytest.raises(InvalidConfigurationError):
        await upsert_integration(None, principal, payload, settings=Settings())


@pytest.mark.asyncio
@pytest.mark.parametrize("reported_project", [None, "other-project"])
async def test_sonarqube_rejects_issues_outside_requested_project(
    monkeypatch, reported_project
) -> None:
    from app.integrations.sonarqube import SonarQubeClient

    class _WrongProject:
        async def get_json(self, path: str, *, params=None, headers=None):
            return {
                "paging": {"total": 1},
                "issues": [{"key": "AZ123", "project": reported_project}],
            }

    monkeypatch.setattr("app.integrations.sonarqube.build_client", lambda **kwargs: _WrongProject())
    client = SonarQubeClient(
        Settings(
            sonarqube={
                "base_url": "https://sonar.example",
                "api_token": "tenant-token",
                "project_keys": ["payments"],
            }
        )
    )
    with pytest.raises(IntegrationError):
        await client.list_vulnerabilities()


def test_sonarqube_vulnerability_normalizes_identity_risk_and_location() -> None:
    from app.services.external_alert import normalize_sonarqube_issue

    alert = normalize_sonarqube_issue(
        "https://sonar.example",
        "payments",
        {
            "key": "AZ123",
            "project": "payments",
            "component": "payments:src/auth.py",
            "line": 18,
            "type": "VULNERABILITY",
            "severity": "BLOCKER",
            "status": "OPEN",
            "message": "SQL injection risk",
            "rule": "python:S3649",
        },
    )

    assert alert.external_id == "payments:AZ123"
    assert alert.severity == "critical"
    assert alert.status == "open"
    assert alert.resource == "payments:src/auth.py:18"
    assert alert.source_url == "https://sonar.example/project/issues?issues=AZ123&id=payments"
    assert alert.title == "SQL injection risk"


def test_sonarqube_modern_high_impact_is_not_downgraded_to_info() -> None:
    from app.services.external_alert import normalize_sonarqube_issue

    alert = normalize_sonarqube_issue(
        "https://sonar.example",
        "payments",
        {
            "key": "AZ456",
            "project": "payments",
            "message": "Authentication bypass",
            "severity": "HIGH",
        },
    )
    assert alert.severity == "high"


def test_sonarqube_security_impact_overrides_legacy_severity() -> None:
    from app.services.external_alert import normalize_sonarqube_issue

    alert = normalize_sonarqube_issue(
        "https://sonar.example", "payments",
        {
            "key": "AZ789", "project": "payments", "message": "Security impact",
            "severity": "INFO",
            "impacts": [
                {"softwareQuality": "SECURITY", "severity": "HIGH"},
                {"softwareQuality": "MAINTAINABILITY", "severity": "LOW"},
            ],
        },
    )
    assert alert.severity == "high"


@pytest.mark.asyncio
async def test_sonarqube_sync_stages_tenant_scoped_idempotent_alerts() -> None:
    import uuid

    from app.services.external_alert import stage_sonarqube_issues
    from tests.unit._empty_rows import EmptyRows

    class _Session:
        def __init__(self) -> None:
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            return EmptyRows()

    session = _Session()
    organization_id = uuid.uuid4()
    result = await stage_sonarqube_issues(
        session,
        organization_id=organization_id,
        integration_id=None,
        base_url="https://sonar.example",
        issues=[
            {
                "key": "AZ123",
                "project": "payments",
                "message": "SQL injection",
                "severity": "BLOCKER",
            }
        ],
    )

    assert result.total == 1
    statement = session.statements[0]
    params = statement.compile(dialect=postgresql.dialect()).params
    assert "sonarqube" in params.values()
    assert "payments:AZ123" in params.values()
    assert organization_id in params.values()
    assert "ON CONFLICT" in str(statement.compile(dialect=postgresql.dialect()))
    assert "missing_sync_count" in str(statement.compile(dialect=postgresql.dialect()))


@pytest.mark.asyncio
async def test_sonarqube_reconciliation_requires_two_complete_misses_within_tenant_and_projects() -> None:
    import uuid

    from sqlalchemy.sql.dml import Update

    from app.services.external_alert import reconcile_missing_sonarqube_issues
    from tests.unit._empty_rows import EmptyRows

    class _Session:
        def __init__(self) -> None:
            self.statement = None

        async def execute(self, statement):
            if isinstance(statement, Update):
                self.statement = statement
                return type("_Result", (), {"rowcount": 1})()
            return EmptyRows()

    session = _Session()
    organization_id = uuid.uuid4()
    closed = await reconcile_missing_sonarqube_issues(
        session,
        organization_id=organization_id,
        project_keys=["payments"],
        observed_external_ids=["payments:AZ123"],
    )
    compiled = session.statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert closed == 1
    assert organization_id in compiled.params.values()
    assert "sonarqube" in compiled.params.values()
    assert ["payments"] in compiled.params.values()
    assert ["payments:AZ123"] in compiled.params.values()
    assert "missing_sync_count" in sql
    assert "CASE WHEN" in sql
    assert "evidence" in sql


@pytest.mark.asyncio
async def test_sonarqube_sync_uses_tenant_settings_and_closes_client(monkeypatch) -> None:
    import uuid
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.services.context import Principal
    from app.services.external_alert import sync_sonarqube_alerts

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    configured = Settings(
        sonarqube={
            "base_url": "https://sonar.example",
            "api_token": "tenant-token",
            "project_keys": ["payments"],
        }
    )
    events = []

    async def find(session, actor, kind):
        assert actor.organization_id == principal.organization_id
        return SimpleNamespace(id=uuid.uuid4())

    async def resolve(session, actor, kind, *, settings, require):
        assert require is True
        return configured

    class _Client:
        def __init__(self, settings, redis):
            assert settings is configured

        async def list_vulnerabilities(self):
            return [{"key": "AZ123", "project": "payments", "message": "SQL injection"}]

        async def aclose(self):
            events.append("closed")

    class _Session:
        async def execute(self, statement):
            events.append("staged")
            from tests.unit._empty_rows import EmptyRows
            return EmptyRows()

    async def record(*args, **kwargs):
        events.append("audited")

    async def reconcile(session, *, organization_id, project_keys, observed_external_ids):
        assert organization_id == principal.organization_id
        assert project_keys == ["payments"]
        assert observed_external_ids == ["payments:AZ123"]
        events.append("reconciled")
        return 0

    monkeypatch.setattr("app.services.integration.find_integration", find)
    monkeypatch.setattr("app.services.integration.resolve_settings", resolve)
    monkeypatch.setattr("app.services.external_alert.SonarQubeClient", _Client)
    monkeypatch.setattr("app.services.external_alert.reconcile_missing_sonarqube_issues", reconcile, raising=False)
    monkeypatch.setattr("app.services.external_alert.audit_service.record", record)

    result = await sync_sonarqube_alerts(_Session(), principal, settings=Settings(), redis=None)
    assert result.total == 1
    assert events == ["staged", "reconciled", "audited", "closed"]


@pytest.mark.asyncio
async def test_sonarqube_sync_endpoint_commits_only_after_success(monkeypatch) -> None:
    import uuid
    from types import SimpleNamespace

    from app.api.v1.integrations import sync_sonarqube_alerts
    from app.db.enums import Role
    from app.services.context import Principal

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    events = []

    class _Session:
        async def commit(self):
            events.append("committed")

    async def sync(session, actor, *, settings, redis):
        events.append("synced")
        return SimpleNamespace(total=2)

    monkeypatch.setattr(
        "app.api.v1.integrations.external_alert_service.sync_sonarqube_alerts", sync
    )
    result = await sync_sonarqube_alerts(principal, _Session(), Settings(), None)
    assert result.kind.value == "sonarqube"
    assert result.alerts_staged == 2
    assert events == ["synced", "committed"]


@pytest.mark.asyncio
async def test_sonarqube_agent_action_requires_approval_then_uses_connector(monkeypatch) -> None:
    import uuid
    from types import SimpleNamespace

    from app.db.base import utcnow
    from app.db.enums import Role
    from app.services import agent_action, external_alert
    from app.services.context import Principal

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = agent_action.new_agent_action(
        organization_id=principal.organization_id,
        session_id=uuid.uuid4(),
        requested_by_user_id=principal.user_id,
        action="sync_sonarqube_alerts",
        label="Sync SonarQube vulnerabilities",
        rationale=None,
        payload={},
    )
    row.status = "approved"
    row.approved_by_user_id = principal.user_id
    row.resolved_at = utcnow()
    calls = []

    async def sync(session, actor, *, settings, redis):
        calls.append(actor.organization_id)
        return SimpleNamespace(total=4)

    async def record(*args, **kwargs):
        return None

    monkeypatch.setattr(external_alert, "sync_sonarqube_alerts", sync)
    monkeypatch.setattr(agent_action.audit_service, "record", record)
    await agent_action.execute_approved_action(
        object(), principal, row, settings=Settings(), redis=None
    )
    assert row.status == "executed"
    assert row.result_summary == "4 alerts synced"
    assert calls == [principal.organization_id]
