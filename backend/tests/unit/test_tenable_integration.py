"""Tenable VM scan ingestion rejects incomplete data and preserves host identity."""

from __future__ import annotations

import uuid

import pytest

from app.core.config import Settings
from app.core.errors import IntegrationError

SCAN = "11111111-1111-4111-8111-111111111111"


class _Transport:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    async def get_json(self, path, *, params=None, headers=None):
        self.requests.append((path, headers))
        return self.responses[len(self.requests) - 1]

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_tenable_reads_each_host_with_scoped_credentials(monkeypatch):
    from app.integrations.tenable import TenableClient

    transport = _Transport([
        {"info": {"is_archived": False, "status": "completed"},
         "hosts": [{"host_id": 7, "hostname": "host.example", "uuid": "host-uuid"}]},
        {"info": {"host-ip": "192.0.2.7"}, "vulnerabilities": [
            {"plugin_id": 123, "plugin_name": "Risk", "severity": 3, "host_id": 7}
        ]},
    ])
    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: transport)
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    results = await client.list_vulnerabilities()
    assert len(results) == 1
    assert results[0]["host_uuid"] == "host-uuid"
    assert [path for path, _ in transport.requests] == [f"/scans/{SCAN}", f"/scans/{SCAN}/hosts/7"]
    assert all(headers["X-ApiKeys"] == "accessKey=access; secretKey=secret" for _, headers in transport.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("scan", [
    {"info": {"is_archived": True}, "hosts": []},
    {"info": {"status": "running", "is_archived": False}, "hosts": []},
    {"info": {"status": "completed", "is_archived": False}},
])
async def test_tenable_rejects_incomplete_scan(monkeypatch, scan):
    from app.integrations.tenable import TenableClient

    transport = _Transport([scan])
    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: transport)
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    with pytest.raises(IntegrationError):
        await client.list_vulnerabilities()
    assert len(transport.requests) == 1


def test_tenable_normalizer_uses_host_and_plugin_not_scan_run():
    from app.services.external_alert import normalize_tenable_vulnerability

    alert = normalize_tenable_vulnerability({
        "scan_id": SCAN, "host_uuid": "host-uuid", "hostname": "host.example",
        "plugin_id": 123, "plugin_name": "Risk", "severity": 3, "host_id": 7,
    })
    assert alert.external_id == f"{SCAN}:host-uuid:123"
    assert alert.severity == "high"
    assert alert.resource == "host.example"


def test_tenable_normalizer_keeps_provider_supplied_cves_for_cross_tool_matching():
    from app.services.external_alert import normalize_tenable_vulnerability

    alert = normalize_tenable_vulnerability({
        "scan_id": SCAN, "host_uuid": "host-uuid", "hostname": "host.example",
        "plugin_id": 123, "plugin_name": "Risk", "severity": 3,
        "cve": "CVE-2024-12345,CVE-2024-99999",
    })
    assert alert.cve_ids == ["CVE-2024-12345", "CVE-2024-99999"]


@pytest.mark.asyncio
async def test_tenable_stages_in_tenant_ledger():
    from sqlalchemy.dialects import postgresql

    from app.services.external_alert import stage_tenable_vulnerabilities
    from tests.unit._empty_rows import EmptyRows

    class _Session:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            return EmptyRows()

    session = _Session()
    tenant_id = uuid.uuid4()
    result = await stage_tenable_vulnerabilities(session, organization_id=tenant_id, integration_id=None,
        vulnerabilities=[{"scan_id": SCAN, "host_uuid": "host-uuid", "hostname": "host.example",
                          "plugin_id": 123, "plugin_name": "Risk", "severity": 3}])
    assert result.total == 1
    params = session.statements[0].compile(dialect=postgresql.dialect()).params
    assert tenant_id in params.values()
    assert "tenable" in params.values()


@pytest.mark.asyncio
async def test_tenable_absence_reconciliation_is_scan_scoped_and_requires_second_miss():
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.sql.dml import Update

    from app.services.external_alert import reconcile_missing_tenable_vulnerabilities
    from tests.unit._empty_rows import EmptyRows

    class _Result:
        rowcount = 2

    class _Session:
        async def execute(self, statement):
            if isinstance(statement, Update):
                self.statement = statement
                return _Result()
            return EmptyRows()

    session = _Session()
    tenant_id = uuid.uuid4()
    count = await reconcile_missing_tenable_vulnerabilities(
        session, organization_id=tenant_id, scan_ids=[SCAN], observed_external_ids=[f"{SCAN}:host-uuid:123"],
    )
    assert count == 2
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert tenant_id in compiled.params.values()
    assert SCAN in str(compiled.params.values())
    assert "missing_sync_count" in str(compiled)


@pytest.mark.asyncio
async def test_tenable_launches_only_configured_scan_without_target_override(monkeypatch):
    from app.integrations.tenable import TenableClient

    class _LaunchTransport:
        def __init__(self):
            self.posts = []

        async def get_json(self, path, *, headers=None):
            return {"status": "completed"}

        async def post_json(self, path, *, json=None, headers=None):
            self.posts.append((path, json, headers))
            return {"scan_uuid": "22222222-2222-4222-8222-222222222222"}

    transport = _LaunchTransport()
    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: transport)
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    launched = await client.launch_scan(SCAN)
    assert launched == "22222222-2222-4222-8222-222222222222"
    assert len(transport.posts) == 1
    assert transport.posts[0][0] == f"/scans/{SCAN}/launch"
    assert transport.posts[0][1] is None
    assert transport.posts[0][2]["X-ApiKeys"] == "accessKey=access; secretKey=secret"


@pytest.mark.asyncio
async def test_tenable_successful_launch_without_run_uuid_is_not_reported_as_failure(monkeypatch):
    from app.integrations.tenable import TenableClient

    class _Transport:
        async def get_json(self, path, *, headers=None):
            return {"status": "completed"}

        async def post_json(self, path, *, headers=None):
            return {}

    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: _Transport())
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    assert await client.launch_scan(SCAN) is None


@pytest.mark.asyncio
async def test_tenable_rejects_unconfigured_scan_before_network(monkeypatch):
    from app.integrations.tenable import TenableClient

    transport = _Transport([])
    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: transport)
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    with pytest.raises(IntegrationError):
        await client.launch_scan("33333333-3333-4333-8333-333333333333")
    assert transport.requests == []


@pytest.mark.asyncio
async def test_tenable_refuses_to_relaunch_active_scan(monkeypatch):
    from app.integrations.tenable import TenableClient

    class _RunningTransport:
        async def get_json(self, path, *, headers=None):
            return {"status": "running"}

        async def post_json(self, path, *, json=None, headers=None):
            raise AssertionError("active scan must not be launched again")

    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: _RunningTransport())
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    with pytest.raises(IntegrationError) as error:
        await client.launch_scan(SCAN)
    assert "running" in error.value.user_message


@pytest.mark.asyncio
async def test_tenable_status_reads_only_configured_scan(monkeypatch):
    from app.integrations.tenable import TenableClient

    transport = _Transport([{"status": "initializing"}])
    monkeypatch.setattr("app.integrations.tenable.build_client", lambda **kwargs: transport)
    client = TenableClient(Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]}))
    assert await client.latest_scan_status(SCAN) == "initializing"
    assert transport.requests[0][0] == f"/scans/{SCAN}/latest-status"


@pytest.mark.asyncio
async def test_tenable_launch_service_checks_permission_and_audits(monkeypatch):
    from types import SimpleNamespace

    from app.core.errors import PermissionDeniedError
    from app.db.enums import Role
    from app.services import integration as integration_service
    from app.services.context import Principal

    settings = Settings(tenable={"access_key": "access", "secret_key": "secret", "scan_ids": [SCAN]})
    calls = []

    async def fake_resolve(*args, **kwargs):
        calls.append("resolve")
        return settings

    async def fake_find(*args, **kwargs):
        return SimpleNamespace(id=uuid.uuid4(), is_usable=True, config={"scan_ids": [SCAN]},
                               credentials=[SimpleNamespace(name="access_key"), SimpleNamespace(name="secret_key")])

    class _Client:
        def __init__(self, *args):
            pass

        async def launch_scan(self, scan_id):
            calls.append(("launch", scan_id))
            return "22222222-2222-4222-8222-222222222222"

        async def aclose(self):
            calls.append("close")

    async def fake_audit(*args, **kwargs):
        calls.append(("audit", kwargs["detail"]["scan_id"]))

    monkeypatch.setattr(integration_service, "resolve_settings", fake_resolve)
    monkeypatch.setattr(integration_service, "find_integration", fake_find)
    monkeypatch.setattr(integration_service, "TenableClient", _Client)
    monkeypatch.setattr(integration_service.audit_service, "record", fake_audit)
    denied = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        await integration_service.launch_tenable_scan(object(), denied, SCAN, settings=settings)
    assert calls == []

    allowed = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    result = await integration_service.launch_tenable_scan(object(), allowed, SCAN, settings=settings)
    assert result == "22222222-2222-4222-8222-222222222222"
    assert calls == ["resolve", ("launch", SCAN), ("audit", SCAN), "close"]


@pytest.mark.asyncio
async def test_tenable_launch_never_uses_deployment_keys_without_tenant_connection(monkeypatch):
    from app.core.errors import IntegrationNotConfiguredError
    from app.db.enums import Role
    from app.services import integration as integration_service
    from app.services.context import Principal

    async def no_integration(*args, **kwargs):
        return None

    monkeypatch.setattr(integration_service, "find_integration", no_integration)
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    settings = Settings(tenable={"access_key": "deployment", "secret_key": "deployment", "scan_ids": [SCAN]})
    with pytest.raises(IntegrationNotConfiguredError):
        await integration_service.launch_tenable_scan(object(), principal, SCAN, settings=settings)


@pytest.mark.asyncio
async def test_tenable_sync_never_uses_deployment_keys_without_tenant_connection(monkeypatch):
    from app.core.errors import IntegrationNotConfiguredError
    from app.db.enums import Role
    from app.services import external_alert as external_alert_service
    from app.services import integration as integration_service
    from app.services.context import Principal

    async def no_integration(*args, **kwargs):
        return None

    def no_provider(*args, **kwargs):
        raise AssertionError("provider must not be called")

    monkeypatch.setattr(integration_service, "find_integration", no_integration)
    monkeypatch.setattr(external_alert_service, "TenableClient", no_provider)
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    settings = Settings(tenable={"access_key": "deployment", "secret_key": "deployment", "scan_ids": [SCAN]})
    with pytest.raises(IntegrationNotConfiguredError):
        await external_alert_service.sync_tenable_vulnerabilities(object(), principal, settings=settings)


@pytest.mark.asyncio
async def test_tenable_api_launch_returns_run_id_and_commits_audit(monkeypatch):
    from app.api.v1 import integrations as integration_api

    class _Session:
        committed = False

        async def commit(self):
            self.committed = True

    async def fake_launch(*args, **kwargs):
        return "22222222-2222-4222-8222-222222222222"

    monkeypatch.setattr(integration_api.integration_service, "launch_tenable_scan", fake_launch)
    session = _Session()
    result = await integration_api.launch_tenable_scan(
        SCAN, object(), session, Settings(), None,
    )
    assert result.scan_id == SCAN
    assert result.run_uuid == "22222222-2222-4222-8222-222222222222"
    assert session.committed
