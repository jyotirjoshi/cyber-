"""Snyk's read path must be complete, scoped, and safe before staging."""

from __future__ import annotations

import uuid

import pytest

from app.core.config import Settings
from app.core.errors import IntegrationError

ORG_ID = "11111111-1111-4111-8111-111111111111"


class _Transport:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    async def get_json(self, path, *, params=None, headers=None):
        self.requests.append((path, dict(params or {}), dict(headers or {})))
        return self.pages[len(self.requests) - 1]

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_snyk_reads_all_pages_with_tenant_token_and_org_scope(monkeypatch) -> None:
    from app.integrations.snyk import SnykClient

    transport = _Transport([
        {"data": [{"id": "one", "attributes": {"title": "First"}}],
         "links": {"next": f"/rest/orgs/{ORG_ID}/issues?version=2024-10-15&page[after]=next"}},
        {"data": [{"id": "two", "attributes": {"title": "Second"}}],
         "links": {"next": None}},
    ])
    monkeypatch.setattr("app.integrations.snyk.build_client", lambda **kwargs: transport)
    client = SnykClient(Settings(snyk={"api_token": "tenant-token", "organization_id": ORG_ID}))
    issues = await client.list_issues()
    assert [issue["id"] for issue in issues] == ["one", "two"]
    assert all(f"/orgs/{ORG_ID}/issues" in path for path, _, _ in transport.requests)
    assert all(headers["Authorization"] == "token tenant-token" for _, _, headers in transport.requests)
    await client.aclose()


@pytest.mark.asyncio
async def test_snyk_rejects_foreign_cursor_before_sending_token(monkeypatch) -> None:
    from app.integrations.snyk import SnykClient

    transport = _Transport([{"data": [], "links": {"next": "https://evil.example/steal"}}])
    monkeypatch.setattr("app.integrations.snyk.build_client", lambda **kwargs: transport)
    client = SnykClient(Settings(snyk={"api_token": "tenant-token", "organization_id": ORG_ID}))
    with pytest.raises(IntegrationError):
        await client.list_issues()
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_snyk_rejects_malformed_page_instead_of_importing_partial_data(monkeypatch) -> None:
    from app.integrations.snyk import SnykClient

    transport = _Transport([{"data": [{"attributes": {"title": "No ID"}}], "links": {"next": None}}])
    monkeypatch.setattr("app.integrations.snyk.build_client", lambda **kwargs: transport)
    client = SnykClient(Settings(snyk={"api_token": "tenant-token", "organization_id": ORG_ID}))
    with pytest.raises(IntegrationError):
        await client.list_issues()


def test_snyk_issue_normalization_preserves_provider_identity_and_state() -> None:
    from app.services.external_alert import normalize_snyk_issue

    alert = normalize_snyk_issue(ORG_ID, {
        "id": "issue-7", "type": "issue",
        "attributes": {"title": "Vulnerable dependency", "effective_severity_level": "high", "status": "open"},
        "relationships": {"scan_item": {"data": {"id": "project-9"}}},
    })
    assert alert.external_id == f"{ORG_ID}:issue-7"
    assert alert.severity == "high"
    assert alert.status == "open"
    assert alert.resource == "project-9"
    assert alert.title == "Vulnerable dependency"


def test_snyk_ignored_issue_is_not_presented_as_open() -> None:
    from app.services.external_alert import normalize_snyk_issue

    alert = normalize_snyk_issue(ORG_ID, {
        "id": "issue-ignored",
        "attributes": {"title": "Accepted issue", "severity": "medium", "status": "ignored"},
    })
    assert alert.status == "dismissed"


def test_snyk_rejects_identity_that_cannot_fit_unique_ledger_key() -> None:
    from app.services.external_alert import normalize_snyk_issue

    with pytest.raises(ValueError):
        normalize_snyk_issue(ORG_ID, {
            "id": "x" * 264,
            "attributes": {"title": "A vulnerability", "status": "open"},
        })


def test_snyk_kind_is_available_to_tenant_integration_settings() -> None:
    from app.db.enums import IntegrationKind
    from app.services.integration import _SPECS

    assert IntegrationKind.SNYK in _SPECS
    assert _SPECS[IntegrationKind.SNYK].required == ("api_token",)
    assert uuid.UUID(ORG_ID)


@pytest.mark.asyncio
async def test_snyk_sync_stages_tenant_scoped_issue() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.external_alert import stage_snyk_issues
    from tests.unit._empty_rows import EmptyRows

    class _Session:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            return EmptyRows()

    session = _Session()
    tenant_id = uuid.uuid4()
    result = await stage_snyk_issues(
        session, organization_id=tenant_id, integration_id=None, snyk_organization_id=ORG_ID,
        issues=[{"id": "issue-7", "attributes": {"title": "A vulnerability", "severity": "high"}}],
    )
    assert result.total == 1
    compiled = session.statements[0].compile(dialect=postgresql.dialect())
    assert tenant_id in compiled.params.values()
    assert "snyk" in compiled.params.values()


@pytest.mark.asyncio
async def test_snyk_rejects_wrong_organization_or_host_before_network(monkeypatch) -> None:
    from app.integrations.snyk import SnykClient

    transport = _Transport([])
    monkeypatch.setattr("app.integrations.snyk.build_client", lambda **kwargs: transport)
    for values in (
        {"api_token": "secret", "organization_id": "not-a-uuid"},
        {"api_token": "secret", "organization_id": ORG_ID, "base_url": "https://evil.example"},
    ):
        with pytest.raises(IntegrationError):
            await SnykClient(Settings(snyk=values)).list_issues()
    assert not transport.requests


def test_snyk_agent_sync_action_requires_separate_approval_and_no_secret_payload() -> None:
    from app.services.agent_action import validate_action_payload

    assert validate_action_payload("sync_snyk_issues", {}) == {}
    with pytest.raises(ValueError):
        validate_action_payload("sync_snyk_issues", {"api_token": "no"})
