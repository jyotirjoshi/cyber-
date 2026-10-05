"""GitHub alert decisions are scoped, explicit, and provider-confirmed."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.github import GitHubClient


class _Transport:
    def __init__(self, state: str):
        self.state = state
        self.patches = []

    async def patch_json(self, path, *, json=None, headers=None):
        self.patches.append((path, json, headers))
        return {"number": 7, "state": self.state}


@pytest.mark.asyncio
@pytest.mark.parametrize(("category", "reason", "state", "path", "body"), [
    ("dependabot", "tolerable_risk", "dismissed", "/repos/acme/app/dependabot/alerts/7",
     {"state": "dismissed", "dismissed_reason": "tolerable_risk", "dismissed_comment": "Reviewed risk"}),
    ("code_scanning", "false positive", "dismissed", "/repos/acme/app/code-scanning/alerts/7",
     {"state": "dismissed", "dismissed_reason": "false positive", "dismissed_comment": "Reviewed risk"}),
    ("secret_scanning", "false_positive", "resolved", "/repos/acme/app/secret-scanning/alerts/7",
     {"state": "resolved", "resolution": "false_positive", "resolution_comment": "Reviewed risk"}),
])
async def test_github_decision_sends_provider_specific_payload(monkeypatch, category, reason, state, path, body):
    transport = _Transport(state)
    monkeypatch.setattr("app.integrations.github.build_client", lambda **kwargs: transport)
    client = GitHubClient(Settings(github={"organization": "acme", "api_token": "token"}))
    result = await client.set_alert_state(category, "acme/app", 7, decision="dismiss", reason=reason,
                                          comment="Reviewed risk")
    assert result == state
    assert transport.patches[0][0] == path
    assert transport.patches[0][1] == body
    assert transport.patches[0][2]["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_github_reopen_does_not_send_dismissal_reason(monkeypatch):
    transport = _Transport("open")
    monkeypatch.setattr("app.integrations.github.build_client", lambda **kwargs: transport)
    client = GitHubClient(Settings(github={"organization": "acme", "api_token": "token"}))
    assert await client.set_alert_state("dependabot", "acme/app", 7, decision="reopen") == "open"
    assert transport.patches[0][1] == {"state": "open"}


@pytest.mark.asyncio
@pytest.mark.parametrize("repository,number,reason", [
    ("other/app", 7, "tolerable_risk"),
    ("acme/../app", 7, "tolerable_risk"),
    ("acme/app", 0, "tolerable_risk"),
    ("acme/app", 7, "not_a_reason"),
])
async def test_github_rejects_foreign_or_invalid_alert_before_write(monkeypatch, repository, number, reason):
    transport = _Transport("dismissed")
    monkeypatch.setattr("app.integrations.github.build_client", lambda **kwargs: transport)
    client = GitHubClient(Settings(github={"organization": "acme", "api_token": "token"}))
    with pytest.raises(IntegrationError):
        await client.set_alert_state("dependabot", repository, number, decision="dismiss",
                                     reason=reason, comment="Reviewed risk")
    assert transport.patches == []


@pytest.mark.asyncio
async def test_github_does_not_accept_unconfirmed_provider_status(monkeypatch):
    transport = _Transport("open")
    monkeypatch.setattr("app.integrations.github.build_client", lambda **kwargs: transport)
    client = GitHubClient(Settings(github={"organization": "acme", "api_token": "token"}))
    with pytest.raises(IntegrationError):
        await client.set_alert_state("dependabot", "acme/app", 7, decision="dismiss",
                                     reason="tolerable_risk", comment="Reviewed risk")


@pytest.mark.asyncio
async def test_github_alert_service_updates_local_state_only_after_provider_confirmation(monkeypatch):
    from app.db.enums import Role
    from app.services import external_alert as service
    from app.services import integration as integration_service
    from app.services.context import Principal

    row = SimpleNamespace(id=uuid.uuid4(), provider="github", category="dependabot",
                          resource="acme/app", evidence={"alert_number": "7"},
                          external_id="dependabot:acme/app:7", status="open",
                          raw_payload={"number": 7, "state": "open"}, missing_sync_count=0)
    class _Result:
        def scalar_one_or_none(self):
            return row

    class _Session:
        async def execute(self, statement):
            self.statement = statement
            return _Result()

    async def fake_find(*args, **kwargs):
        return SimpleNamespace(id=uuid.uuid4(), is_usable=True,
                               config={"organization": "acme"},
                               credentials=[SimpleNamespace(name="api_token")])

    async def fake_resolve(*args, **kwargs):
        return Settings(github={"organization": "acme", "api_token": "token"})

    class _Client:
        def __init__(self, *args):
            pass

        async def set_alert_state(self, *args, **kwargs):
            assert row.status == "open"
            return "dismissed"

        async def aclose(self):
            pass

    audits = []
    async def fake_audit(*args, **kwargs):
        audits.append(kwargs["detail"])

    monkeypatch.setattr(integration_service, "find_integration", fake_find)
    monkeypatch.setattr(integration_service, "resolve_settings", fake_resolve)
    monkeypatch.setattr(service, "GitHubClient", _Client)
    monkeypatch.setattr(service.audit_service, "record", fake_audit)
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session = _Session()
    updated = await service.set_github_alert_state(
        session, principal, row.id, decision="dismiss", reason="tolerable_risk",
        comment="Reviewed risk", settings=Settings(),
    )
    assert updated is row
    assert row.status == "dismissed"
    assert row.raw_payload["state"] == "dismissed"
    assert audits[0]["to"] == "dismissed"
    assert principal.organization_id in session.statement.compile().params.values()


@pytest.mark.asyncio
async def test_github_alert_service_preserves_local_state_when_provider_rejects(monkeypatch):
    from app.db.enums import Role
    from app.services import external_alert as service
    from app.services import integration as integration_service
    from app.services.context import Principal

    row = SimpleNamespace(id=uuid.uuid4(), provider="github", category="dependabot",
                          resource="acme/app", evidence={"alert_number": "7"},
                          external_id="dependabot:acme/app:7", status="open",
                          raw_payload={"number": 7, "state": "open"}, missing_sync_count=0)

    class _Result:
        def scalar_one_or_none(self):
            return row

    class _Session:
        async def execute(self, statement):
            return _Result()

    async def fake_find(*args, **kwargs):
        return SimpleNamespace(is_usable=True, config={"organization": "acme"},
                               credentials=[SimpleNamespace(name="api_token")])

    async def fake_resolve(*args, **kwargs):
        return Settings(github={"organization": "acme", "api_token": "token"})

    class _Client:
        def __init__(self, *args):
            pass

        async def set_alert_state(self, *args, **kwargs):
            raise IntegrationError("Provider rejected update", provider="GitHub")

        async def aclose(self):
            pass

    monkeypatch.setattr(integration_service, "find_integration", fake_find)
    monkeypatch.setattr(integration_service, "resolve_settings", fake_resolve)
    monkeypatch.setattr(service, "GitHubClient", _Client)
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    with pytest.raises(IntegrationError):
        await service.set_github_alert_state(
            _Session(), principal, row.id, decision="dismiss", reason="tolerable_risk",
            comment="Reviewed risk", settings=Settings(),
        )
    assert row.status == "open"
    assert row.raw_payload["state"] == "open"


@pytest.mark.asyncio
async def test_github_alert_service_rejects_missing_tenant_connection_before_provider(monkeypatch):
    from app.core.errors import IntegrationNotConfiguredError
    from app.db.enums import Role
    from app.services import external_alert as service
    from app.services import integration as integration_service
    from app.services.context import Principal

    async def no_integration(*args, **kwargs):
        return None

    monkeypatch.setattr(integration_service, "find_integration", no_integration)
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    with pytest.raises(IntegrationNotConfiguredError):
        await service.set_github_alert_state(object(), principal, uuid.uuid4(),
            decision="dismiss", reason="tolerable_risk", comment="Reviewed risk",
            settings=Settings(github={"organization": "acme", "api_token": "deployment"}))


def test_github_source_action_requires_explicit_rationale():
    from pydantic import ValidationError

    from app.schemas.external_alert import ExternalAlertSourceActionIn

    with pytest.raises(ValidationError):
        ExternalAlertSourceActionIn(decision="dismiss", reason="tolerable_risk")
    with pytest.raises(ValidationError):
        ExternalAlertSourceActionIn(decision="reopen", reason="tolerable_risk")
    assert ExternalAlertSourceActionIn(decision="dismiss", reason="tolerable_risk", comment="Reviewed risk").comment == "Reviewed risk"


@pytest.mark.asyncio
async def test_github_source_action_route_commits_confirmed_status(monkeypatch):
    from app.api.v1 import external_alerts as api
    from app.schemas.external_alert import ExternalAlertSourceActionIn

    row = SimpleNamespace(id=uuid.uuid4(), provider="github", category="dependabot", title="Risk",
                          severity="high", status="dismissed", resource="acme/app", cve_ids=[],
                          first_seen_at=None, last_seen_at=None, missing_sync_count=0,
                          triage_status="new", external_id="dependabot:acme/app:7",
                          source_url=None, triage_note=None, triage_version=0,
                          triaged_at=None)
    class _Session:
        committed = False

        async def commit(self):
            self.committed = True

    async def fake_service(*args, **kwargs):
        return row

    monkeypatch.setattr(api, "set_github_alert_state", fake_service)
    session = _Session()
    result = await api.update_github_alert_source(
        row.id,
        ExternalAlertSourceActionIn(decision="dismiss", reason="tolerable_risk", comment="Reviewed risk"),
        object(), session, Settings(), None,
    )
    assert result.status == "dismissed"
    assert session.committed
