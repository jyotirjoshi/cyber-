"""Wazuh connector contracts.

These tests protect the authentication boundary: a regression that sent the API
password with every manager request would expose a long-lived credential far more
often than necessary.
"""

from __future__ import annotations

import base64
import uuid
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.core.crypto import Secret
from app.db.enums import IntegrationKind, Role
from app.integrations.wazuh import WazuhClient, WazuhIndexerClient
from app.services.context import Principal
from app.services.integration import _spec_for


class _WazuhTransport:
    """Small transport double retaining the requests made at Cynux's boundary."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str] | None, dict[str, str] | None]] = []

    async def post_json(self, path: str, *, params=None, headers=None, **_kwargs):
        self.requests.append(("POST", path, headers, params))
        if path == "/wazuh-alerts*/_search":
            return {"hits": {"hits": [{"_id": "alert-1"}]}}
        return "short-lived-jwt"

    async def get_json(self, path: str, *, headers=None, **_kwargs):
        self.requests.append(("GET", path, headers, None))
        return {"data": {"affected_items": [{"version": "4.14.7"}]}}


@pytest.mark.asyncio
async def test_wazuh_ping_exchanges_password_for_jwt_before_manager_request(monkeypatch) -> None:
    """Replacing the manager request's Bearer token with Basic credentials is a secret-leak bug."""
    transport = _WazuhTransport()
    monkeypatch.setattr("app.integrations.wazuh.build_client", lambda **_kwargs: transport)
    settings = Settings(
        wazuh={
            "base_url": "https://wazuh.example:55000",
            "api_username": "cynux-reader",
            "api_password": "a-long-lived-password",
        }
    )

    assert await WazuhClient(settings).ping() is True

    expected_basic = base64.b64encode(b"cynux-reader:a-long-lived-password").decode("ascii")
    assert transport.requests == [
        (
            "POST",
            "/security/user/authenticate",
            {"Authorization": f"Basic {expected_basic}"},
            {"raw": "true"},
        ),
        ("GET", "/manager/info", {"Authorization": "Bearer short-lived-jwt"}, None),
    ]


def test_wazuh_uses_encrypted_credentials_and_read_only_connection_settings() -> None:
    """A misspelled slot would store a secret that the Wazuh client can never read."""
    spec = _spec_for(IntegrationKind.WAZUH)

    assert spec.section == "wazuh"
    assert spec.base_url_field == "base_url"
    assert spec.credentials == {
        "api_username": "api_username",
        "api_password": "api_password",
        "indexer_username": "indexer_username",
        "indexer_password": "indexer_password",
    }
    assert spec.required == ("api_username", "api_password")
    assert spec.config == {"verify_tls": "verify_tls", "indexer_base_url": "indexer_base_url"}


@pytest.mark.asyncio
async def test_wazuh_indexer_reads_alerts_without_using_manager_credentials(monkeypatch) -> None:
    """Wazuh alert search belongs to the Indexer and uses its own read-only identity."""
    transport = _WazuhTransport()
    monkeypatch.setattr("app.integrations.wazuh.build_client", lambda **_kwargs: transport)
    settings = Settings(
        wazuh={
            "indexer_base_url": "https://wazuh-indexer.example:9200",
            "indexer_username": "cynux-alert-reader",
            "indexer_password": "indexer-password",
        }
    )

    assert await WazuhIndexerClient(settings).list_alerts() == [{"_id": "alert-1"}]

    expected_basic = base64.b64encode(b"cynux-alert-reader:indexer-password").decode("ascii")
    assert transport.requests == [
        (
            "POST",
            "/wazuh-alerts*/_search",
            {"Authorization": f"Basic {expected_basic}", "Content-Type": "application/json"},
            None,
        )
    ]


@pytest.mark.asyncio
async def test_wazuh_sync_accepts_indexer_only_tenant_connection(monkeypatch) -> None:
    from app.services import external_alert
    from app.services import integration as integration_service

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    connection = SimpleNamespace(
        id=uuid.uuid4(),
        kind_enum=IntegrationKind.WAZUH,
        is_usable=True,
        is_enabled=True,
        sync_interval_minutes=None,
        name="Wazuh Indexer",
        base_url=None,
        config={"indexer_base_url": "https://wazuh-indexer.example:9200"},
        credentials=[],
    )

    async def find_integration(*_args, **_kwargs):
        return connection

    def credentials_for(*_args, **_kwargs):
        return {
            "indexer_username": Secret("reader"),
            "indexer_password": Secret("indexer-password"),
        }

    class _Indexer:
        def __init__(self, scoped, redis):
            assert scoped.wazuh.indexer_configured
            assert not scoped.wazuh.configured

        async def list_alerts(self):
            return []

    async def stage(*_args, **_kwargs):
        return SimpleNamespace(total=0)

    async def audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(integration_service, "find_integration", find_integration)
    monkeypatch.setattr(integration_service, "credentials_for", credentials_for)
    monkeypatch.setattr(external_alert, "WazuhIndexerClient", _Indexer)
    monkeypatch.setattr(external_alert, "stage_wazuh_alerts", stage)
    monkeypatch.setattr(external_alert.audit_service, "record", audit)
    result = await external_alert.sync_wazuh_alerts(
        object(),
        principal,
        settings=Settings(),
        redis=None,
    )
    assert result.total == 0
