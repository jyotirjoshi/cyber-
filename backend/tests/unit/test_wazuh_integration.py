"""Wazuh connector contracts.

These tests protect the authentication boundary: a regression that sent the API
password with every manager request would expose a long-lived credential far more
often than necessary.
"""

from __future__ import annotations

import base64

import pytest

from app.core.config import Settings
from app.db.enums import IntegrationKind
from app.integrations.wazuh import WazuhClient
from app.services.integration import _spec_for


class _WazuhTransport:
    """Small transport double retaining the requests made at Cynux's boundary."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str] | None, dict[str, str] | None]] = []

    async def post_json(self, path: str, *, params=None, headers=None, **_kwargs):
        self.requests.append(("POST", path, headers, params))
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
    }
    assert spec.required == ("api_username", "api_password")
    assert spec.config == {"verify_tls": "verify_tls"}
