"""Checkmarx One connector and canonical result contracts."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.integrations.checkmarx import CheckmarxClient
from app.services.external_alert import normalize_checkmarx_result

PROJECT_ID = "683c51da-8644-4e27-990f-1128ab911a1b"
SCAN_ID = "3c028677-5df7-4bd9-8a10-7214ced45670"


def _settings() -> Settings:
    return Settings(checkmarx={
        "base_url": "https://ast.checkmarx.net",
        "auth_url": "https://iam.checkmarx.net",
        "tenant": "acme",
        "client_id": "cynux-reader",
        "client_secret": "secret",
        "projects": {PROJECT_ID: "acme/payments"},
    })


@pytest.mark.asyncio
async def test_checkmarx_authenticates_and_reads_latest_complete_results(monkeypatch) -> None:
    api_calls = []

    class _Auth:
        async def request(self, method, path, **kwargs):
            assert method == "POST"
            assert path == "/auth/realms/acme/protocol/openid-connect/token"
            assert kwargs["data"]["grant_type"] == "client_credentials"
            return _Response({"access_token": "bearer", "expires_in": 300})
        async def aclose(self): return None

    class _Api:
        async def get_json(self, path, **kwargs):
            api_calls.append((path, kwargs))
            if path == "/api/scans":
                return {"scans": [{"id": SCAN_ID, "projectId": PROJECT_ID, "status": "Completed"}], "totalCount": 1}
            return {"results": [{"id": "result-1", "scanId": SCAN_ID}], "totalCount": 1}
        async def aclose(self): return None

    clients = iter([_Auth(), _Api()])
    monkeypatch.setattr("app.integrations.checkmarx.build_client", lambda **_kwargs: next(clients))

    rows = await CheckmarxClient(_settings()).list_results()

    assert rows == [{"result": {"id": "result-1", "scanId": SCAN_ID}, "project_id": PROJECT_ID, "asset": "acme/payments"}]
    assert api_calls[0][1]["params"]["project-id"] == PROJECT_ID
    assert api_calls[1][1]["params"] == {"scan-id": SCAN_ID, "limit": 100, "offset": 0}
    assert api_calls[1][1]["headers"]["Authorization"] == "Bearer bearer"


def test_checkmarx_normalizes_sast_result_location_and_lifecycle() -> None:
    normalized = normalize_checkmarx_result({
        "project_id": PROJECT_ID,
        "asset": "acme/payments",
        "result": {
            "id": "result-1", "scanId": SCAN_ID, "type": "sast", "severity": "HIGH",
            "status": "NEW", "state": "TO_VERIFY", "data": {"queryName": "SQL Injection", "fileName": "src/db.py", "line": 42},
        },
    })
    assert normalized.external_id == "result-1"
    assert normalized.resource == "acme/payments"
    assert normalized.category == "sast"
    assert normalized.status == "open"
    assert normalized.evidence["file"] == "src/db.py"
    assert normalized.evidence["line"] == 42


def test_checkmarx_is_a_persistable_continuous_agent_integration() -> None:
    from sqlalchemy import CheckConstraint

    from app.db.enums import AgentActionName, IntegrationKind
    from app.db.models.agent import AgentAction
    from app.db.models.integration import Integration
    from app.services.integration import CONTINUOUS_SYNC_KINDS
    assert IntegrationKind.CHECKMARX in CONTINUOUS_SYNC_KINDS
    assert AgentActionName.SYNC_CHECKMARX_RESULTS.value == "sync_checkmarx_results"
    integration_sql = next(str(c.sqltext) for c in Integration.__table__.constraints if isinstance(c, CheckConstraint) and c.name.endswith("valid_integration_kind"))
    action_sql = next(str(c.sqltext) for c in AgentAction.__table__.constraints if isinstance(c, CheckConstraint) and c.name.endswith("valid_agent_action"))
    assert "'checkmarx'" in integration_sql
    assert "'sync_checkmarx_results'" in action_sql


class _Response:
    def __init__(self, payload): self._payload = payload
    def json(self): return self._payload
    content = b"{}"
