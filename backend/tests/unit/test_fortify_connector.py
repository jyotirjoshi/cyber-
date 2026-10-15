"""Fortify SSC connector and canonical issue contracts."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.integrations.fortify import FortifySscClient
from app.services.external_alert import normalize_fortify_issue


def _settings() -> Settings:
    return Settings(
        fortify={
            "base_url": "https://ssc.example.com/ssc",
            "automation_token": "decoded-token",
            "application_versions": {"42": "acme/payments"},
        }
    )


@pytest.mark.asyncio
async def test_fortify_reads_complete_application_version_issue_snapshot(monkeypatch) -> None:
    calls: list[tuple[str, dict]] = []

    class _Client:
        async def get_json(self, path, **kwargs):
            calls.append((path, kwargs))
            if path.endswith("/projectVersions/42"):
                return {"data": {"id": 42, "name": "main"}}
            start = kwargs["params"]["start"]
            if start == 0:
                return {
                    "data": [{"issueInstanceId": "iid-1", "issueName": "SQL Injection"}],
                    "count": 1,
                    "totalCount": 1,
                }
            raise AssertionError("unexpected page")

        async def aclose(self):
            return None

    monkeypatch.setattr("app.integrations.fortify.build_client", lambda **_kwargs: _Client())

    rows = await FortifySscClient(_settings()).list_issues()

    assert rows == [
        {
            "issue": {"issueInstanceId": "iid-1", "issueName": "SQL Injection"},
            "application_version_id": "42",
            "asset": "acme/payments",
        }
    ]
    assert calls[1][0] == "/api/v1/projectVersions/42/issues"
    assert calls[1][1]["params"] == {"start": 0, "limit": 200}
    assert calls[1][1]["headers"]["Authorization"] == "FortifyToken decoded-token"


def test_fortify_normalizes_sast_location_identity_and_lifecycle() -> None:
    normalized = normalize_fortify_issue(
        {
            "application_version_id": "42",
            "asset": "acme/payments",
            "issue": {
                "issueInstanceId": "iid-1",
                "issueName": "SQL Injection",
                "friority": "Critical",
                "primaryLocation": "src/db.py:42",
                "kingdom": "Input Validation and Representation",
                "removed": False,
                "audited": False,
            },
        }
    )

    assert normalized.external_id == "42:iid-1"
    assert normalized.resource == "acme/payments"
    assert normalized.category == "sast"
    assert normalized.severity == "critical"
    assert normalized.status == "open"
    assert normalized.evidence["application_version_id"] == "42"
    assert normalized.evidence["file"] == "src/db.py"
    assert normalized.evidence["line"] == 42


def test_fortify_is_a_persistable_continuous_agent_integration() -> None:
    from sqlalchemy import CheckConstraint

    from app.db.enums import AgentActionName, IntegrationKind
    from app.db.models.agent import AgentAction
    from app.db.models.integration import Integration
    from app.services.integration import CONTINUOUS_SYNC_KINDS

    assert IntegrationKind.FORTIFY in CONTINUOUS_SYNC_KINDS
    assert AgentActionName.SYNC_FORTIFY_ISSUES.value == "sync_fortify_issues"
    integration_sql = next(
        str(c.sqltext)
        for c in Integration.__table__.constraints
        if isinstance(c, CheckConstraint) and c.name.endswith("valid_integration_kind")
    )
    action_sql = next(
        str(c.sqltext)
        for c in AgentAction.__table__.constraints
        if isinstance(c, CheckConstraint) and c.name.endswith("valid_agent_action")
    )
    assert "'fortify'" in integration_sql
    assert "'sync_fortify_issues'" in action_sql
