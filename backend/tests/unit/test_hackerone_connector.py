"""HackerOne customer report connector and canonical normalization contracts."""

from __future__ import annotations

import base64

import pytest

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.hackerone import HackerOneClient
from app.services.external_alert import normalize_hackerone_report


def _settings() -> Settings:
    return Settings(
        hackerone={
            "api_username": "analyst@example.com",
            "api_token": "secret",
            "program_handles": ["acme"],
        }
    )


@pytest.mark.asyncio
async def test_hackerone_reads_every_program_scoped_page(monkeypatch) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class _Client:
        async def get_json(self, path, **kwargs):
            calls.append((path, kwargs))
            if len(calls) == 1:
                return {
                    "data": [_report("101")],
                    "links": {
                        "next": "https://api.hackerone.com/v1/reports?page%5Bnumber%5D=2&page%5Bsize%5D=100&filter%5Bprogram%5D%5B%5D=acme"
                    },
                }
            return {"data": [_report("102")], "links": {"next": None}}

        async def aclose(self):
            return None

    monkeypatch.setattr("app.integrations.hackerone.build_client", lambda **_kwargs: _Client())

    reports = await HackerOneClient(_settings()).list_reports()

    assert [report["id"] for report in reports] == ["101", "102"]
    assert calls[0][1]["params"] == [
        ("filter[program][]", "acme"),
        ("page[size]", "100"),
        ("page[number]", "1"),
    ]
    expected = base64.b64encode(b"analyst@example.com:secret").decode("ascii")
    assert calls[0][1]["headers"]["Authorization"] == f"Basic {expected}"
    assert calls[1][1]["params"] is None


@pytest.mark.asyncio
async def test_hackerone_rejects_reports_outside_selected_programs(monkeypatch) -> None:
    class _Client:
        async def get_json(self, *_args, **_kwargs):
            return {"data": [_report("101", program="other")], "links": {"next": None}}

        async def aclose(self):
            return None

    monkeypatch.setattr("app.integrations.hackerone.build_client", lambda **_kwargs: _Client())

    with pytest.raises(IntegrationError, match="outside the selected programs"):
        await HackerOneClient(_settings()).list_reports()


def test_hackerone_normalizes_scope_lifecycle_severity_and_cves() -> None:
    report = _report("101")
    report["attributes"].update(
        {
            "title": "CVE-2026-12345 in customer API",
            "state": "triaged",
            "created_at": "2026-09-01T12:00:00Z",
            "cve_ids": ["CVE-2026-12345"],
        }
    )
    normalized = normalize_hackerone_report(report)

    assert normalized.external_id == "101"
    assert normalized.resource == "https://api.example.com/"
    assert normalized.severity == "critical"
    assert normalized.status == "open"
    assert normalized.cve_ids == ["CVE-2026-12345"]
    assert normalized.evidence["program_handle"] == "acme"
    assert normalized.evidence["asset_type"] == "url"


def test_hackerone_is_a_persistable_continuous_agent_integration() -> None:
    from sqlalchemy import CheckConstraint

    from app.db.enums import AgentActionName, IntegrationKind
    from app.db.models.agent import AgentAction
    from app.db.models.integration import Integration
    from app.services.integration import CONTINUOUS_SYNC_KINDS

    assert IntegrationKind.HACKERONE in CONTINUOUS_SYNC_KINDS
    assert AgentActionName.SYNC_HACKERONE_REPORTS.value == "sync_hackerone_reports"
    integration_sql = next(
        str(item.sqltext)
        for item in Integration.__table__.constraints
        if isinstance(item, CheckConstraint) and item.name.endswith("valid_integration_kind")
    )
    action_sql = next(
        str(item.sqltext)
        for item in AgentAction.__table__.constraints
        if isinstance(item, CheckConstraint) and item.name.endswith("valid_agent_action")
    )
    assert "'hackerone'" in integration_sql
    assert "'sync_hackerone_reports'" in action_sql


def _report(report_id: str, *, program: str = "acme") -> dict[str, object]:
    return {
        "id": report_id,
        "type": "report",
        "attributes": {"title": f"Report {report_id}", "state": "new"},
        "relationships": {
            "program": {"data": {"id": "9", "type": "program", "attributes": {"handle": program}}},
            "structured_scope": {
                "data": {
                    "id": "88",
                    "type": "structured-scope",
                    "attributes": {"asset_type": "URL", "asset_identifier": "https://api.example.com"},
                }
            },
            "severity": {"data": {"id": "5", "type": "severity", "attributes": {"rating": "critical"}}},
        },
    }
