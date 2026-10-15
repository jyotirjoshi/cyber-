"""Burp Suite DAST GraphQL ingestion contracts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr


@pytest.mark.asyncio
async def test_burp_client_reads_complete_latest_scan_pages() -> None:
    from app.integrations.burp_dast import BurpDastClient

    settings = SimpleNamespace(
        burp_dast=SimpleNamespace(
            configured=True,
            base_url="https://burp.example",
            api_key=SecretStr("burp-key"),
            site_ids=["28"],
        )
    )
    client = BurpDastClient(settings)
    requests: list[dict[str, object]] = []

    class Http:
        async def post_json(self, path, **kwargs):
            requests.append(kwargs["json"])
            variables = kwargs["json"].get("variables", {})
            if "siteId" in variables:
                return {"data": {"scans": [{"id": "21029", "status": "succeeded", "site_name": "store"}]}}
            start = variables["start"]
            issues = [
                {
                    "serial_number": str(start + 1),
                    "severity": "high",
                    "confidence": "certain",
                    "path": "/checkout",
                    "origin": "https://store.example",
                    "description_html": "SQL injection",
                    "remediation_html": "Use parameters",
                    "issue_type": {"type_index": "1049088", "name": "SQL injection"},
                }
            ] if start == 0 else []
            return {"data": {"scan": {"issues": issues}}}

    client._client = Http()
    rows = await client.list_findings()

    assert len(rows) == 1
    assert rows[0]["site_id"] == "28"
    assert rows[0]["scan"]["id"] == "21029"
    assert rows[0]["issue"]["serial_number"] == "1"
    assert [request["variables"] for request in requests] == [
        {"siteId": "28"},
        {"scanId": "21029", "start": 0, "count": 500},
    ]


def test_burp_issue_normalizes_to_persistent_web_exposure() -> None:
    from app.services.external_alert import normalize_burp_dast_issue

    alert = normalize_burp_dast_issue(
        {
            "site_id": "28",
            "scan": {"id": "21029", "status": "succeeded", "site_name": "store"},
            "issue": {
                "serial_number": "6150599811840047104",
                "severity": "high",
                "confidence": "certain",
                "path": "/checkout",
                "origin": "https://store.example",
                "description_html": "CVE-2026-12345 is exploitable.",
                "remediation_html": "Use a patched component.",
                "issue_type": {"type_index": "1049088", "name": "SQL injection"},
            },
        }
    )

    assert alert.title == "SQL injection"
    assert alert.resource == "https://store.example/checkout"
    assert alert.severity == "high"
    assert alert.status == "open"
    assert alert.cve_ids == ["CVE-2026-12345"]
    assert alert.evidence["provider"] == "burp_dast"
    assert alert.evidence["site_id"] == "28"
    assert alert.evidence["scan_id"] == "21029"
    assert alert.evidence["asset_type"] == "url"


def test_agent_sync_action_is_persistable_for_every_direct_connector() -> None:
    from sqlalchemy import CheckConstraint

    from app.db.enums import AgentActionName
    from app.db.models.agent import AgentAction

    assert AgentActionName.SYNC_BURP_DAST_FINDINGS.value == "sync_burp_dast_findings"
    action_check = next(
        constraint
        for constraint in AgentAction.__table__.constraints
        if isinstance(constraint, CheckConstraint) and constraint.name.endswith("valid_agent_action")
    )
    sql = str(action_check.sqltext)
    for action in (
        "sync_crowdstrike_vulnerabilities",
        "sync_prisma_cloud_alerts",
        "sync_aws_security_hub_findings",
        "sync_azure_defender_alerts",
        "sync_gcp_scc_findings",
        "sync_burp_dast_findings",
    ):
        assert f"'{action}'" in sql
