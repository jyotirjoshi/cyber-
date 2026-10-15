"""AWS Security Hub connector and ASFF normalization contracts."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core.config import Settings
from app.integrations.aws_security_hub import AwsSecurityHubClient
from app.services.external_alert import normalize_aws_security_hub_finding


@pytest.mark.asyncio
async def test_security_hub_reads_complete_scoped_active_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    service = MagicMock()
    service.get_findings.side_effect = [
        {"Findings": [{"Id": "finding-1", "AwsAccountId": "123456789012"}], "NextToken": "next"},
        {"Findings": [{"Id": "finding-2", "AwsAccountId": "123456789012"}]},
    ]
    monkeypatch.setattr("app.integrations.aws_security_hub.boto3.client", lambda *_a, **_kw: service)
    settings = Settings(
        aws_security_hub={
            "region": "us-east-1",
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret",
            "account_ids": ["123456789012"],
        }
    )

    client = AwsSecurityHubClient(settings)
    findings = await client.list_findings()

    assert [item["Id"] for item in findings] == ["finding-1", "finding-2"]
    first = service.get_findings.call_args_list[0].kwargs
    assert first["Filters"]["RecordState"] == [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
    assert first["Filters"]["WorkflowStatus"] == [
        {"Value": "NEW", "Comparison": "EQUALS"},
        {"Value": "NOTIFIED", "Comparison": "EQUALS"},
    ]
    assert first["Filters"]["AwsAccountId"] == [
        {"Value": "123456789012", "Comparison": "EQUALS"}
    ]
    assert service.get_findings.call_args_list[1].kwargs["NextToken"] == "next"


def test_security_hub_normalizes_asff_asset_and_vulnerability() -> None:
    alert = normalize_aws_security_hub_finding(
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/example/finding/1",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Public workload contains vulnerable package",
            "Description": "Upgrade the affected package.",
            "Severity": {"Label": "CRITICAL", "Normalized": 95},
            "ProductName": "Inspector",
            "CompanyName": "AWS",
            "Resources": [
                {
                    "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123",
                    "Type": "AwsEc2Instance",
                    "Region": "us-east-1",
                    "Details": {"AwsEc2Instance": {"IpV4Addresses": ["8.8.8.8"]}},
                }
            ],
            "Vulnerabilities": [{"Id": "CVE-2026-12345", "FixAvailable": "YES"}],
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
            "FirstObservedAt": "2026-10-01T00:00:00Z",
            "UpdatedAt": "2026-10-12T00:00:00Z",
            "Remediation": {"Recommendation": {"Text": "Upgrade now"}},
        }
    )

    assert alert.external_id.endswith("finding/1")
    assert alert.resource.endswith("instance/i-0123")
    assert alert.severity == "critical"
    assert alert.cve_ids == ["CVE-2026-12345"]
    assert alert.evidence["provider"] == "aws_security_hub"
    assert alert.evidence["asset_type"] == "cloud_resource"
    assert alert.evidence["internet_exposed"] is True
    assert alert.evidence["risk_score"] == 95.0
