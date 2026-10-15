"""Amazon Inspector direct connector and canonical normalization contracts."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.aws_inspector import AwsInspectorClient
from app.services.external_alert import normalize_aws_inspector_finding


def _settings() -> Settings:
    return Settings(
        aws_inspector={
            "region": "us-east-1",
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret",
            "account_ids": ["123456789012"],
        }
    )


@pytest.mark.asyncio
async def test_inspector_reads_complete_active_account_scoped_snapshot(monkeypatch) -> None:
    service = MagicMock()
    service.list_findings.side_effect = [
        {
            "findings": [
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/" + "a" * 32,
                    "awsAccountId": "123456789012",
                }
            ],
            "nextToken": "next",
        },
        {
            "findings": [
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/" + "b" * 32,
                    "awsAccountId": "123456789012",
                }
            ]
        },
    ]
    monkeypatch.setattr("app.integrations.aws_inspector.boto3.client", lambda *_a, **_kw: service)

    findings = await AwsInspectorClient(_settings()).list_findings()

    assert len(findings) == 2
    first = service.list_findings.call_args_list[0].kwargs
    assert first["filterCriteria"]["findingStatus"] == [
        {"comparison": "EQUALS", "value": "ACTIVE"}
    ]
    assert first["filterCriteria"]["awsAccountId"] == [
        {"comparison": "EQUALS", "value": "123456789012"}
    ]
    assert service.list_findings.call_args_list[1].kwargs["nextToken"] == "next"


@pytest.mark.asyncio
async def test_inspector_rejects_findings_outside_selected_accounts(monkeypatch) -> None:
    service = MagicMock()
    service.list_findings.return_value = {
        "findings": [
            {
                "findingArn": "arn:aws:inspector2:us-east-1:999999999999:finding/" + "a" * 32,
                "awsAccountId": "999999999999",
            }
        ]
    }
    monkeypatch.setattr("app.integrations.aws_inspector.boto3.client", lambda *_a, **_kw: service)

    with pytest.raises(IntegrationError, match="outside the selected accounts"):
        await AwsInspectorClient(_settings()).list_findings()


def test_inspector_normalizes_vulnerability_and_resource_evidence() -> None:
    normalized = normalize_aws_inspector_finding(
        {
            "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/" + "a" * 32,
            "awsAccountId": "123456789012",
            "title": "CVE-2026-12345 in openssl",
            "description": "A vulnerable package is installed.",
            "severity": "CRITICAL",
            "status": "ACTIVE",
            "type": "PACKAGE_VULNERABILITY",
            "inspectorScore": 9.8,
            "exploitAvailable": "YES",
            "fixAvailable": "YES",
            "resources": [
                {
                    "id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123",
                    "type": "AWS_EC2_INSTANCE",
                    "region": "us-east-1",
                }
            ],
            "packageVulnerabilityDetails": {
                "vulnerabilityId": "CVE-2026-12345",
                "referenceUrls": ["https://example.invalid/CVE-2026-12345"],
            },
            "remediation": {"recommendation": {"text": "Upgrade OpenSSL."}},
        }
    )

    assert normalized.resource.endswith("instance/i-0123")
    assert normalized.cve_ids == ["CVE-2026-12345"]
    assert normalized.severity == "critical"
    assert normalized.evidence["aws_account_id"] == "123456789012"
    assert normalized.evidence["exploit_available"] is True
    assert normalized.evidence["fix_available"] is True
    assert normalized.evidence["risk_score"] == 9.8


def test_inspector_is_a_persistable_continuous_agent_integration() -> None:
    from sqlalchemy import CheckConstraint

    from app.db.enums import AgentActionName, IntegrationKind
    from app.db.models.agent import AgentAction
    from app.db.models.integration import Integration
    from app.services.integration import CONTINUOUS_SYNC_KINDS

    assert IntegrationKind.AWS_INSPECTOR in CONTINUOUS_SYNC_KINDS
    assert AgentActionName.SYNC_AWS_INSPECTOR_FINDINGS.value == "sync_aws_inspector_findings"
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
    assert "'aws_inspector'" in integration_sql
    assert "'sync_aws_inspector_findings'" in action_sql
