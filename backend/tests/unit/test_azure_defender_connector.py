"""Microsoft Defender for Cloud connector contracts."""

from __future__ import annotations

from app.services.external_alert import normalize_azure_defender_alert


def test_defender_alert_normalizes_cloud_resource_and_cves() -> None:
    alert = normalize_azure_defender_alert(
        {
            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Security/alerts/a-1",
            "name": "a-1",
            "properties": {
                "alertDisplayName": "Vulnerable internet-facing virtual machine CVE-2026-12345",
                "description": "A vulnerable package is reachable.",
                "severity": "High",
                "status": "Active",
                "productName": "Microsoft Defender for Servers",
                "resourceIdentifiers": [
                    {
                        "type": "AzureResource",
                        "azureResourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/api-1",
                    }
                ],
                "remediationSteps": ["Upgrade the affected package."],
                "entities": [{"type": "ip", "address": "8.8.8.8"}],
            },
        },
        subscription_id="11111111-1111-1111-1111-111111111111",
    )

    assert alert.external_id == "a-1"
    assert alert.severity == "high"
    assert alert.status == "open"
    assert alert.cve_ids == ["CVE-2026-12345"]
    assert alert.evidence["provider"] == "azure_defender"
    assert alert.evidence["asset_type"] == "cloud_resource"
    assert alert.evidence["internet_exposed"] is True
