"""Google Security Command Center normalization contracts."""

from __future__ import annotations

from app.core.config import Settings
from app.integrations.gcp_scc import GcpSccClient
from app.services.external_alert import normalize_gcp_scc_finding


def test_gcp_scc_accepts_documented_regional_location() -> None:
    settings = Settings(
        gcp_scc={
            "project_id": "acme-prod",
            "location": "me-central2",
            "service_account_json": "{}",
        }
    )

    assert GcpSccClient(settings)._scope()[:2] == ("acme-prod", "me-central2")


def test_gcp_scc_normalizes_finding_and_resource() -> None:
    alert = normalize_gcp_scc_finding(
        {
            "finding": {
                "name": "projects/acme-prod/sources/123/locations/global/findings/f-1",
                "state": "ACTIVE",
                "category": "PUBLIC_BUCKET_CVE-2026-12345",
                "severity": "CRITICAL",
                "resourceName": "//storage.googleapis.com/acme-public",
                "externalUri": "https://console.cloud.google.com/security/command-center/findingsv2",
                "sourceProperties": {"Explanation": "Publicly reachable bucket"},
            },
            "resource": {
                "name": "//storage.googleapis.com/acme-public",
                "projectName": "//cloudresourcemanager.googleapis.com/projects/acme-prod",
                "type": "google.cloud.storage.Bucket",
                "displayName": "acme-public",
            },
        },
        project_id="acme-prod",
    )

    assert alert.external_id == "f-1"
    assert alert.resource == "//storage.googleapis.com/acme-public"
    assert alert.severity == "critical"
    assert alert.status == "open"
    assert alert.cve_ids == ["CVE-2026-12345"]
    assert alert.evidence["provider"] == "gcp_scc"
    assert alert.evidence["project_id"] == "acme-prod"
    assert alert.evidence["asset_type"] == "cloud_resource"
