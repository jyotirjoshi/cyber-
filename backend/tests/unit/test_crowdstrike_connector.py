"""CrowdStrike Spotlight normalization contracts."""

from __future__ import annotations


def test_crowdstrike_spotlight_normalizes_host_cve_and_risk_signals() -> None:
    from app.services.external_alert import normalize_crowdstrike_vulnerability

    alert = normalize_crowdstrike_vulnerability(
        {
            "id": "vuln-1",
            "status": "open",
            "vulnerability_id": "CVE-2026-12345",
            "risk_score": 92,
            "cve": {
                "id": "CVE-2026-12345",
                "severity": "CRITICAL",
                "base_score": 9.8,
                "is_cisa_kev": True,
                "description": "Remote code execution",
            },
            "host_info": {
                "aid": "agent-1",
                "hostname": "prod-api-1",
                "local_ip": "10.0.0.7",
                "internet_exposure": "YES",
            },
            "remediation": {"ids": ["rem-1"]},
        }
    )

    assert alert.external_id == "vuln-1"
    assert alert.resource == "prod-api-1"
    assert alert.severity == "critical"
    assert alert.cve_ids == ["CVE-2026-12345"]
    assert alert.evidence["asset_type"] == "host"
    assert alert.evidence["asset_value"] == "prod-api-1"
    assert alert.evidence["internet_exposed"] is True
    assert alert.evidence["in_kev"] is True
    assert alert.evidence["risk_score"] == 92.0

