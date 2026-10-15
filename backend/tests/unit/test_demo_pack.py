"""The downloadable demo pack must stay compatible with real ingestion parsers."""

from __future__ import annotations

from pathlib import Path

from app.services.file_intake import parse_scan_export


DEMO_FIXTURES = Path(__file__).resolve().parents[3] / "demo" / "fixtures"


def _read(name: str) -> bytes:
    return (DEMO_FIXTURES / name).read_bytes()


def test_demo_sarif_exercises_code_findings_and_cve_identity() -> None:
    alerts = parse_scan_export(
        _read("demo-shop-semgrep.sarif"),
        format_name="sarif",
        provider="semgrep_demo",
        asset_type="repo",
        asset_value="cynux/demo-shop",
    )

    assert len(alerts) == 2
    assert {alert.severity for alert in alerts} == {"critical", "high"}
    assert any(alert.cve_ids == ["CVE-2021-44228"] for alert in alerts)
    assert all(alert.evidence["asset_value"] == "cynux/demo-shop" for alert in alerts)


def test_demo_cyclonedx_exercises_dependency_finding_for_same_cve() -> None:
    alerts = parse_scan_export(
        _read("demo-shop-sbom.cdx.json"),
        format_name="cyclonedx",
        provider="syft_demo",
        asset_type="repo",
        asset_value="cynux/demo-shop",
    )

    assert len(alerts) == 1
    assert alerts[0].cve_ids == ["CVE-2021-44228"]
    assert alerts[0].evidence["package"] == "log4j-core"
    assert alerts[0].evidence["version"] == "2.14.1"


def test_demo_wazuh_export_works_through_mapped_json_ingestion() -> None:
    alerts = parse_scan_export(
        _read("demo-wazuh-alerts.json"),
        format_name="generic_json",
        provider="wazuh_demo",
        asset_type="domain",
        asset_value="demo-shop.internal",
        field_mapping={
            "id": "id",
            "title": "rule.description",
            "severity": "risk",
            "status": "status",
            "cve": "rule.cve",
            "location": "location",
        },
    )

    assert len(alerts) == 2
    assert {alert.severity for alert in alerts} == {"critical", "high"}
    assert {alert.status for alert in alerts} == {"open", "resolved"}
    assert all(alert.evidence["asset_value"] == "demo-shop.internal" for alert in alerts)
