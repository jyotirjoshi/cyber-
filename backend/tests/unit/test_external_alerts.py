"""Normalized external-alert ledger contracts."""

from __future__ import annotations

from app.db.models.external_alert import ExternalSecurityAlert
from app.services.external_alert import normalize_github_alert


def test_external_alerts_deduplicate_per_tenant_and_provider_identity() -> None:
    """Removing provider identity from this uniqueness key merges unrelated alerts."""
    constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in ExternalSecurityAlert.__table__.constraints
        if constraint.name
    }

    assert constraints["unique_external_security_alert"] == (
        "organization_id",
        "provider",
        "external_id",
    )
    assert ExternalSecurityAlert.__table__.c.raw_payload.nullable is False
    assert ExternalSecurityAlert.__table__.c.evidence.default.arg(None) == {}


def test_github_dependabot_alert_is_normalized_without_discarding_cve_or_repository() -> None:
    """Dropping CVEs or the repository makes cross-source correlation impossible."""
    normalized = normalize_github_alert(
        "dependabot",
        {
            "number": 42,
            "state": "open",
            "html_url": "https://github.com/acme/payments/security/dependabot/42",
            "repository": {"full_name": "acme/payments"},
            "security_advisory": {
                "summary": "Django denial of service",
                "severity": "high",
                "identifiers": [{"type": "CVE", "value": "CVE-2026-1234"}],
            },
        },
    )

    assert normalized.external_id == "dependabot:42"
    assert normalized.title == "Django denial of service"
    assert normalized.severity == "high"
    assert normalized.status == "open"
    assert normalized.resource == "acme/payments"
    assert normalized.cve_ids == ["CVE-2026-1234"]
