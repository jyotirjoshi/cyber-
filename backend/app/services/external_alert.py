"""Provider-neutral normalization for externally ingested security alerts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_STATUS = {
    "open": "open",
    "dismissed": "dismissed",
    "resolved": "resolved",
    "fixed": "fixed",
}


@dataclass(frozen=True, slots=True)
class NormalizedExternalAlert:
    external_id: str
    category: str
    title: str
    severity: str
    status: str
    resource: str | None
    source_url: str | None
    cve_ids: list[str]
    evidence: dict[str, Any]
    raw_payload: dict[str, Any]


def _severity(value: object) -> str:
    candidate = str(value or "").lower()
    return candidate if candidate in _SEVERITIES else "info"


def _cves(alert: dict[str, Any]) -> list[str]:
    advisory = alert.get("security_advisory") or {}
    identifiers = advisory.get("identifiers") if isinstance(advisory, dict) else []
    return [
        str(item["value"]).upper()
        for item in identifiers or []
        if isinstance(item, dict)
        and str(item.get("type") or "").upper() == "CVE"
        and item.get("value")
    ]


def normalize_github_alert(category: str, alert: dict[str, Any]) -> NormalizedExternalAlert:
    """Normalize one GitHub security alert without inventing missing risk data."""
    advisory = alert.get("security_advisory") or {}
    rule = alert.get("rule") or {}
    repository = alert.get("repository") or {}
    number = str(alert.get("number") or alert.get("id") or "")
    if not number:
        raise ValueError("GitHub security alert has no stable identifier")
    title = (
        advisory.get("summary")
        if isinstance(advisory, dict)
        else None
    ) or (rule.get("description") if isinstance(rule, dict) else None) or alert.get(
        "secret_type_display_name"
    ) or f"GitHub {category.replace('_', ' ')} alert"
    severity = _severity(
        (advisory.get("severity") if isinstance(advisory, dict) else None)
        or (rule.get("security_severity_level") if isinstance(rule, dict) else None)
    )
    resource = repository.get("full_name") if isinstance(repository, dict) else None
    status = _STATUS.get(str(alert.get("state") or "").lower(), "open")
    return NormalizedExternalAlert(
        external_id=f"{category}:{number}",
        category=category,
        title=str(title)[:1000],
        severity=severity,
        status=status,
        resource=str(resource)[:1000] if resource else None,
        source_url=str(alert.get("html_url"))[:2000] if alert.get("html_url") else None,
        cve_ids=_cves(alert),
        evidence={"provider": "github", "category": category, "alert_number": number},
        raw_payload=alert,
    )


__all__ = ["NormalizedExternalAlert", "normalize_github_alert"]
