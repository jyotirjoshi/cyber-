"""Provider-neutral normalization for externally ingested security alerts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.base import utcnow
from app.db.enums import IntegrationKind, Permission
from app.db.models.external_alert import ExternalSecurityAlert
from app.integrations.github import GitHubClient
from app.services import audit as audit_service
from app.services.audit import AuditAction
from app.services.context import Principal

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


@dataclass(frozen=True, slots=True)
class GitHubSyncResult:
    """Safe summary of a GitHub ingestion run; it intentionally carries no alert content."""

    total: int


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


async def stage_github_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    feeds: list[tuple[str, list[dict[str, Any]]]],
) -> GitHubSyncResult:
    """Stage conflict-safe, tenant-isolated GitHub alert persistence.

    GitHub alert identifiers are only unique within a feed, so the normalizer includes
    the feed category in ``external_id``. PostgreSQL's unique index is the final
    deduplication authority, which makes repeated or concurrent syncs idempotent.
    """
    alerts = {
        normalized.external_id: normalized
        for category, feed_alerts in feeds
        for alert in feed_alerts
        for normalized in [normalize_github_alert(category, alert)]
    }
    if not alerts:
        return GitHubSyncResult(total=0)

    now = utcnow()
    values = [
        {
            "organization_id": organization_id,
            "integration_id": integration_id,
            "provider": "github",
            "external_id": alert.external_id,
            "category": alert.category,
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "resource": alert.resource,
            "source_url": alert.source_url,
            "cve_ids": alert.cve_ids,
            "evidence": alert.evidence,
            "raw_payload": alert.raw_payload,
            "first_seen_at": now,
            "last_seen_at": now,
        }
        for alert in alerts.values()
    ]
    statement = insert(ExternalSecurityAlert).values(values)
    statement = statement.on_conflict_do_update(
        constraint="unique_external_security_alert",
        set_={
            "integration_id": statement.excluded.integration_id,
            "category": statement.excluded.category,
            "title": statement.excluded.title,
            "severity": statement.excluded.severity,
            "status": statement.excluded.status,
            "resource": statement.excluded.resource,
            "source_url": statement.excluded.source_url,
            "cve_ids": statement.excluded.cve_ids,
            "evidence": statement.excluded.evidence,
            "raw_payload": statement.excluded.raw_payload,
            "last_seen_at": statement.excluded.last_seen_at,
        },
    )
    await session.execute(statement)
    return GitHubSyncResult(total=len(values))


async def sync_github_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Fetch the caller tenant's GitHub alerts and atomically stage them in its ledger."""
    principal.require(Permission.INTEGRATION_MANAGE)
    # Local import prevents the integration service's provider-client imports from
    # becoming a package-level circular dependency.
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.GITHUB
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.GITHUB, settings=settings, require=True
    )
    feeds = await GitHubClient(scoped, redis).list_security_alerts()
    result = await stage_github_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=integration.id if integration else None,
        feeds=[(feed.kind, feed.alerts) for feed in feeds],
    )
    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_SYNC,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id if integration else None,
        detail={"provider": "github", "alerts_staged": result.total},
    )
    return result


__all__ = [
    "GitHubSyncResult",
    "NormalizedExternalAlert",
    "normalize_github_alert",
    "stage_github_alerts",
    "sync_github_alerts",
]
