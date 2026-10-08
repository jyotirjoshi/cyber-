"""Provider-neutral normalization for externally ingested security alerts."""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    IntegrationNotConfiguredError,
    InvalidConfigurationError,
    TenantIsolationError,
)
from app.db.base import utcnow
from app.db.enums import IntegrationKind, Permission
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding
from app.db.repository import TenantRepository, tenant_select
from app.integrations.github import GitHubClient
from app.integrations.gitlab import GitLabClient
from app.integrations.snyk import SnykClient
from app.integrations.sonarqube import SonarQubeClient
from app.integrations.tenable import TenableClient
from app.integrations.wazuh import WazuhIndexerClient
from app.schemas.common import PaginationParams
from app.services import audit as audit_service
from app.services.audit import AuditAction
from app.services.context import Principal

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_STATUS = {
    "open": "open",
    "dismissed": "dismissed",
    "auto_dismissed": "dismissed",
    "resolved": "resolved",
    "closed": "resolved",
    "fixed": "fixed",
}


async def get_external_alert(
    session: AsyncSession,
    principal: Principal,
    alert_id: uuid.UUID,
) -> ExternalSecurityAlert:
    """Return one alert only within the caller's organization."""
    principal.require(Permission.FINDING_READ)
    return await TenantRepository(
        session, ExternalSecurityAlert, principal.organization_id
    ).get_or_404(alert_id)


async def related_findings_for_alert(
    session: AsyncSession,
    principal: Principal,
    alert_id: uuid.UUID,
) -> list[Finding]:
    """Return bounded same-CVE candidates, never assert they are duplicate exposures."""
    alert = await get_external_alert(session, principal, alert_id)
    cves = list(dict.fromkeys(cve.strip().upper() for cve in alert.cve_ids if cve.strip()))[:20]
    if not cves:
        return []
    stmt = (
        tenant_select(Finding, principal.organization_id)
        .where(
            or_(*(Finding.cve_ids.contains([cve]) for cve in cves)),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
        )
        .order_by(Finding.risk_score.desc().nullslast(), Finding.id)
        .limit(20)
    )
    return list((await session.execute(stmt)).scalars().all())


async def related_external_alerts_for_alert(
    session: AsyncSession,
    principal: Principal,
    alert_id: uuid.UUID,
) -> list[ExternalSecurityAlert]:
    """Suggest cross-provider candidates only with exact repo and shared CVE evidence.

    This is a read-only lead for an analyst, not a duplicate declaration. SonarQube
    project keys and Wazuh agent names are not assumed to identify repositories.
    """
    alert = await get_external_alert(session, principal, alert_id)
    if alert.provider == "github":
        repository = (alert.resource or "").strip()
    elif alert.provider == "gitlab":
        repository = str((alert.evidence or {}).get("project") or "").strip()
    else:
        return []
    cves = list(dict.fromkeys(cve.strip().upper() for cve in alert.cve_ids if cve.strip()))[:20]
    if not repository or "/" not in repository or not cves:
        return []
    candidate = ExternalSecurityAlert
    statement = (
        tenant_select(candidate, principal.organization_id)
        .where(
            candidate.id != alert.id,
            candidate.provider != alert.provider,
            or_(
                and_(candidate.provider == "github", candidate.resource == repository),
                and_(
                    candidate.provider == "gitlab",
                    candidate.evidence["project"].astext == repository,
                ),
            ),
            or_(*(candidate.cve_ids.contains([cve]) for cve in cves)),
        )
        .order_by(candidate.last_seen_at.desc().nullslast(), candidate.id)
        .limit(20)
    )
    return list((await session.execute(statement)).scalars().all())


async def triage_external_alert(
    session: AsyncSession,
    principal: Principal,
    alert_id: uuid.UUID,
    *,
    status: str,
    note: str | None,
    expected_version: int,
) -> ExternalSecurityAlert:
    """Record a local analyst decision without mutating the provider's status."""
    principal.require(Permission.FINDING_VALIDATE)
    if status not in {"new", "investigating", "risk_accepted", "false_positive", "closed"}:
        raise InvalidConfigurationError("invalid external alert triage status")
    clean_note = note.strip() if note else None
    if status in {"risk_accepted", "false_positive", "closed"} and not clean_note:
        raise InvalidConfigurationError(
            "external alert triage rationale missing",
            user_message="A rationale is required for this triage decision.",
        )
    row = (
        await session.execute(
            tenant_select(ExternalSecurityAlert, principal.organization_id)
            .where(ExternalSecurityAlert.id == alert_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise TenantIsolationError("external alert not found")
    if row.triage_version != expected_version:
        raise ConflictError(
            "external alert triage version changed",
            user_message="This alert was updated by another user. Refresh and retry.",
        )

    previous = row.triage_status
    row.triage_status = status
    row.triage_note = clean_note
    row.triage_version += 1
    row.triaged_at = utcnow()
    row.triaged_by_user_id = principal.user_id
    await audit_service.record(
        session,
        action=AuditAction.EXTERNAL_ALERT_TRIAGE,
        principal=principal,
        resource_type="external_security_alert",
        resource_id=row.id,
        detail={"from": previous, "to": status, "version": row.triage_version},
    )
    return row


async def set_github_alert_state(
    session: AsyncSession,
    principal: Principal,
    alert_id: uuid.UUID,
    *,
    decision: str,
    reason: str | None,
    comment: str | None,
    settings: Settings,
    redis: Any | None = None,
) -> ExternalSecurityAlert:
    """Write one tenant-owned GitHub alert decision and retain provider-confirmed status."""
    principal.require(Permission.INTEGRATION_MANAGE, Permission.FINDING_VALIDATE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.GITHUB
    )
    credential_names = (
        {credential.name for credential in integration.credentials} if integration else set()
    )
    if (
        integration is None
        or not integration.is_usable
        or not integration.config.get("organization")
        or "api_token" not in credential_names
    ):
        raise IntegrationNotConfiguredError(
            "GitHub",
            hint="Save the organization and API token in this organization's connection first.",
        )
    row = (
        await session.execute(
            tenant_select(ExternalSecurityAlert, principal.organization_id)
            .where(ExternalSecurityAlert.id == alert_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.provider != "github":
        raise TenantIsolationError("GitHub alert not found in this organization")
    if decision == "dismiss" and row.status != "open":
        raise ConflictError(
            "GitHub alert is not open",
            user_message="Refresh this alert before changing its source status.",
        )
    if decision == "reopen" and row.status not in {"dismissed", "resolved"}:
        raise ConflictError(
            "GitHub alert is not dismissed", user_message="Refresh this alert before reopening it."
        )
    evidence = row.evidence or {}
    number_text = str(evidence.get("alert_number") or "")
    if (
        not number_text.isdecimal()
        or row.external_id != f"{row.category}:{row.resource}:{number_text}"
    ):
        raise ConflictError(
            "GitHub alert identity is inconsistent",
            user_message="This alert needs a fresh GitHub sync before it can be changed.",
        )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.GITHUB, settings=settings, require=True
    )
    client = GitHubClient(scoped, redis)
    try:
        provider_state = await client.set_alert_state(
            row.category,
            row.resource or "",
            int(number_text),
            decision=decision,
            reason=reason,
            comment=comment,
        )
    finally:
        await client.aclose()
    previous = row.status
    row.status = provider_state
    row.raw_payload = {**(row.raw_payload or {}), "state": provider_state}
    row.last_seen_at = utcnow()
    row.missing_sync_count = 0
    await audit_service.record(
        session,
        action=AuditAction.EXTERNAL_ALERT_SOURCE_UPDATE,
        principal=principal,
        resource_type="external_security_alert",
        resource_id=row.id,
        detail={
            "provider": "github",
            "category": row.category,
            "decision": decision,
            "reason": reason,
            "from": previous,
            "to": provider_state,
        },
    )
    return row


async def list_external_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    provider: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    triage_status: str | None = None,
    q: str | None = None,
    pagination: PaginationParams | None = None,
) -> tuple[list[ExternalSecurityAlert], int]:
    """List provider alerts without crossing tenant boundaries or loading unbounded pages."""
    principal.require(Permission.FINDING_READ)
    page = pagination or PaginationParams()
    conditions = []
    if provider:
        conditions.append(ExternalSecurityAlert.provider == provider)
    if severity:
        conditions.append(ExternalSecurityAlert.severity == severity)
    if status:
        conditions.append(ExternalSecurityAlert.status == status)
    if triage_status:
        conditions.append(ExternalSecurityAlert.triage_status == triage_status)
    if q and q.strip():
        escaped = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        conditions.append(
            or_(
                ExternalSecurityAlert.title.ilike(pattern, escape="\\"),
                ExternalSecurityAlert.resource.ilike(pattern, escape="\\"),
            )
        )

    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(ExternalSecurityAlert)
                .where(
                    ExternalSecurityAlert.organization_id == principal.organization_id, *conditions
                )
            )
        ).scalar_one()
    )
    stmt = (
        tenant_select(ExternalSecurityAlert, principal.organization_id)
        .where(*conditions)
        .order_by(
            ExternalSecurityAlert.last_seen_at.desc().nullslast(),
            ExternalSecurityAlert.id,
        )
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return list(rows), total


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
    resource = (
        str(repository.get("full_name") or "").strip() if isinstance(repository, dict) else ""
    )
    if not resource or "/" not in resource:
        raise ValueError("GitHub security alert has no repository identity")
    external_id = f"{category}:{resource}:{number}"
    if len(external_id) > 300:
        raise ValueError("GitHub security alert identity exceeds storage limit")
    title = (
        (advisory.get("summary") if isinstance(advisory, dict) else None)
        or (rule.get("description") if isinstance(rule, dict) else None)
        or alert.get("secret_type_display_name")
        or f"GitHub {category.replace('_', ' ')} alert"
    )
    severity = _severity(
        (advisory.get("severity") if isinstance(advisory, dict) else None)
        or (rule.get("security_severity_level") if isinstance(rule, dict) else None)
    )
    status = _STATUS.get(str(alert.get("state") or "").lower(), "open")
    return NormalizedExternalAlert(
        external_id=external_id,
        category=category,
        title=str(title)[:1000],
        severity=severity,
        status=status,
        resource=resource,
        source_url=str(alert.get("html_url"))[:2000] if alert.get("html_url") else None,
        cve_ids=_cves(alert),
        evidence={"provider": "github", "category": category, "alert_number": number},
        raw_payload=alert,
    )


def normalize_gitlab_alert(project: str, alert: dict[str, Any]) -> NormalizedExternalAlert:
    """Normalize one GitLab security-report finding without losing scan context.

    GitLab returns a stable finding UUID for each project pipeline finding.  It is not
    globally unique across GitLab projects, so the project is part of the external identity.
    The REST endpoint can return SAST, DAST, dependency and container findings through the
    same shape; ``report_type`` stays as the category so downstream correlation does not
    need provider-specific table branches.
    """
    finding_id = str(alert.get("uuid") or alert.get("id") or "").strip()
    if not finding_id:
        raise ValueError("GitLab security finding has no stable identifier")

    project_data = alert.get("project")
    project_path = (
        str(project_data.get("full_path") or "").strip() if isinstance(project_data, dict) else ""
    ) or project.strip()
    if not project_path:
        raise ValueError("GitLab security finding has no project identity")

    location = alert.get("location")
    location_data = location if isinstance(location, dict) else {}
    location_file = str(location_data.get("file") or "").strip()
    resource = f"{project_path}:{location_file}" if location_file else project_path
    category = str(alert.get("report_type") or "security_finding").strip().lower()
    title = str(alert.get("name") or alert.get("title") or "GitLab security finding").strip()
    raw_state = str(alert.get("state") or "").strip().lower()
    status = {
        "detected": "open",
        "confirmed": "open",
        "opened": "open",
        "dismissed": "dismissed",
        "resolved": "resolved",
        "closed": "resolved",
    }.get(raw_state, "open")
    identifiers = alert.get("identifiers")
    cve_ids = [
        str(item.get("external_id") or item.get("value")).upper()
        for item in identifiers or []
        if isinstance(item, dict)
        and str(item.get("external_type") or item.get("type") or "").lower() == "cve"
        and (item.get("external_id") or item.get("value"))
    ]

    return NormalizedExternalAlert(
        external_id=f"{project_path}:{finding_id}",
        category=category[:80],
        title=title[:1000],
        severity=_severity(alert.get("severity")),
        status=status,
        resource=resource[:1000],
        source_url=str(alert.get("web_url"))[:2000] if alert.get("web_url") else None,
        cve_ids=list(dict.fromkeys(cve_ids)),
        evidence={
            "provider": "gitlab",
            "project": project_path,
            "report_type": category,
            "finding_id": finding_id,
            "location": {
                key: location_data[key]
                for key in ("file", "start_line", "end_line")
                if location_data.get(key) is not None
            },
        },
        raw_payload=alert,
    )


def normalize_wazuh_alert(hit: dict[str, Any]) -> NormalizedExternalAlert:
    """Normalize an immutable Wazuh Indexer alert hit into Cynux's shared ledger."""
    external_id = str(hit.get("_id") or "").strip()
    source = hit.get("_source")
    if not external_id or not isinstance(source, dict):
        raise ValueError("Wazuh Indexer hit has no stable identifier or source document")

    rule = source.get("rule")
    rule_data = rule if isinstance(rule, dict) else {}
    agent = source.get("agent")
    agent_data = agent if isinstance(agent, dict) else {}
    groups = rule_data.get("groups")
    group_values = [str(group).strip() for group in groups or [] if str(group).strip()]
    category = group_values[0].lower() if group_values else "wazuh_rule"
    level = _integer(rule_data.get("level"))
    severity = (
        "critical"
        if level >= 12
        else "high"
        if level >= 8
        else "medium"
        if level >= 5
        else "low"
        if level >= 3
        else "info"
    )

    agent_name = str(agent_data.get("name") or "").strip()
    agent_id = str(agent_data.get("id") or "").strip()
    resource = (
        f"{agent_name} ({agent_id})" if agent_name and agent_id else agent_name or agent_id or None
    )
    description = str(rule_data.get("description") or "Wazuh security alert").strip()

    return NormalizedExternalAlert(
        external_id=external_id,
        category=category[:80],
        title=description[:1000],
        severity=severity,
        status="open",
        resource=resource[:1000] if resource else None,
        source_url=None,
        cve_ids=[],
        evidence={
            "provider": "wazuh",
            "rule_id": str(rule_data.get("id") or "") or None,
            "rule_level": level,
            "groups": group_values[:20],
            "agent_id": agent_id or None,
            "timestamp": source.get("@timestamp"),
        },
        raw_payload=hit,
    )


def normalize_sonarqube_issue(
    base_url: str, project: str, issue: dict[str, Any]
) -> NormalizedExternalAlert:
    """Keep SonarQube's stable issue identity and code location without inventing CVEs."""
    key = str(issue.get("key") or "").strip()
    if not key:
        raise ValueError("SonarQube issue has no stable key")
    issue_project = str(issue.get("project") or project).strip()
    if issue_project != project:
        raise ValueError("SonarQube issue project does not match the requested scope")
    severity_map = {
        "BLOCKER": "critical",
        "CRITICAL": "high",
        "HIGH": "high",
        "MAJOR": "medium",
        "MEDIUM": "medium",
        "MINOR": "low",
        "LOW": "low",
        "INFO": "info",
    }
    impacts = issue.get("impacts")
    security_impacts = (
        [
            impact
            for impact in impacts
            if isinstance(impact, dict) and impact.get("softwareQuality") == "SECURITY"
        ]
        if isinstance(impacts, list)
        else []
    )
    severity_source = (
        security_impacts[0].get("severity") if security_impacts else issue.get("severity")
    )
    severity = severity_map.get(str(severity_source or "").upper(), "info")
    status = {
        "RESOLVED": "resolved",
        "CLOSED": "resolved",
        "FIXED": "resolved",
        "FALSE-POSITIVE": "dismissed",
        "FALSE_POSITIVE": "dismissed",
    }.get(str(issue.get("issueStatus") or issue.get("status") or "").upper(), "open")
    component = str(issue.get("component") or project).strip()
    line = issue.get("line")
    resource = f"{component}:{line}" if isinstance(line, int) and line > 0 else component
    source_url = (
        f"{base_url.rstrip('/')}/project/issues?{urlencode({'issues': key, 'id': project})}"
    )
    return NormalizedExternalAlert(
        external_id=f"{project}:{key}",
        category="vulnerability",
        title=str(issue.get("message") or "SonarQube vulnerability")[:1000],
        severity=severity,
        status=status,
        resource=resource[:1000],
        source_url=source_url[:2000],
        cve_ids=[],
        evidence={
            "provider": "sonarqube",
            "project": project,
            "rule": issue.get("rule"),
            "line": line,
        },
        raw_payload=issue,
    )


def normalize_snyk_issue(organization_id: str, issue: dict[str, Any]) -> NormalizedExternalAlert:
    """Project a Snyk JSON:API issue into the source-preserving alert ledger."""
    issue_id = str(issue.get("id") or "").strip()
    attributes = issue.get("attributes")
    if not issue_id or not isinstance(attributes, dict):
        raise ValueError("Snyk issue lacks stable identity or attributes")
    external_id = f"{organization_id}:{issue_id}"
    if len(external_id) > 300:
        raise ValueError("Snyk issue identity exceeds ledger key size")
    relationships = issue.get("relationships") or {}
    scan_item = relationships.get("scan_item") if isinstance(relationships, dict) else None
    scan_item_data = scan_item.get("data") if isinstance(scan_item, dict) else None
    resource = (
        str(scan_item_data.get("id"))[:1000]
        if isinstance(scan_item_data, dict) and scan_item_data.get("id")
        else None
    )
    problems = attributes.get("problems")
    if not isinstance(problems, list):
        problems = []
    cves = [
        str(problem["id"]).upper()
        for problem in problems
        if isinstance(problem, dict) and str(problem.get("id", "")).upper().startswith("CVE-")
    ]
    status = str(attributes.get("status") or "open").lower()
    normalized_status = {**_STATUS, "ignored": "dismissed"}.get(status)
    if normalized_status is None:
        raise ValueError("Unsupported Snyk issue status")
    return NormalizedExternalAlert(
        external_id=external_id,
        category=str(issue.get("type") or "vulnerability")[:80],
        title=str(attributes.get("title") or "Snyk issue")[:1000],
        severity=_severity(
            attributes.get("effective_severity_level") or attributes.get("severity")
        ),
        status=normalized_status,
        resource=resource,
        source_url=None,
        cve_ids=list(dict.fromkeys(cves)),
        evidence={"provider": "snyk", "organization_id": organization_id},
        raw_payload=issue,
    )


def normalize_tenable_vulnerability(vuln: dict[str, Any]) -> NormalizedExternalAlert:
    """Keep scan, host, and plugin identity stable across subsequent scan runs."""
    scan_id = str(vuln.get("scan_id") or "")
    host_uuid = str(vuln.get("host_uuid") or "")
    plugin_id = vuln.get("plugin_id")
    if not scan_id or not host_uuid or not isinstance(plugin_id, int):
        raise ValueError("Tenable vulnerability lacks stable identity")
    external_id = f"{scan_id}:{host_uuid}:{plugin_id}"
    if len(external_id) > 300:
        raise ValueError("Tenable vulnerability identity exceeds ledger key size")
    severity_code = vuln.get("severity")
    severity = (
        {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(severity_code)
        if isinstance(severity_code, int)
        else None
    )
    if severity is None:
        raise ValueError("Unsupported Tenable vulnerability severity")
    from app.services.canonical_identity import valid_cves

    supplied = vuln.get("cve") or vuln.get("cves") or []
    if isinstance(supplied, str):
        supplied = re.split(r"[,;\s]+", supplied)
    cve_ids = valid_cves([str(value) for value in supplied]) if isinstance(supplied, list) else []
    return NormalizedExternalAlert(
        external_id=external_id,
        category="vulnerability",
        title=str(vuln.get("plugin_name") or f"Tenable plugin {plugin_id}")[:1000],
        severity=severity,
        status="open",
        resource=str(vuln.get("hostname") or host_uuid)[:1000],
        source_url=f"https://cloud.tenable.com/scans/{scan_id}/hosts/{vuln.get('host_id')}",
        cve_ids=cve_ids,
        evidence={
            "provider": "tenable",
            "scan_id": scan_id,
            "host_uuid": host_uuid,
            "plugin_id": plugin_id,
        },
        raw_payload=vuln,
    )


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
    alerts = (
        normalize_github_alert(category, alert)
        for category, feed_alerts in feeds
        for alert in feed_alerts
    )
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="github",
        alerts=alerts,
    )
    return GitHubSyncResult(total=total)


async def stage_gitlab_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    feeds: list[tuple[str, list[dict[str, Any]]]],
) -> GitHubSyncResult:
    """Stage GitLab project findings in the same idempotent external-alert ledger."""
    alerts = (
        normalize_gitlab_alert(project, alert)
        for project, project_alerts in feeds
        for alert in project_alerts
    )
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="gitlab",
        alerts=alerts,
    )
    return GitHubSyncResult(total=total)


async def stage_wazuh_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    hits: list[dict[str, Any]],
) -> GitHubSyncResult:
    """Stage Wazuh Indexer alert hits with the standard tenant-safe upsert boundary."""
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="wazuh",
        alerts=(normalize_wazuh_alert(hit) for hit in hits),
    )
    return GitHubSyncResult(total=total)


async def stage_sonarqube_issues(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    base_url: str,
    issues: list[dict[str, Any]],
) -> GitHubSyncResult:
    """Stage SonarQube vulnerabilities in the tenant-local idempotent alert ledger."""
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="sonarqube",
        alerts=(
            normalize_sonarqube_issue(base_url, str(issue["project"]), issue) for issue in issues
        ),
    )
    return GitHubSyncResult(total=total)


async def stage_snyk_issues(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    snyk_organization_id: str,
    issues: list[dict[str, Any]],
) -> GitHubSyncResult:
    """Stage Snyk issues through the same tenant-safe idempotent ledger."""
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="snyk",
        alerts=(normalize_snyk_issue(snyk_organization_id, issue) for issue in issues),
    )
    return GitHubSyncResult(total=total)


async def stage_tenable_vulnerabilities(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    vulnerabilities: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="tenable",
        alerts=(normalize_tenable_vulnerability(v) for v in vulnerabilities),
    )
    return GitHubSyncResult(total=total)


async def _stage_normalized_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    provider: str,
    alerts: Iterable[NormalizedExternalAlert],
) -> int:
    """Persist one provider's normalized alerts with tenant-local idempotency."""
    alerts_by_id = {alert.external_id: alert for alert in alerts}
    if not alerts_by_id:
        return 0

    now = utcnow()
    values = [
        {
            "organization_id": organization_id,
            "integration_id": integration_id,
            "provider": provider,
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
            "missing_sync_count": 0,
        }
        for alert in alerts_by_id.values()
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
            "missing_sync_count": 0,
        },
    )
    # RETURNING supplies the exact persisted rows (including ids and conflict-updated
    # state) to the canonical projector without a second, racy lookup.
    result = await session.execute(statement.returning(ExternalSecurityAlert))
    from app.services.canonical_ingest import ingest_external_alerts

    await ingest_external_alerts(session, organization_id, list(result.scalars().all()))
    return len(values)


async def reconcile_missing_sonarqube_issues(
    session: AsyncSession,
    *,
    organization_id: Any,
    project_keys: list[str],
    observed_external_ids: list[str],
) -> int:
    """Advance absence only after a complete SonarQube read in selected projects.

    A second consecutive miss resolves an open alert. Reappearance resets the counter
    in the normal upsert; the source system is never modified.
    """
    if not project_keys:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.provider == "sonarqube",
        alert.status == "open",
        alert.evidence["project"].astext.in_(project_keys),
    )
    if observed_external_ids:
        statement = statement.where(alert.external_id.not_in(observed_external_ids))
    statement = statement.values(
        missing_sync_count=alert.missing_sync_count + 1,
        status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
    )
    result = await session.execute(statement)
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="sonarqube",
        scope_keys=project_keys,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_tenable_vulnerabilities(
    session: AsyncSession,
    *,
    organization_id: Any,
    scan_ids: list[str],
    observed_external_ids: list[str],
) -> int:
    """Resolve only after two complete missing observations in the selected scans."""
    if not scan_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.provider == "tenable",
        alert.status == "open",
        alert.evidence["scan_id"].astext.in_(scan_ids),
    )
    if observed_external_ids:
        statement = statement.where(alert.external_id.not_in(observed_external_ids))
    statement = statement.values(
        missing_sync_count=alert.missing_sync_count + 1,
        status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
    )
    result = await session.execute(statement)
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="tenable",
        scope_keys=scan_ids,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def mark_missing_source_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    provider: str,
    sync_started_at: Any,
    project_keys: list[str] | None = None,
) -> int:
    """Flag absent GitHub/GitLab opens after a complete read, without closing them.

    Provider permissions and repository eligibility can shrink silently. An absence
    is therefore a freshness warning, never proof that a vulnerability was fixed.
    Re-seen alerts have their counter reset by the normal upsert.
    """
    if provider not in {"github", "gitlab"}:
        raise ValueError("absence marking is only supported for GitHub and GitLab")
    if provider == "gitlab" and not project_keys:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == provider,
        alert.status == "open",
        or_(alert.last_seen_at.is_(None), alert.last_seen_at < sync_started_at),
    )
    if provider == "gitlab":
        statement = statement.where(alert.evidence["project"].astext.in_(project_keys))
    result = await session.execute(
        statement.values(missing_sync_count=alert.missing_sync_count + 1)
    )
    return int(result.rowcount or 0)


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
    sync_started_at = utcnow()
    feeds = await GitHubClient(scoped, redis).list_security_alerts()
    result = await stage_github_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=integration.id if integration else None,
        feeds=[(feed.kind, feed.alerts) for feed in feeds],
    )
    missing_candidates = await mark_missing_source_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=integration.id if integration else None,
        provider="github",
        sync_started_at=sync_started_at,
    )
    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_SYNC,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id if integration else None,
        detail={
            "provider": "github",
            "alerts_staged": result.total,
            "missing_candidates": missing_candidates,
        },
    )
    return result


async def sync_gitlab_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Fetch the tenant's GitLab security findings and stage them privately.

    This is read-only against GitLab.  The synchronization result deliberately contains only
    a count, while locations, remediation hints and raw provider evidence stay behind the
    tenant-scoped backend boundary.
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.GITLAB
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.GITLAB, settings=settings, require=True
    )
    sync_started_at = utcnow()
    feeds = await GitLabClient(scoped, redis).list_security_alerts()
    result = await stage_gitlab_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=integration.id if integration else None,
        feeds=[(feed.project, feed.alerts) for feed in feeds],
    )
    missing_candidates = await mark_missing_source_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=integration.id if integration else None,
        provider="gitlab",
        sync_started_at=sync_started_at,
        project_keys=[feed.project for feed in feeds],
    )
    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_SYNC,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id if integration else None,
        detail={
            "provider": "gitlab",
            "alerts_staged": result.total,
            "missing_candidates": missing_candidates,
        },
    )
    return result


async def sync_wazuh_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Read Wazuh Indexer alerts through the tenant's dedicated read-only connection."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.WAZUH
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.WAZUH, settings=settings, require=False
    )
    hits = await WazuhIndexerClient(scoped, redis).list_alerts()
    result = await stage_wazuh_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=integration.id if integration else None,
        hits=hits,
    )
    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_SYNC,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id if integration else None,
        detail={"provider": "wazuh", "alerts_staged": result.total},
    )
    return result


async def sync_sonarqube_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest a tenant's configured SonarQube projects without provider-side writes."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.SONARQUBE
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.SONARQUBE, settings=settings, require=True
    )
    client = SonarQubeClient(scoped, redis)
    try:
        issues = await client.list_vulnerabilities()
        result = await stage_sonarqube_issues(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            base_url=scoped.sonarqube.base_url or "",
            issues=issues,
        )
        absence_candidates = await reconcile_missing_sonarqube_issues(
            session,
            organization_id=principal.organization_id,
            project_keys=list(scoped.sonarqube.project_keys),
            observed_external_ids=[f"{issue['project']}:{issue['key']}" for issue in issues],
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "sonarqube",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        return result
    finally:
        await client.aclose()


async def sync_snyk_issues(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Read one tenant's Snyk organization and stage issues without provider writes."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.SNYK
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.SNYK, settings=settings, require=True
    )
    client = SnykClient(scoped, redis)
    try:
        issues = await client.list_issues()
        result = await stage_snyk_issues(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            snyk_organization_id=scoped.snyk.organization_id or "",
            issues=issues,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={"provider": "snyk", "alerts_staged": result.total},
        )
        return result
    finally:
        await client.aclose()


async def sync_tenable_vulnerabilities(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Read selected, completed Tenable scans into this tenant's exposure ledger."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.require_tenant_tenable_integration(session, principal)
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.TENABLE, settings=settings, require=True
    )
    client = TenableClient(scoped, redis)
    try:
        vulnerabilities = await client.list_vulnerabilities()
        result = await stage_tenable_vulnerabilities(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            vulnerabilities=vulnerabilities,
        )
        absence_candidates = await reconcile_missing_tenable_vulnerabilities(
            session,
            organization_id=principal.organization_id,
            scan_ids=list(scoped.tenable.scan_ids),
            observed_external_ids=[
                normalize_tenable_vulnerability(v).external_id for v in vulnerabilities
            ],
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "tenable",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        return result
    finally:
        await client.aclose()


__all__ = [
    "GitHubSyncResult",
    "NormalizedExternalAlert",
    "normalize_gitlab_alert",
    "normalize_github_alert",
    "normalize_wazuh_alert",
    "stage_gitlab_alerts",
    "stage_github_alerts",
    "stage_wazuh_alerts",
    "sync_gitlab_alerts",
    "sync_github_alerts",
    "sync_wazuh_alerts",
    "sync_sonarqube_alerts",
    "stage_sonarqube_issues",
    "normalize_sonarqube_issue",
    "normalize_snyk_issue",
    "stage_snyk_issues",
    "sync_snyk_issues",
    "normalize_tenable_vulnerability",
    "stage_tenable_vulnerabilities",
    "sync_tenable_vulnerabilities",
    "reconcile_missing_tenable_vulnerabilities",
    "reconcile_missing_sonarqube_issues",
    "related_external_alerts_for_alert",
    "mark_missing_source_alerts",
]
