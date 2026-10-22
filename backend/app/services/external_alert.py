"""Provider-neutral normalization for externally ingested security alerts."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

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
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding
from app.db.models.identity import Organization
from app.db.queries import pg_any
from app.db.repository import TenantRepository, tenant_select
from app.integrations.aws_inspector import AwsInspectorClient
from app.integrations.aws_security_hub import AwsSecurityHubClient
from app.integrations.azure_defender import AzureDefenderClient
from app.integrations.bugcrowd import BugcrowdClient
from app.integrations.burp_dast import BurpDastClient
from app.integrations.checkmarx import CheckmarxClient
from app.integrations.crowdstrike import CrowdStrikeClient
from app.integrations.fortify import FortifySscClient
from app.integrations.gcp_scc import GcpSccClient
from app.integrations.github import GitHubClient
from app.integrations.gitlab import GitLabClient
from app.integrations.hackerone import HackerOneClient
from app.integrations.prisma_cloud import PrismaCloudClient
from app.integrations.qualys import QualysClient
from app.integrations.rapid7 import Rapid7Client
from app.integrations.snyk import SnykClient
from app.integrations.sonarqube import SonarQubeClient
from app.integrations.tenable import TenableClient
from app.integrations.wazuh import WazuhIndexerClient
from app.integrations.wiz import WizClient
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


async def canonical_findings_for_alert(
    session: AsyncSession,
    principal: Principal,
    alert_id: uuid.UUID,
) -> list[CanonicalFinding]:
    """Return the canonical records directly backed by this source observation.

    Canonical projection deliberately preserves a separate record per affected CVE
    where a provider reports multiple CVEs for one alert.  This endpoint makes that
    relationship explicit instead of asking an analyst to infer it from a looser
    title or CVE match.
    """
    alert = await get_external_alert(session, principal, alert_id)
    statement = (
        select(CanonicalFinding)
        .join(
            FindingObservation,
            FindingObservation.canonical_finding_id == CanonicalFinding.id,
        )
        .where(
            CanonicalFinding.organization_id == principal.organization_id,
            FindingObservation.organization_id == principal.organization_id,
            FindingObservation.provider == alert.provider,
            FindingObservation.external_id == alert.external_id,
        )
        .order_by(CanonicalFinding.risk_score.desc(), CanonicalFinding.id)
    )
    return list((await session.execute(statement)).scalars().unique().all())


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
    # Keep the same organization -> source row -> canonical row lock order as
    # bulk ingestion. A concurrent sync must not overwrite a confirmed decision
    # halfway through projecting its canonical lifecycle.
    await session.execute(
        select(Organization.id)
        .where(Organization.id == principal.organization_id)
        .with_for_update()
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
    from app.services.canonical_ingest import ingest_external_alerts

    await ingest_external_alerts(session, principal.organization_id, [row])
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
    """Safe summary of a provider ingestion run; it intentionally carries no alert content."""

    total: int
    absence_candidates: int = 0
    missing_source_records: int = 0


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


def normalize_rapid7_vulnerability(vuln: dict[str, Any]) -> NormalizedExternalAlert:
    """Map one scoped InsightVM service result into the shared exposure ledger."""
    asset_id = str(vuln.get("asset_id") or "")
    vuln_id = str(vuln.get("id") or "")
    protocol = str(vuln.get("protocol") or "").lower()
    port = vuln.get("port")
    if not asset_id.isdecimal() or not vuln_id or protocol not in {"tcp", "udp"} or not isinstance(port, int):
        raise ValueError("Rapid7 vulnerability lacks stable service identity")
    resource = str(vuln.get("asset_resource") or "").strip()
    if not resource:
        raise ValueError("Rapid7 vulnerability lacks an asset identity")
    try:
        ipaddress.ip_address(resource)
        asset_type = "ip"
    except ValueError:
        asset_type = "domain"
    references = vuln.get("references")
    from app.services.canonical_identity import valid_cves
    cves = valid_cves([str(item) for item in references]) if isinstance(references, list) else []
    severity = _severity(vuln.get("severity"))
    return NormalizedExternalAlert(
        external_id=f"{asset_id}:{protocol}:{port}:{vuln_id}"[:300],
        category="network",
        title=str(vuln.get("title") or vuln.get("description") or vuln_id)[:1000],
        severity=severity,
        status="dismissed" if vuln.get("invulnerable") is True else "open",
        resource=resource[:1000],
        source_url=None,
        cve_ids=cves,
        evidence={
            "provider": "rapid7",
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_value": resource[:1000],
            "vulnerability_id": vuln_id[:200],
            "protocol": protocol,
            "port": port,
        },
        raw_payload=vuln,
    )


def normalize_wiz_issue(issue: dict[str, Any]) -> NormalizedExternalAlert:
    """Map one selected-project Wiz Issue into the shared exposure ledger."""
    issue_id = issue.get("id")
    project_id = issue.get("_cynux_project_id")
    snapshot = issue.get("entitySnapshot")
    source_rule = issue.get("sourceRule")
    if not isinstance(snapshot, dict) or not isinstance(source_rule, dict):
        raise ValueError("Wiz issue lacks resource or rule information")
    resource = snapshot.get("externalId")
    rule_id = source_rule.get("id")
    title = source_rule.get("name") or rule_id
    for value, limit in ((issue_id, 300), (project_id, 128), (resource, 1000), (rule_id, 200), (title, 1000)):
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            raise ValueError("Wiz issue has missing or oversized identity fields")
    raw_severity = issue.get("severity")
    if not isinstance(raw_severity, str):
        raise ValueError("Unsupported Wiz issue severity")
    severity = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFORMATIONAL": "info",
    }.get(raw_severity)
    if severity is None:
        raise ValueError("Unsupported Wiz issue severity")
    status = {
        **_STATUS,
        "in_progress": "open",
        "rejected": "dismissed",
    }.get(str(issue.get("status") or "").lower())
    if status is None:
        raise ValueError("Unsupported Wiz issue status")
    from app.services.canonical_identity import valid_cves

    cves = valid_cves(re.findall(r"\bCVE-\d{4}-\d{4,}\b", f"{title} {rule_id}", re.I))
    return NormalizedExternalAlert(
        external_id=issue_id,
        category="cloud",
        title=title[:1000],
        severity=severity,
        status=status,
        resource=resource,
        source_url=None,
        cve_ids=cves,
        evidence={
            "provider": "wiz",
            "project_id": project_id,
            "project_ids": list(issue.get("_cynux_project_ids") or [project_id]),
            "rule_id": rule_id,
            "asset_type": "cloud",
            "asset_value": resource,
        },
        raw_payload=issue,
    )


def normalize_prisma_cloud_alert(alert: dict[str, Any]) -> NormalizedExternalAlert:
    """Map a Prisma CSPM alert to a stable cloud-resource observation."""
    external_id = alert.get("id")
    policy = alert.get("policy")
    resource = alert.get("resource")
    if (
        not isinstance(external_id, str)
        or not external_id
        or len(external_id) > 300
        or not isinstance(policy, dict)
        or not isinstance(resource, dict)
    ):
        raise ValueError("Prisma Cloud alert lacks stable identity")
    asset_value = str(resource.get("id") or resource.get("rrn") or resource.get("name") or "").strip()
    account_id = str(resource.get("accountId") or "").strip()
    policy_id = str(policy.get("policyId") or policy.get("id") or "").strip()
    title = str(policy.get("name") or policy_id or external_id).strip()
    if not asset_value or not account_id or not policy_id:
        raise ValueError("Prisma Cloud alert lacks resource, account, or policy identity")
    severity = _severity(policy.get("severity") or alert.get("severity"))
    status = _STATUS.get(str(alert.get("status") or "open").lower())
    if status is None:
        raise ValueError("Unsupported Prisma Cloud alert status")
    from app.services.canonical_identity import valid_cves

    cves = valid_cves(re.findall(r"\bCVE-\d{4}-\d{4,}\b", f"{title} {policy.get('description', '')}", re.I))
    return NormalizedExternalAlert(
        external_id=external_id,
        category="cloud",
        title=title[:1000],
        severity=severity,
        status=status,
        resource=asset_value[:1000],
        source_url=None,
        cve_ids=cves,
        evidence={
            "provider": "prisma_cloud",
            "asset_type": "cloud",
            "asset_value": asset_value[:1000],
            "cloud_account_id": account_id[:256],
            "policy_id": policy_id[:256],
            "policy_type": str(policy.get("policyType") or "")[:80],
            "cloud_type": str(resource.get("cloudType") or "")[:40],
            "region": str(resource.get("region") or "")[:120],
            "resource_type": str(resource.get("resourceType") or "")[:200],
            "recommendation": str(policy.get("recommendation") or "")[:8000],
        },
        raw_payload=alert,
    )


def normalize_crowdstrike_vulnerability(
    vulnerability: dict[str, Any],
) -> NormalizedExternalAlert:
    """Map one Falcon Spotlight exposure into the canonical intake contract."""
    external_id = vulnerability.get("id")
    cve = vulnerability.get("cve")
    host = vulnerability.get("host_info")
    if (
        not isinstance(external_id, str)
        or not external_id
        or len(external_id) > 300
        or not isinstance(cve, dict)
        or not isinstance(host, dict)
    ):
        raise ValueError("CrowdStrike vulnerability lacks stable identity")
    aid = str(host.get("aid") or vulnerability.get("aid") or "").strip()
    hostname = str(host.get("hostname") or "").strip()
    local_ip = str(host.get("local_ip") or "").strip()
    resource = hostname or local_ip or aid
    if not resource:
        raise ValueError("CrowdStrike vulnerability has no host identity")
    cve_id = str(cve.get("id") or vulnerability.get("vulnerability_id") or "").strip()
    from app.services.canonical_identity import valid_cves

    cve_ids = valid_cves([cve_id])
    severity = _severity(cve.get("severity"))
    status = _STATUS.get(str(vulnerability.get("status") or "").lower())
    if status is None:
        raise ValueError("Unsupported CrowdStrike vulnerability status")
    risk_score = vulnerability.get("risk_score")
    if isinstance(risk_score, bool) or not isinstance(risk_score, int | float):
        risk_score = None
    internet_exposure = str(host.get("internet_exposure") or "").upper() in {
        "YES",
        "TRUE",
        "EXTERNAL",
    }
    title = str(cve.get("description") or cve_id or vulnerability.get("vulnerability_id") or external_id)
    return NormalizedExternalAlert(
        external_id=external_id,
        category="endpoint_vulnerability",
        title=title[:1000],
        severity=severity,
        status=status,
        resource=resource[:1000],
        source_url=None,
        cve_ids=cve_ids,
        evidence={
            "provider": "crowdstrike",
            "asset_type": "host",
            "asset_value": resource[:1000],
            "aid": aid[:128],
            "local_ip": local_ip[:64],
            "internet_exposed": internet_exposure,
            "in_kev": cve.get("is_cisa_kev") is True,
            "cvss_score": cve.get("base_score")
            if isinstance(cve.get("base_score"), int | float)
            else None,
            "risk_score": float(risk_score) if risk_score is not None else None,
            "remediation_ids": list((vulnerability.get("remediation") or {}).get("ids") or [])[:50]
            if isinstance(vulnerability.get("remediation"), dict)
            else [],
        },
        raw_payload=vulnerability,
    )


def normalize_aws_security_hub_finding(finding: dict[str, Any]) -> NormalizedExternalAlert:
    """Map one active ASFF finding into the canonical exposure contract."""
    external_id = finding.get("Id")
    account_id = finding.get("AwsAccountId")
    resources = finding.get("Resources")
    if (
        not isinstance(external_id, str)
        or not external_id
        or len(external_id) > 300
        or not isinstance(account_id, str)
        or re.fullmatch(r"\d{12}", account_id) is None
        or not isinstance(resources, list)
        or not resources
        or not isinstance(resources[0], dict)
    ):
        raise ValueError("AWS Security Hub finding lacks stable resource identity")
    resource = str(resources[0].get("Id") or "").strip()
    if not resource:
        raise ValueError("AWS Security Hub finding has no resource ID")
    severity_data = finding.get("Severity")
    if not isinstance(severity_data, dict):
        raise ValueError("AWS Security Hub finding has no severity")
    severity = _severity(severity_data.get("Label"))
    normalized_score = severity_data.get("Normalized")
    if isinstance(normalized_score, bool) or not isinstance(normalized_score, int | float):
        normalized_score = None
    vulnerabilities = finding.get("Vulnerabilities")
    from app.services.canonical_identity import valid_cves

    cve_ids = valid_cves(
        [str(item.get("Id") or "") for item in vulnerabilities if isinstance(item, dict)]
        if isinstance(vulnerabilities, list)
        else []
    )
    details = resources[0].get("Details")
    public_ips: list[str] = []
    if isinstance(details, dict):
        for value in details.values():
            if not isinstance(value, dict):
                continue
            for key in ("IpV4Addresses", "PublicIp", "PublicIpAddress"):
                candidates = value.get(key)
                if isinstance(candidates, str):
                    candidates = [candidates]
                if isinstance(candidates, list):
                    for candidate in candidates:
                        try:
                            address = ipaddress.ip_address(str(candidate))
                        except ValueError:
                            continue
                        if address.is_global:
                            public_ips.append(str(address))
    remediation = finding.get("Remediation")
    recommendation = remediation.get("Recommendation") if isinstance(remediation, dict) else None
    return NormalizedExternalAlert(
        external_id=external_id,
        category="cloud",
        title=str(finding.get("Title") or external_id)[:1000],
        severity=severity,
        status="open",
        resource=resource[:1000],
        source_url=None,
        cve_ids=cve_ids,
        evidence={
            "provider": "aws_security_hub",
            "account_id": account_id,
            "region": str(finding.get("Region") or resources[0].get("Region") or "")[:64],
            "product": str(finding.get("ProductName") or "")[:200],
            "company": str(finding.get("CompanyName") or "")[:200],
            "asset_type": "cloud_resource",
            "asset_value": resource[:1000],
            "resource_type": str(resources[0].get("Type") or "")[:200],
            "internet_exposed": bool(public_ips),
            "public_ips": public_ips[:20],
            "risk_score": float(normalized_score) if normalized_score is not None else None,
            "remediation": str(recommendation.get("Text") or "")[:4000]
            if isinstance(recommendation, dict)
            else "",
        },
        raw_payload=finding,
    )


def normalize_aws_inspector_finding(finding: dict[str, Any]) -> NormalizedExternalAlert:
    """Map one active Inspector2 finding into the canonical exposure contract."""
    external_id = finding.get("findingArn")
    account_id = finding.get("awsAccountId")
    resources = finding.get("resources")
    if (
        not isinstance(external_id, str)
        or not external_id
        or len(external_id) > 300
        or not isinstance(account_id, str)
        or re.fullmatch(r"\d{12}", account_id) is None
        or not isinstance(resources, list)
        or not resources
        or not isinstance(resources[0], dict)
    ):
        raise ValueError("Amazon Inspector finding lacks stable resource identity")
    resource_data = resources[0]
    resource = str(resource_data.get("id") or "").strip()
    if not resource:
        raise ValueError("Amazon Inspector finding has no resource ID")
    raw_severity = str(finding.get("severity") or "").upper()
    severity = "info" if raw_severity == "UNTRIAGED" else _severity(raw_severity)
    status = {
        "active": "open",
        "suppressed": "dismissed",
        "closed": "resolved",
    }.get(str(finding.get("status") or "").lower())
    if status is None:
        raise ValueError("Unsupported Amazon Inspector finding status")
    package = finding.get("packageVulnerabilityDetails")
    vulnerability_id = package.get("vulnerabilityId") if isinstance(package, dict) else None
    from app.services.canonical_identity import valid_cves

    cve_ids = valid_cves(
        [
            str(vulnerability_id or ""),
            *re.findall(
                r"\bCVE-\d{4}-\d{4,}\b",
                f"{finding.get('title', '')} {finding.get('description', '')}",
                re.I,
            ),
        ]
    )
    score = finding.get("inspectorScore")
    if isinstance(score, bool) or not isinstance(score, int | float):
        score = None
    remediation = finding.get("remediation")
    recommendation = remediation.get("recommendation") if isinstance(remediation, dict) else None
    return NormalizedExternalAlert(
        external_id=external_id,
        category="cloud_vulnerability",
        title=str(finding.get("title") or vulnerability_id or external_id)[:1000],
        severity=severity,
        status=status,
        resource=resource[:1000],
        source_url=None,
        cve_ids=cve_ids,
        evidence={
            "provider": "aws_inspector",
            "aws_account_id": account_id,
            "asset_type": "cloud_resource",
            "asset_value": resource[:1000],
            "resource_type": str(resource_data.get("type") or "")[:100],
            "region": str(resource_data.get("region") or "")[:64],
            "finding_type": str(finding.get("type") or "")[:80],
            "risk_score": float(score) if score is not None else None,
            "exploit_available": finding.get("exploitAvailable") == "YES",
            "fix_available": finding.get("fixAvailable") in {"YES", "PARTIAL"},
            "remediation": str(recommendation.get("text") or "")[:4000]
            if isinstance(recommendation, dict)
            else "",
        },
        raw_payload=finding,
    )


def normalize_hackerone_report(report: dict[str, Any]) -> NormalizedExternalAlert:
    """Map a HackerOne customer report and its structured scope into one exposure."""
    if report.get("type") != "report":
        raise ValueError("HackerOne object is not a report")
    report_id = str(report.get("id") or "").strip()
    attributes = report.get("attributes")
    relationships = report.get("relationships")
    if not report_id or len(report_id) > 300 or not isinstance(attributes, dict) or not isinstance(relationships, dict):
        raise ValueError("HackerOne report lacks stable identity")
    program_relation = relationships.get("program")
    program_data = program_relation.get("data") if isinstance(program_relation, dict) else None
    program_attrs = program_data.get("attributes") if isinstance(program_data, dict) else None
    handle = str(program_attrs.get("handle") or "") if isinstance(program_attrs, dict) else ""
    scope_relation = relationships.get("structured_scope")
    scope_data = scope_relation.get("data") if isinstance(scope_relation, dict) else None
    scope_attrs = scope_data.get("attributes") if isinstance(scope_data, dict) else None
    if not handle or not isinstance(scope_attrs, dict):
        raise ValueError("HackerOne report lacks program or structured scope")
    asset_identifier = str(scope_attrs.get("asset_identifier") or "").strip()
    scope_type = str(scope_attrs.get("asset_type") or "").strip().lower()
    from app.services.canonical_identity import normalized_asset_identity, valid_cves

    type_map = {
        "url": "url",
        "domain": "domain",
        "wildcard": "domain",
        "cidr": "ip",
        "ip address": "ip",
        "source code": "repo",
        "downloadable executable": "application",
        "android: play store": "application",
        "ios: app store": "application",
    }
    try:
        asset_type, resource = normalized_asset_identity(type_map.get(scope_type, scope_type or "application"), asset_identifier)
    except ValueError as exc:
        raise ValueError("HackerOne report has an invalid structured scope") from exc
    state = str(attributes.get("state") or "").lower()
    status = {
        "new": "open",
        "pending-program-review": "open",
        "triaged": "open",
        "needs-more-info": "open",
        "retesting": "open",
        "resolved": "fixed",
        "not-applicable": "dismissed",
        "informative": "dismissed",
        "duplicate": "dismissed",
        "spam": "dismissed",
    }.get(state)
    if status is None:
        raise ValueError("Unsupported HackerOne report state")
    severity_relation = relationships.get("severity")
    severity_data = severity_relation.get("data") if isinstance(severity_relation, dict) else None
    severity_attrs = severity_data.get("attributes") if isinstance(severity_data, dict) else None
    rating = str(severity_attrs.get("rating") or "none").lower() if isinstance(severity_attrs, dict) else "none"
    if rating not in {"none", "low", "medium", "high", "critical"}:
        raise ValueError("Unsupported HackerOne severity rating")
    title = str(attributes.get("title") or "").strip()
    if not title:
        raise ValueError("HackerOne report has no title")
    cves = attributes.get("cve_ids")
    candidates = [str(value) for value in cves] if isinstance(cves, list) else []
    candidates.extend(re.findall(r"\bCVE-\d{4}-\d{4,}\b", title, re.I))
    return NormalizedExternalAlert(
        external_id=report_id,
        category="bug_bounty",
        title=title[:1000],
        severity="info" if rating == "none" else rating,
        status=status,
        resource=resource[:1000],
        source_url=f"https://hackerone.com/reports/{report_id}",
        cve_ids=valid_cves(candidates[:100]),
        evidence={
            "provider": "hackerone",
            "program_handle": handle,
            "asset_type": asset_type,
            "asset_value": resource[:1000],
            "scope_id": str(scope_data.get("id") or "")[:100] if isinstance(scope_data, dict) else "",
            "provider_state": state,
        },
        raw_payload=report,
    )


def normalize_bugcrowd_submission(row: dict[str, Any]) -> NormalizedExternalAlert:
    submission, target = row.get("submission"), row.get("target")
    engagement = str(row.get("engagement_code") or "")
    if not isinstance(submission, dict) or not isinstance(target, dict) or not engagement:
        raise ValueError("Bugcrowd submission lacks scoped identity")
    submission_id = str(submission.get("id") or "")
    attributes, target_attrs = submission.get("attributes"), target.get("attributes")
    if submission.get("type") != "submission" or not submission_id or not isinstance(attributes, dict) or not isinstance(target_attrs, dict):
        raise ValueError("Invalid Bugcrowd submission")
    resource = str(target_attrs.get("name") or "").strip()
    from app.services.canonical_identity import normalized_asset_identity, valid_cves
    if resource.startswith(("http://", "https://")):
        kind = "url"
    else:
        try:
            ipaddress.ip_address(resource)
            kind = "ip"
        except ValueError:
            kind = "domain" if "." in resource and " " not in resource else "application"
    kind, resource = normalized_asset_identity(kind, resource)
    state = str(attributes.get("state") or "").lower()
    status = {"new": "open", "triaged": "open", "unresolved": "open", "resolved": "fixed", "informational": "dismissed", "not-applicable": "dismissed", "not-reproducible": "dismissed", "out-of-scope": "dismissed"}.get(state)
    severity_raw = attributes.get("severity")
    if isinstance(severity_raw, str) and severity_raw.isdecimal():
        severity_raw = int(severity_raw)
    severity = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}.get(severity_raw) if not isinstance(severity_raw, bool) else None
    title = str(attributes.get("title") or "").strip()
    if status is None or severity is None or not title:
        raise ValueError("Bugcrowd submission lacks valid state, severity, or title")
    if attributes.get("duplicate") is True:
        status = "dismissed"
    return NormalizedExternalAlert(external_id=submission_id, category="bug_bounty", title=title[:1000], severity=severity, status=status, resource=resource[:1000], source_url=f"https://bugcrowd.com/submissions/{submission_id}", cve_ids=valid_cves(re.findall(r"\bCVE-\d{4}-\d{4,}\b", title, re.I)), evidence={"provider": "bugcrowd", "engagement_code": engagement, "asset_type": kind, "asset_value": resource[:1000], "target_id": str(target.get("id") or "")[:100], "provider_state": state}, raw_payload=submission)


def normalize_checkmarx_result(row: dict[str, Any]) -> NormalizedExternalAlert:
    result = row.get("result")
    project_id, asset = str(row.get("project_id") or ""), str(row.get("asset") or "")
    if not isinstance(result, dict) or not project_id or not asset:
        raise ValueError("Checkmarx result lacks project scope")
    external_id = str(result.get("id") or "")
    scan_id = str(result.get("scanId") or "")
    data = result.get("data")
    if not external_id or not scan_id or not isinstance(data, dict):
        raise ValueError("Checkmarx result lacks stable identity or details")
    category = str(result.get("type") or "sast").lower().replace("_", "-")
    category = {"sast": "sast", "sca": "sca", "kics": "iac", "iac-security": "iac", "api-security": "api", "containers": "container", "secret-detection": "secret"}.get(category, category)
    state = str(result.get("state") or "").upper()
    status_value = str(result.get("status") or "").upper()
    status = "dismissed" if state in {"NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE", "FALSE_POSITIVE"} or status_value in {"IGNORED", "NOT_EXPLOITABLE"} else "fixed" if status_value in {"FIXED", "RESOLVED"} else "open"
    title = str(data.get("queryName") or data.get("packageName") or data.get("title") or external_id)
    file_name = str(data.get("fileName") or data.get("path") or "")
    line = data.get("line")
    if isinstance(line, bool) or not isinstance(line, int):
        line = None
    from app.services.canonical_identity import valid_cves
    cve_values = [str(data.get(key) or "") for key in ("cveName", "cve", "vulnerabilityId")]
    cve_values.extend(re.findall(r"\bCVE-\d{4}-\d{4,}\b", title, re.I))
    return NormalizedExternalAlert(external_id=external_id, category=category, title=title[:1000], severity=_severity(result.get("severity")), status=status, resource=asset[:1000], source_url=None, cve_ids=valid_cves(cve_values), evidence={"provider": "checkmarx", "project_id": project_id, "scan_id": scan_id, "asset_type": "repo", "asset_value": asset[:1000], "file": file_name[:500], "line": line, "query_id": str(data.get("queryId") or "")[:100], "provider_state": state, "provider_status": status_value}, raw_payload=result)


def normalize_fortify_issue(row: dict[str, Any]) -> NormalizedExternalAlert:
    issue = row.get("issue")
    version_id = str(row.get("application_version_id") or "")
    asset = str(row.get("asset") or "").strip()
    if not isinstance(issue, dict) or not version_id or not asset:
        raise ValueError("Fortify issue lacks application-version scope")
    issue_id = str(issue.get("issueInstanceId") or "").strip()
    title = str(issue.get("issueName") or issue.get("category") or "").strip()
    if not issue_id or not title:
        raise ValueError("Fortify issue lacks stable identity or title")
    removed = issue.get("removed") is True or issue.get("isRemoved") is True
    suppressed = issue.get("suppressed") is True or issue.get("hidden") is True
    status = "fixed" if removed else "dismissed" if suppressed else "open"
    location = str(issue.get("primaryLocation") or issue.get("fileName") or "").strip()
    file_name, line = location, None
    match = re.fullmatch(r"(.+):(\d+)", location)
    if match:
        file_name, line = match.group(1), int(match.group(2))
    from app.services.canonical_identity import valid_cves

    cve_values: list[str] = []
    for value in (issue.get("cve"), issue.get("cveId"), issue.get("externalId")):
        if isinstance(value, str):
            cve_values.append(value)
    cve_values.extend(re.findall(r"\bCVE-\d{4}-\d{4,}\b", title, re.I))
    return NormalizedExternalAlert(
        external_id=f"{version_id}:{issue_id}",
        category="sast",
        title=title[:1000],
        severity=_severity(issue.get("friority") or issue.get("severityString") or issue.get("severity")),
        status=status,
        resource=asset[:1000],
        source_url=None,
        cve_ids=valid_cves(cve_values),
        evidence={
            "provider": "fortify",
            "application_version_id": version_id,
            "asset_type": "repo",
            "asset_value": asset[:1000],
            "issue_instance_id": issue_id[:200],
            "file": file_name[:500],
            "line": line,
            "kingdom": str(issue.get("kingdom") or "")[:200],
            "audited": issue.get("audited") is True,
        },
        raw_payload=issue,
    )


def normalize_azure_defender_alert(
    alert: dict[str, Any], *, subscription_id: str
) -> NormalizedExternalAlert:
    """Map a Defender for Cloud alert into the canonical exposure contract."""
    properties = alert.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("Azure Defender alert lacks properties")
    external_id = str(alert.get("name") or "").strip()
    if not external_id or len(external_id) > 300:
        raise ValueError("Azure Defender alert lacks stable identity")
    identifiers = properties.get("resourceIdentifiers")
    resource = ""
    if isinstance(identifiers, list):
        for item in identifiers:
            if isinstance(item, dict) and item.get("type") == "AzureResource":
                resource = str(item.get("azureResourceId") or "").strip()
                if resource:
                    break
    if not resource:
        resource = str(alert.get("id") or "").strip()
    expected_prefix = f"/subscriptions/{subscription_id.lower()}/"
    if not resource or not resource.lower().startswith(expected_prefix):
        raise ValueError("Azure Defender alert is outside the configured subscription")
    status = {
        "active": "open",
        "inprogress": "open",
        "resolved": "resolved",
        "dismissed": "dismissed",
    }.get(str(properties.get("status") or "").replace("_", "").lower())
    if status is None:
        raise ValueError("Unsupported Azure Defender alert status")
    title = str(properties.get("alertDisplayName") or properties.get("alertType") or external_id)
    description = str(properties.get("description") or "")
    from app.services.canonical_identity import valid_cves

    cve_ids = valid_cves(re.findall(r"\bCVE-\d{4}-\d{4,}\b", f"{title} {description}", re.I))
    entities = properties.get("entities")
    public_ips: list[str] = []
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            candidate = entity.get("address") or entity.get("ipAddress")
            if not isinstance(candidate, str):
                continue
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.is_global:
                public_ips.append(str(address))
    remediation = properties.get("remediationSteps")
    return NormalizedExternalAlert(
        external_id=external_id,
        category="cloud",
        title=title[:1000],
        severity=_severity(properties.get("severity")),
        status=status,
        resource=resource[:1000],
        source_url=None,
        cve_ids=cve_ids,
        evidence={
            "provider": "azure_defender",
            "subscription_id": subscription_id.lower(),
            "asset_type": "cloud_resource",
            "asset_value": resource[:1000],
            "product": str(properties.get("productName") or "")[:200],
            "alert_type": str(properties.get("alertType") or "")[:200],
            "internet_exposed": bool(public_ips),
            "public_ips": public_ips[:20],
            "remediation": [str(item)[:2000] for item in remediation[:20]]
            if isinstance(remediation, list)
            else [],
        },
        raw_payload=alert,
    )


def normalize_gcp_scc_finding(
    result: dict[str, Any], *, project_id: str
) -> NormalizedExternalAlert:
    """Map one SCC v2 ListFindingsResult into the canonical exposure contract."""
    finding = result.get("finding")
    resource_data = result.get("resource")
    if not isinstance(finding, dict) or not isinstance(resource_data, dict):
        raise ValueError("GCP SCC result lacks finding or resource data")
    name = str(finding.get("name") or "")
    expected_prefix = f"projects/{project_id}/sources/"
    if not name.startswith(expected_prefix) or "/findings/" not in name:
        raise ValueError("GCP SCC finding is outside the configured project")
    external_id = name.rsplit("/findings/", 1)[-1]
    if not external_id or len(external_id) > 300:
        raise ValueError("GCP SCC finding lacks stable identity")
    resource = str(finding.get("resourceName") or resource_data.get("name") or "").strip()
    resource_project = str(resource_data.get("projectName") or "")
    if not resource or not resource_project.endswith(f"/projects/{project_id}"):
        raise ValueError("GCP SCC resource is outside the configured project")
    state = str(finding.get("state") or "").upper()
    mute = str(finding.get("mute") or "").upper()
    if mute == "MUTED":
        status = "dismissed"
    elif state == "ACTIVE":
        status = "open"
    elif state == "INACTIVE":
        status = "resolved"
    else:
        raise ValueError("Unsupported GCP SCC finding state")
    category = str(finding.get("category") or "")
    properties = finding.get("sourceProperties")
    description = " ".join(str(value) for value in properties.values()) if isinstance(properties, dict) else ""
    from app.services.canonical_identity import valid_cves

    cve_ids = valid_cves(
        re.findall(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}\b", f"{category} {description}", re.I)
    )
    exposure = finding.get("attackExposure")
    score = exposure.get("score") if isinstance(exposure, dict) else None
    if isinstance(score, bool) or not isinstance(score, int | float):
        score = None
    return NormalizedExternalAlert(
        external_id=external_id,
        category="cloud",
        title=(category or external_id)[:1000],
        severity=_severity(finding.get("severity")),
        status=status,
        resource=resource[:1000],
        source_url=str(finding.get("externalUri") or "")[:2000] or None,
        cve_ids=cve_ids,
        evidence={
            "provider": "gcp_scc",
            "project_id": project_id,
            "asset_type": "cloud_resource",
            "asset_value": resource[:1000],
            "resource_type": str(resource_data.get("type") or "")[:200],
            "display_name": str(resource_data.get("displayName") or "")[:500],
            "finding_class": str(finding.get("findingClass") or "")[:100],
            "risk_score": float(score) if score is not None else None,
        },
        raw_payload=result,
    )


def normalize_burp_dast_issue(row: dict[str, Any]) -> NormalizedExternalAlert:
    """Map a Burp issue to a stable web exposure across repeated site scans."""
    site_id = str(row.get("site_id") or "")
    scan = row.get("scan")
    issue = row.get("issue")
    if not site_id.isdigit() or not isinstance(scan, dict) or not isinstance(issue, dict):
        raise ValueError("Burp DAST issue lacks site, scan, or issue data")
    if str(scan.get("status") or "").lower() != "succeeded":
        raise ValueError("Burp DAST scan is not complete")
    scan_id = str(scan.get("id") or "")
    serial_number = str(issue.get("serial_number") or "")
    issue_type = issue.get("issue_type")
    if not scan_id or not serial_number or not isinstance(issue_type, dict):
        raise ValueError("Burp DAST issue lacks stable identity")
    type_index = str(issue_type.get("type_index") or "")
    title = str(issue_type.get("name") or "").strip()
    origin = str(issue.get("origin") or "").strip().rstrip("/")
    path = str(issue.get("path") or "").strip()
    try:
        parsed = urlsplit(origin)
    except ValueError as exc:
        raise ValueError("Burp DAST issue has an invalid origin") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not type_index or not title:
        raise ValueError("Burp DAST issue lacks a valid web location or issue type")
    resource = f"{origin}/{path.lstrip('/')}" if path else origin
    identity = f"{site_id}\0{type_index}\0{origin.lower()}\0{path}"
    external_id = f"{site_id}:{hashlib.sha256(identity.encode()).hexdigest()[:40]}"
    description_html = str(issue.get("description_html") or "")
    remediation_html = str(issue.get("remediation_html") or "")
    searchable = re.sub(r"<[^>]+>", " ", f"{title} {description_html}")
    from app.services.canonical_identity import valid_cves

    cve_ids = valid_cves(re.findall(r"\bCVE-\d{4}-\d{4,}\b", searchable, re.I))
    return NormalizedExternalAlert(
        external_id=external_id,
        category="dast",
        title=title[:1000],
        severity=_severity(issue.get("severity")),
        status="open",
        resource=resource[:1000],
        source_url=None,
        cve_ids=cve_ids,
        evidence={
            "provider": "burp_dast",
            "site_id": site_id,
            "scan_id": scan_id,
            "serial_number": serial_number[:100],
            "type_index": type_index[:100],
            "confidence": str(issue.get("confidence") or "")[:50],
            "asset_type": "url",
            "asset_value": resource[:1000],
            "remediation": re.sub(r"<[^>]+>", " ", remediation_html).strip()[:4000],
        },
        raw_payload=row,
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


async def stage_rapid7_vulnerabilities(
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
        provider="rapid7",
        alerts=(normalize_rapid7_vulnerability(vulnerability) for vulnerability in vulnerabilities),
    )
    return GitHubSyncResult(total=total)


async def stage_wiz_issues(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    issues: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="wiz",
        alerts=(normalize_wiz_issue(issue) for issue in issues),
    )
    return GitHubSyncResult(total=total)


async def stage_prisma_cloud_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    alerts: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="prisma_cloud",
        alerts=(normalize_prisma_cloud_alert(item) for item in alerts),
    )
    return GitHubSyncResult(total=total)


async def stage_crowdstrike_vulnerabilities(
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
        provider="crowdstrike",
        alerts=(normalize_crowdstrike_vulnerability(item) for item in vulnerabilities),
    )
    return GitHubSyncResult(total=total)


async def stage_aws_security_hub_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    findings: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="aws_security_hub",
        alerts=(normalize_aws_security_hub_finding(item) for item in findings),
    )
    return GitHubSyncResult(total=total)


async def stage_aws_inspector_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    findings: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="aws_inspector",
        alerts=(normalize_aws_inspector_finding(item) for item in findings),
    )
    return GitHubSyncResult(total=total)


async def stage_hackerone_reports(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    reports: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="hackerone",
        alerts=(normalize_hackerone_report(item) for item in reports),
    )
    return GitHubSyncResult(total=total)


async def stage_bugcrowd_submissions(session: AsyncSession, *, organization_id: Any, integration_id: Any | None, submissions: list[dict[str, Any]]) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(session, organization_id=organization_id, integration_id=integration_id, provider="bugcrowd", alerts=(normalize_bugcrowd_submission(item) for item in submissions))
    return GitHubSyncResult(total=total)


async def stage_checkmarx_results(session: AsyncSession, *, organization_id: Any, integration_id: Any | None, results: list[dict[str, Any]]) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(session, organization_id=organization_id, integration_id=integration_id, provider="checkmarx", alerts=(normalize_checkmarx_result(item) for item in results))
    return GitHubSyncResult(total=total)


async def stage_fortify_issues(session: AsyncSession, *, organization_id: Any, integration_id: Any | None, issues: list[dict[str, Any]]) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(session, organization_id=organization_id, integration_id=integration_id, provider="fortify", alerts=(normalize_fortify_issue(item) for item in issues))
    return GitHubSyncResult(total=total)


async def stage_azure_defender_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    subscription_id: str,
    alerts: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="azure_defender",
        alerts=(
            normalize_azure_defender_alert(item, subscription_id=subscription_id)
            for item in alerts
        ),
    )
    return GitHubSyncResult(total=total)


async def stage_gcp_scc_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    project_id: str,
    findings: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="gcp_scc",
        alerts=(normalize_gcp_scc_finding(item, project_id=project_id) for item in findings),
    )
    return GitHubSyncResult(total=total)


async def stage_burp_dast_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    findings: list[dict[str, Any]],
) -> GitHubSyncResult:
    total = await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider="burp_dast",
        alerts=(normalize_burp_dast_issue(item) for item in findings),
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
    # Match the canonical projector's lock order before touching source rows.
    # Otherwise two multi-batch syncs can each hold rows the other needs while
    # one waits for the projector's organization lock. Empty pulls also serialize
    # with subsequent absence marking in the same caller-owned transaction.
    await session.execute(
        select(Organization.id).where(Organization.id == organization_id).with_for_update()
    )
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
    from app.services.canonical_ingest import ingest_external_alerts

    # Normalize the entire pull before writing, but bound source-upsert parameter
    # counts. Every batch stays in the caller's single transaction.
    persisted: list[ExternalSecurityAlert] = []
    for offset in range(0, len(values), 500):
        statement = insert(ExternalSecurityAlert).values(values[offset : offset + 500])
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
        # RETURNING includes conflict-updated state; refresh identity-map objects
        # too if this session already loaded a row earlier in the workflow.
        result = await session.execute(
            statement.returning(ExternalSecurityAlert).execution_options(populate_existing=True)
        )
        persisted.extend(result.scalars().all())
    # Reconcile lifecycle once for the complete snapshot. Projecting each chunk
    # independently could briefly close and reopen a finding whose open and fixed
    # observations happened to arrive in separate chunks, emitting false events.
    await ingest_external_alerts(session, organization_id, persisted)
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
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
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
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
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


async def reconcile_missing_qualys_host_detections(
    session: AsyncSession,
    *,
    organization_id: Any,
    asset_ip: str,
    observed_external_ids: list[str],
) -> int:
    """Advance closure evidence only for a complete Qualys read of one IP asset.

    A Qualys connector is deliberately bounded to one configured host.  This
    lets a later complete response safely act as evidence of absence for that
    host, while leaving detections from every other asset and every other
    scanner untouched.
    """
    if not asset_ip:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.provider == "qualys",
        alert.status == "open",
        alert.evidence["asset_value"].astext == asset_ip,
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="qualys",
        scope_keys=[asset_ip],
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_rapid7_vulnerabilities(
    session: AsyncSession,
    *,
    organization_id: Any,
    asset_ids: list[str],
    observed_external_ids: list[str],
) -> int:
    """Use two complete scoped InsightVM reads before closing source observations."""
    if not asset_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.provider == "rapid7",
        alert.status == "open",
        alert.evidence["asset_id"].astext.in_(asset_ids),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="rapid7",
        scope_keys=asset_ids,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_crowdstrike_vulnerabilities(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    observed_external_ids: list[str],
) -> int:
    """Close Spotlight source observations only after two complete open snapshots."""
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "crowdstrike",
        alert.status == "open",
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="crowdstrike",
        scope_keys=["crowdstrike"],
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_aws_security_hub_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    account_ids: list[str],
    observed_external_ids: list[str],
) -> int:
    """Close ASFF observations only after two complete account-scoped snapshots."""
    if not account_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "aws_security_hub",
        alert.status == "open",
        alert.evidence["account_id"].astext.in_(account_ids),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="aws_security_hub",
        scope_keys=account_ids,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_prisma_cloud_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    account_ids: list[str],
    observed_external_ids: list[str],
) -> int:
    """Close Prisma observations only after two complete account-scoped snapshots."""
    if not account_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "prisma_cloud",
        alert.status == "open",
        alert.evidence["cloud_account_id"].astext.in_(account_ids),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="prisma_cloud",
        scope_keys=account_ids,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_aws_inspector_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    account_ids: list[str],
    observed_external_ids: list[str],
) -> int:
    """Close Inspector observations only after two complete account snapshots."""
    if not account_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "aws_inspector",
        alert.status == "open",
        alert.evidence["aws_account_id"].astext.in_(account_ids),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="aws_inspector",
        scope_keys=account_ids,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_hackerone_reports(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    program_handles: list[str],
    observed_external_ids: list[str],
) -> int:
    """Close reports after two complete misses within selected programs."""
    if not program_handles:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "hackerone",
        alert.status == "open",
        alert.evidence["program_handle"].astext.in_(program_handles),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="hackerone",
        scope_keys=program_handles,
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_bugcrowd_submissions(session: AsyncSession, *, organization_id: Any, integration_id: Any | None, engagement_codes: list[str], observed_external_ids: list[str]) -> int:
    if not engagement_codes:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(alert.organization_id == organization_id, alert.integration_id == integration_id, alert.provider == "bugcrowd", alert.status == "open", alert.evidence["engagement_code"].astext.in_(engagement_codes))
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(statement.values(missing_sync_count=alert.missing_sync_count + 1, status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status)))
    from app.services.canonical_ingest import reconcile_absent_observations
    await reconcile_absent_observations(session, organization_id, provider="bugcrowd", scope_keys=engagement_codes, observed_external_ids=observed_external_ids)
    return int(result.rowcount or 0)


async def reconcile_missing_checkmarx_results(session: AsyncSession, *, organization_id: Any, integration_id: Any | None, project_ids: list[str], observed_external_ids: list[str]) -> int:
    if not project_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(alert.organization_id == organization_id, alert.integration_id == integration_id, alert.provider == "checkmarx", alert.status == "open", alert.evidence["project_id"].astext.in_(project_ids))
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(statement.values(missing_sync_count=alert.missing_sync_count + 1, status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status)))
    from app.services.canonical_ingest import reconcile_absent_observations
    await reconcile_absent_observations(session, organization_id, provider="checkmarx", scope_keys=project_ids, observed_external_ids=observed_external_ids)
    return int(result.rowcount or 0)


async def reconcile_missing_fortify_issues(session: AsyncSession, *, organization_id: Any, integration_id: Any | None, application_version_ids: list[str], observed_external_ids: list[str]) -> int:
    if not application_version_ids:
        return 0
    alert = ExternalSecurityAlert
    statement = update(alert).where(alert.organization_id == organization_id, alert.integration_id == integration_id, alert.provider == "fortify", alert.status == "open", alert.evidence["application_version_id"].astext.in_(application_version_ids))
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(statement.values(missing_sync_count=alert.missing_sync_count + 1, status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status)))
    from app.services.canonical_ingest import reconcile_absent_observations
    await reconcile_absent_observations(session, organization_id, provider="fortify", scope_keys=application_version_ids, observed_external_ids=observed_external_ids)
    return int(result.rowcount or 0)


async def reconcile_missing_azure_defender_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    subscription_id: str,
    observed_external_ids: list[str],
) -> int:
    """Close Defender observations after two complete subscription snapshots."""
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "azure_defender",
        alert.status == "open",
        alert.evidence["subscription_id"].astext == subscription_id,
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="azure_defender",
        scope_keys=[subscription_id],
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_gcp_scc_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    project_id: str,
    observed_external_ids: list[str],
) -> int:
    """Close SCC observations only after two complete project snapshots."""
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "gcp_scc",
        alert.status == "open",
        alert.evidence["project_id"].astext == project_id,
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="gcp_scc",
        scope_keys=[project_id],
        observed_external_ids=observed_external_ids,
    )
    return int(result.rowcount or 0)


async def reconcile_missing_burp_dast_findings(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    site_ids: list[str],
    observed_external_ids: list[str],
) -> int:
    """Close Burp issues after two complete latest-scan snapshots for selected sites."""
    alert = ExternalSecurityAlert
    statement = update(alert).where(
        alert.organization_id == organization_id,
        alert.integration_id == integration_id,
        alert.provider == "burp_dast",
        alert.status == "open",
        pg_any(alert.evidence["site_id"].astext, site_ids),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(alert.external_id, observed_external_ids))
    result = await session.execute(
        statement.values(
            missing_sync_count=alert.missing_sync_count + 1,
            status=case((alert.missing_sync_count >= 1, "resolved"), else_=alert.status),
        )
    )
    from app.services.canonical_ingest import reconcile_absent_observations

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="burp_dast",
        scope_keys=site_ids,
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
    """Flag absent GitHub/GitLab/Wiz opens after a complete read, without closing them.

    Provider permissions and repository eligibility can shrink silently. An absence
    is therefore a freshness warning, never proof that a vulnerability was fixed.
    Re-seen alerts have their counter reset by the normal upsert.
    """
    if provider not in {"github", "gitlab", "wiz"}:
        raise ValueError("absence marking is only supported for GitHub, GitLab, and Wiz")
    if provider in {"gitlab", "wiz"} and not project_keys:
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
    if provider == "wiz":
        statement = statement.where(or_(
            alert.evidence["project_id"].astext.in_(project_keys),
            *(alert.evidence["project_ids"].contains([key]) for key in project_keys or []),
        ))
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
    integration_service.mark_sync_succeeded(integration)
    return GitHubSyncResult(total=result.total, missing_source_records=missing_candidates)


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
    integration_service.mark_sync_succeeded(integration)
    return GitHubSyncResult(total=result.total, missing_source_records=missing_candidates)


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
    integration_service.mark_sync_succeeded(integration)
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
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
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
        integration_service.mark_sync_succeeded(integration)
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
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_rapid7_vulnerabilities(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest service vulnerabilities from only the tenant-selected InsightVM assets."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(session, principal, IntegrationKind.RAPID7)
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.RAPID7, settings=settings, require=True
    )
    client = Rapid7Client(scoped, redis)
    try:
        vulnerabilities = await client.list_vulnerabilities()
        result = await stage_rapid7_vulnerabilities(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            vulnerabilities=vulnerabilities,
        )
        absence_candidates = await reconcile_missing_rapid7_vulnerabilities(
            session,
            organization_id=principal.organization_id,
            asset_ids=list(scoped.rapid7.asset_ids),
            observed_external_ids=[
                normalize_rapid7_vulnerability(vulnerability).external_id
                for vulnerability in vulnerabilities
            ],
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "rapid7",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_wiz_issues(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest selected-project Wiz Issues without any provider-side mutation."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(session, principal, IntegrationKind.WIZ)
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.WIZ, settings=settings, require=True
    )
    client = WizClient(scoped, redis)
    try:
        sync_started_at = utcnow()
        issues = await client.list_issues()
        result = await stage_wiz_issues(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            issues=issues,
        )
        missing_candidates = await mark_missing_source_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            provider="wiz",
            sync_started_at=sync_started_at,
            project_keys=list(scoped.wiz.project_ids),
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "wiz",
                "alerts_staged": result.total,
                "missing_candidates": missing_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, missing_source_records=missing_candidates)
    finally:
        await client.aclose()


async def sync_prisma_cloud_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest a complete open-alert snapshot for selected Prisma cloud accounts."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.PRISMA_CLOUD
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.PRISMA_CLOUD, settings=settings, require=True
    )
    client = PrismaCloudClient(scoped, redis)
    try:
        alerts = await client.list_alerts()
        result = await stage_prisma_cloud_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            alerts=alerts,
        )
        absence_candidates = await reconcile_missing_prisma_cloud_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            account_ids=list(scoped.prisma_cloud.cloud_account_ids),
            observed_external_ids=[normalize_prisma_cloud_alert(item).external_id for item in alerts],
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "prisma_cloud",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_crowdstrike_vulnerabilities(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest a complete read-only Falcon Spotlight open-vulnerability snapshot."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.CROWDSTRIKE
    )
    scoped = await integration_service.resolve_settings(
        session,
        principal,
        IntegrationKind.CROWDSTRIKE,
        settings=settings,
        require=True,
    )
    client = CrowdStrikeClient(scoped, redis)
    try:
        vulnerabilities = await client.list_vulnerabilities()
        result = await stage_crowdstrike_vulnerabilities(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            vulnerabilities=vulnerabilities,
        )
        observed = [normalize_crowdstrike_vulnerability(item).external_id for item in vulnerabilities]
        absence_candidates = await reconcile_missing_crowdstrike_vulnerabilities(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "crowdstrike",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_aws_security_hub_findings(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest active AWS Security Hub findings for explicitly selected accounts."""
    del redis
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.AWS_SECURITY_HUB
    )
    scoped = await integration_service.resolve_settings(
        session,
        principal,
        IntegrationKind.AWS_SECURITY_HUB,
        settings=settings,
        require=True,
    )
    client = AwsSecurityHubClient(scoped)
    try:
        findings = await client.list_findings()
        result = await stage_aws_security_hub_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            findings=findings,
        )
        observed = [normalize_aws_security_hub_finding(item).external_id for item in findings]
        absence_candidates = await reconcile_missing_aws_security_hub_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            account_ids=list(scoped.aws_security_hub.account_ids),
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "aws_security_hub",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_aws_inspector_findings(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest active Inspector2 findings for explicitly selected AWS accounts."""
    del redis
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.AWS_INSPECTOR
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.AWS_INSPECTOR, settings=settings, require=True
    )
    client = AwsInspectorClient(scoped)
    try:
        findings = await client.list_findings()
        result = await stage_aws_inspector_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            findings=findings,
        )
        observed = [normalize_aws_inspector_finding(item).external_id for item in findings]
        absence_candidates = await reconcile_missing_aws_inspector_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            account_ids=list(scoped.aws_inspector.account_ids),
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "aws_inspector",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_hackerone_reports(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest a complete report snapshot for selected HackerOne programs."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.HACKERONE
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.HACKERONE, settings=settings, require=True
    )
    client = HackerOneClient(scoped, redis)
    program_handles = [str(value) for value in scoped.hackerone.program_handles]
    try:
        reports = await client.list_reports()
        result = await stage_hackerone_reports(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            reports=reports,
        )
        observed = [normalize_hackerone_report(item).external_id for item in reports]
        absence_candidates = await reconcile_missing_hackerone_reports(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            program_handles=program_handles,
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "hackerone",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_bugcrowd_submissions(session: AsyncSession, principal: Principal, *, settings: Settings, redis: Any | None = None) -> GitHubSyncResult:
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service
    integration = await integration_service.find_integration(session, principal, IntegrationKind.BUGCROWD)
    scoped = await integration_service.resolve_settings(session, principal, IntegrationKind.BUGCROWD, settings=settings, require=True)
    client = BugcrowdClient(scoped, redis)
    codes = [str(value) for value in scoped.bugcrowd.engagement_codes]
    try:
        rows = await client.list_submissions()
        result = await stage_bugcrowd_submissions(session, organization_id=principal.organization_id, integration_id=integration.id if integration else None, submissions=rows)
        absence_candidates = await reconcile_missing_bugcrowd_submissions(session, organization_id=principal.organization_id, integration_id=integration.id if integration else None, engagement_codes=codes, observed_external_ids=[normalize_bugcrowd_submission(item).external_id for item in rows])
        await audit_service.record(session, action=AuditAction.INTEGRATION_SYNC, principal=principal, resource_type="integration", resource_id=integration.id if integration else None, detail={"provider": "bugcrowd", "alerts_staged": result.total, "absence_candidates": absence_candidates})
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_checkmarx_results(session: AsyncSession, principal: Principal, *, settings: Settings, redis: Any | None = None) -> GitHubSyncResult:
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service
    integration = await integration_service.find_integration(session, principal, IntegrationKind.CHECKMARX)
    scoped = await integration_service.resolve_settings(session, principal, IntegrationKind.CHECKMARX, settings=settings, require=True)
    client = CheckmarxClient(scoped, redis)
    project_ids = list(scoped.checkmarx.projects)
    try:
        rows = await client.list_results()
        result = await stage_checkmarx_results(session, organization_id=principal.organization_id, integration_id=integration.id if integration else None, results=rows)
        absence_candidates = await reconcile_missing_checkmarx_results(session, organization_id=principal.organization_id, integration_id=integration.id if integration else None, project_ids=project_ids, observed_external_ids=[normalize_checkmarx_result(item).external_id for item in rows])
        await audit_service.record(session, action=AuditAction.INTEGRATION_SYNC, principal=principal, resource_type="integration", resource_id=integration.id if integration else None, detail={"provider": "checkmarx", "alerts_staged": result.total, "absence_candidates": absence_candidates})
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_fortify_issues(session: AsyncSession, principal: Principal, *, settings: Settings, redis: Any | None = None) -> GitHubSyncResult:
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service
    integration = await integration_service.find_integration(session, principal, IntegrationKind.FORTIFY)
    scoped = await integration_service.resolve_settings(session, principal, IntegrationKind.FORTIFY, settings=settings, require=True)
    client = FortifySscClient(scoped, redis)
    version_ids = list(scoped.fortify.application_versions)
    try:
        rows = await client.list_issues()
        result = await stage_fortify_issues(session, organization_id=principal.organization_id, integration_id=integration.id if integration else None, issues=rows)
        observed = [normalize_fortify_issue(item).external_id for item in rows]
        absence_candidates = await reconcile_missing_fortify_issues(session, organization_id=principal.organization_id, integration_id=integration.id if integration else None, application_version_ids=version_ids, observed_external_ids=observed)
        await audit_service.record(session, action=AuditAction.INTEGRATION_SYNC, principal=principal, resource_type="integration", resource_id=integration.id if integration else None, detail={"provider": "fortify", "alerts_staged": result.total, "absence_candidates": absence_candidates})
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_azure_defender_alerts(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest a complete Defender for Cloud subscription alert snapshot."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.AZURE_DEFENDER
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.AZURE_DEFENDER, settings=settings, require=True
    )
    client = AzureDefenderClient(scoped, redis)
    subscription_id = str(scoped.azure_defender.subscription_id or "").lower()
    try:
        alerts = await client.list_alerts()
        result = await stage_azure_defender_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            subscription_id=subscription_id,
            alerts=alerts,
        )
        observed = [
            normalize_azure_defender_alert(item, subscription_id=subscription_id).external_id
            for item in alerts
        ]
        absence_candidates = await reconcile_missing_azure_defender_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            subscription_id=subscription_id,
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "azure_defender",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_gcp_scc_findings(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest a complete Security Command Center project snapshot."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(session, principal, IntegrationKind.GCP_SCC)
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.GCP_SCC, settings=settings, require=True
    )
    client = GcpSccClient(scoped, redis)
    project_id = str(scoped.gcp_scc.project_id or "")
    try:
        findings = await client.list_findings()
        result = await stage_gcp_scc_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            project_id=project_id,
            findings=findings,
        )
        observed = [normalize_gcp_scc_finding(item, project_id=project_id).external_id for item in findings]
        absence_candidates = await reconcile_missing_gcp_scc_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            project_id=project_id,
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "gcp_scc",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_burp_dast_findings(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest complete latest Burp DAST scan snapshots for selected tenant sites."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(
        session, principal, IntegrationKind.BURP_DAST
    )
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.BURP_DAST, settings=settings, require=True
    )
    client = BurpDastClient(scoped, redis)
    site_ids = [str(value) for value in scoped.burp_dast.site_ids]
    try:
        findings = await client.list_findings()
        result = await stage_burp_dast_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            findings=findings,
        )
        observed = [normalize_burp_dast_issue(item).external_id for item in findings]
        absence_candidates = await reconcile_missing_burp_dast_findings(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            site_ids=site_ids,
            observed_external_ids=observed,
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "burp_dast",
                "alerts_staged": result.total,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
    finally:
        await client.aclose()


async def sync_qualys_host_detections(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Any | None = None,
) -> GitHubSyncResult:
    """Ingest one explicitly configured Qualys VM host without provider-side writes."""
    principal.require(Permission.INTEGRATION_MANAGE)
    from app.services import file_intake
    from app.services import integration as integration_service

    integration = await integration_service.find_integration(session, principal, IntegrationKind.QUALYS)
    scoped = await integration_service.resolve_settings(
        session, principal, IntegrationKind.QUALYS, settings=settings, require=True
    )
    client = QualysClient(scoped, redis)
    try:
        asset_ip = scoped.qualys.asset_ip or ""
        report = await client.host_detections_xml(details="All")
        alerts = file_intake.parse_scan_export(
            report,
            format_name="qualys_host_detection_xml",
            provider="qualys",
            asset_type="ip",
            asset_value=asset_ip,
        )
        result = await _stage_normalized_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=integration.id if integration else None,
            provider="qualys",
            alerts=alerts,
        )
        absence_candidates = await reconcile_missing_qualys_host_detections(
            session,
            organization_id=principal.organization_id,
            asset_ip=asset_ip,
            observed_external_ids=[alert.external_id for alert in alerts],
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={
                "provider": "qualys",
                "alerts_staged": result.total,
                "asset_ip": asset_ip,
                "absence_candidates": absence_candidates,
            },
        )
        integration_service.mark_sync_succeeded(integration)
        return GitHubSyncResult(total=result.total, absence_candidates=absence_candidates)
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
    "normalize_aws_inspector_finding",
    "normalize_hackerone_report",
    "normalize_bugcrowd_submission",
    "normalize_checkmarx_result",
    "normalize_fortify_issue",
    "normalize_rapid7_vulnerability",
    "normalize_wiz_issue",
    "normalize_prisma_cloud_alert",
    "stage_tenable_vulnerabilities",
    "stage_rapid7_vulnerabilities",
    "stage_crowdstrike_vulnerabilities",
    "stage_aws_security_hub_findings",
    "stage_aws_inspector_findings",
    "stage_hackerone_reports",
    "stage_bugcrowd_submissions",
    "stage_checkmarx_results",
    "stage_fortify_issues",
    "stage_azure_defender_alerts",
    "stage_gcp_scc_findings",
    "stage_burp_dast_findings",
    "stage_wiz_issues",
    "stage_prisma_cloud_alerts",
    "sync_crowdstrike_vulnerabilities",
    "sync_aws_security_hub_findings",
    "sync_aws_inspector_findings",
    "sync_hackerone_reports",
    "sync_bugcrowd_submissions",
    "sync_checkmarx_results",
    "sync_fortify_issues",
    "sync_azure_defender_alerts",
    "sync_gcp_scc_findings",
    "sync_burp_dast_findings",
    "sync_tenable_vulnerabilities",
    "sync_rapid7_vulnerabilities",
    "sync_wiz_issues",
    "sync_prisma_cloud_alerts",
    "sync_qualys_host_detections",
    "reconcile_missing_qualys_host_detections",
    "reconcile_missing_rapid7_vulnerabilities",
    "reconcile_missing_tenable_vulnerabilities",
    "reconcile_missing_sonarqube_issues",
    "related_external_alerts_for_alert",
    "mark_missing_source_alerts",
]
