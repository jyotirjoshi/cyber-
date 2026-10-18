"""Jira issue creation for findings (FR-027, FR-028).

One finding gets one ticket per provider, enforced by a unique constraint on
``(finding_id, provider)`` and checked here before the call goes out. That constraint is
the whole reason this module exists as more than a thin wrapper: duplicate tickets are the
fastest way for a development team to stop trusting an automated scanner, and a re-run of
the actions node must be able to happen without consequence.

Duplicate protection is therefore doubled deliberately, and the two halves catch different
failures. The local ``TicketLink`` row catches "Cynux already did this". The client's own
label search (``cynux-finding-<id>``) catches "Cynux did this, then the row was lost" -- a
rolled-back transaction after a successful POST, which is exactly the window where the
tracker has an issue and the database does not. Only one of the two survives a
half-completed run.

FR-028 confines the MVP to Jira. GitHub and GitLab appear in
:class:`~app.db.enums.IntegrationKind` and in the ``ticket_links`` CHECK constraint because
the schema should not need a migration to add them, but asking for one here is a clear
refusal rather than a silent fall-through to Jira.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence

import structlog
from redis.asyncio import Redis
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    CynuxError,
    IntegrationError,
    InvalidConfigurationError,
    ResourceNotFoundError,
)
from app.db.base import utcnow
from app.db.enums import AuditOutcome, IntegrationKind, Permission, Severity
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingHistory, FindingObservation
from app.db.models.finding import Finding, Remediation, TicketLink
from app.db.repository import TenantRepository, tenant_select
from app.integrations.azure_devops import AzureDevOpsClient
from app.integrations.github import GitHubClient
from app.integrations.gitlab import GitLabClient
from app.integrations.jira import SEVERITY_PRIORITY, JiraClient, JiraIssue
from app.integrations.linear import LinearClient
from app.integrations.servicenow import ServiceNowClient
from app.services import audit as audit_service
from app.services import notification as notification_service
from app.services.automation import queue_finding_event
from app.services.context import Principal
from app.services.finding import get_finding
from app.services.integration import resolve_settings
from app.services.organization import load_policy
from app.services.remediation import list_remediations

log = structlog.get_logger(__name__)

_TERMINAL_TICKET_STATUSES = frozenset({"closed", "done", "resolved", "complete", "completed"})


def is_terminal_ticket_status(status: str | None) -> bool:
    """Whether a tracker status represents completed remediation work."""
    return bool(status and status.strip().casefold() in _TERMINAL_TICKET_STATUSES)


def became_terminal_ticket_status(previous: str | None, current: str | None) -> bool:
    """Return true only for the first transition into a completed tracker state."""
    return not is_terminal_ticket_status(previous) and is_terminal_ticket_status(current)


def became_reopened_ticket_status(previous: str | None, current: str | None) -> bool:
    """Return true when a tracker moves from a terminal state back to active work."""
    return is_terminal_ticket_status(previous) and not is_terminal_ticket_status(current)

#: FR-028. Widened only when a provider is actually implemented -- an unimplemented value
#: accepted here becomes a ticket_links row pointing at nothing.
SUPPORTED_PROVIDERS: frozenset[str] = frozenset(
    {"jira", "github", "gitlab", "servicenow", "azure_devops", "linear"}
)

_MAX_DESCRIPTION_CHARS = 24_000
# Successful remote reads are cached on the ticket row for this interval. It keeps the
# worker's maintenance loop from repeatedly spending a tenant's tracker API quota.
_TICKET_STATUS_REFRESH_SECONDS = 15 * 60


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def list_tickets(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
) -> Sequence[TicketLink]:
    principal.require(Permission.FINDING_READ)
    await get_finding(session, principal, finding_id)
    canonical_ids = select(FindingObservation.canonical_finding_id).where(
        FindingObservation.organization_id == principal.organization_id,
        FindingObservation.source_record_id == finding_id,
        FindingObservation.provider == "defectdojo",
    )
    stmt = (
        tenant_select(TicketLink, principal.organization_id)
        .where(
            or_(
                TicketLink.finding_id == finding_id,
                TicketLink.canonical_finding_id.in_(canonical_ids),
            )
        )
        .order_by(TicketLink.created_at.desc())
    )
    return (await session.execute(stmt)).scalars().all()


async def find_ticket(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    *,
    provider: str = "jira",
) -> TicketLink | None:
    stmt = tenant_select(TicketLink, principal.organization_id).where(
        TicketLink.finding_id == finding_id,
        TicketLink.provider == provider,
    )
    direct = (await session.execute(stmt)).scalar_one_or_none()
    if direct is not None:
        return direct
    # A native record may have been ingested after its canonical exposure already
    # received a Jira issue. Reuse that issue rather than filing a second one.
    stmt = (
        tenant_select(TicketLink, principal.organization_id)
        .join(
            FindingObservation,
            TicketLink.canonical_finding_id == FindingObservation.canonical_finding_id,
        )
        .where(
            FindingObservation.organization_id == principal.organization_id,
            FindingObservation.source_record_id == finding_id,
            FindingObservation.provider == "defectdojo",
            TicketLink.provider == provider,
        )
        .order_by(TicketLink.created_at.desc(), TicketLink.id)
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def find_canonical_ticket(
    session: AsyncSession,
    principal: Principal,
    canonical_finding_id: uuid.UUID,
    *,
    provider: str = "jira",
) -> TicketLink | None:
    stmt = tenant_select(TicketLink, principal.organization_id).where(
        TicketLink.canonical_finding_id == canonical_finding_id,
        TicketLink.provider == provider,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_canonical_tickets(
    session: AsyncSession, principal: Principal, canonical_finding_id: uuid.UUID
) -> list[TicketLink]:
    """Show both directly linked and legacy native tickets for one exposure."""
    principal.require(Permission.FINDING_READ)
    native_ids = select(FindingObservation.source_record_id).where(
        FindingObservation.organization_id == principal.organization_id,
        FindingObservation.canonical_finding_id == canonical_finding_id,
        FindingObservation.provider == "defectdojo",
        FindingObservation.source_record_id.is_not(None),
    )
    stmt = (
        tenant_select(TicketLink, principal.organization_id)
        .where(
            or_(
                TicketLink.canonical_finding_id == canonical_finding_id,
                TicketLink.finding_id.in_(native_ids),
            )
        )
        .order_by(TicketLink.created_at.desc(), TicketLink.id)
    )
    return list((await session.execute(stmt)).scalars().all())


# ---------------------------------------------------------------------------
# Description rendering
# ---------------------------------------------------------------------------


def _severity_line(finding: Finding) -> str:
    parts = [f"*Severity:* {finding.severity}"]
    if finding.cvss_score is not None:
        parts.append(f"*CVSS:* {finding.cvss_score}")
    if finding.enrichment is not None and finding.enrichment.epss_score is not None:
        parts.append(f"*EPSS:* {finding.enrichment.epss_score:.4f}")
    if finding.enrichment is not None and finding.enrichment.in_kev is True:
        # Stated only when true. ``in_kev`` is tri-state (FR-020) and printing "KEV: no"
        # for an unreachable CISA feed would assert something Cynux does not know.
        parts.append("*CISA KEV:* actively exploited")
    return "  ".join(parts)


def build_description(
    finding: Finding,
    *,
    remediation: Remediation | None,
    settings: Settings,
) -> str:
    """Render the issue body for a developer who has this ticket and no other context.

    Ordered by what the reader needs first: where it is, how bad it is, why it matters,
    then how to fix it. The AI-generated sections are labelled as such -- a developer
    deciding how much to trust a paragraph needs to know a model wrote it, and an
    unattributed machine paragraph in a Jira ticket is how AI output gets mistaken for a
    vendor advisory.

    Third-party text is included verbatim rather than fenced: Jira is not an LLM, so
    SEC-005 does not apply, and mangling a description with prompt-injection fencing would
    make the ticket harder to read for the human it is written for.
    """
    lines: list[str] = [_severity_line(finding), ""]

    if finding.asset is not None:
        lines.append(f"*Affected asset:* {finding.asset.name}")
    if finding.component:
        version = f" {finding.component_version}" if finding.component_version else ""
        lines.append(f"*Component:* {finding.component}{version}")
    if finding.endpoint:
        lines.append(f"*Observed at:* {finding.endpoint}")
    if finding.cve_ids:
        lines.append(f"*CVE:* {', '.join(finding.cve_ids)}")
    if finding.cwe:
        lines.append(f"*CWE:* {finding.cwe}")
    if finding.scanner:
        lines.append(f"*Detected by:* {finding.scanner}")

    if finding.enrichment is not None and finding.enrichment.nvd_description:
        lines += ["", "h3. NVD description", finding.enrichment.nvd_description.strip()]

    if finding.ai_explanation:
        lines += ["", "h3. What this means (AI-generated)", finding.ai_explanation.strip()]
    if finding.ai_business_impact:
        lines += ["", "h3. Business impact (AI-generated)", finding.ai_business_impact.strip()]

    if remediation is not None:
        lines += ["", "h3. Suggested remediation (AI-generated, review before applying)"]
        lines.append(remediation.summary.strip())
        if remediation.steps:
            lines.append("")
            lines += [f"# {step.strip()}" for step in remediation.steps]
        if remediation.configuration_change:
            lines += [
                "",
                "*Configuration change:*",
                "{code}",
                remediation.configuration_change,
                "{code}",
            ]
        if remediation.code_patch:
            language = remediation.patch_language or "diff"
            lines += [
                "",
                "*Suggested patch -- advisory only, not applied by Cynux:*",
                f"{{code:{language}}}",
                remediation.code_patch,
                "{code}",
            ]
        if remediation.verification:
            lines += ["", f"*Verification:* {remediation.verification.strip()}"]
        if remediation.side_effects:
            lines += ["", f"*Possible side effects:* {remediation.side_effects.strip()}"]
        if not remediation.references:
            # FR-024. An empty reference list means nothing corroborated the guidance, and
            # the ticket should say so where the reader will see it.
            lines += [
                "",
                "_No external source could be attached to this guidance; treat it as a "
                "starting point rather than a verified fix._",
            ]

    lines += [
        "",
        "----",
        f"Cynux finding: {settings.public_base_url.rstrip('/')}/findings/{finding.id}",
        "Filed automatically by Cynux. Do not edit the cynux-finding label; it prevents "
        "duplicate tickets.",
    ]
    body = "\n".join(lines)
    if len(body) > _MAX_DESCRIPTION_CHARS:
        # Trimmed here rather than at the API boundary so the truncation is announced.
        body = body[:_MAX_DESCRIPTION_CHARS] + "\n\n_(truncated -- see the finding in Cynux)_"
    return body


def build_canonical_description(
    finding: CanonicalFinding,
    *,
    asset_name: str,
    observations: Sequence[FindingObservation],
    settings: Settings,
    include_remediation: bool = True,
) -> str:
    """Explain a unified exposure to the ticket owner without inventing scan evidence."""
    lines = [
        f"*Severity:* {finding.severity}",
        f"*Risk score:* {finding.risk_score:.1f} / 100 (prioritization estimate)",
        f"*Affected asset:* {asset_name}",
    ]
    if finding.cve_ids:
        lines.append(f"*CVE:* {', '.join(finding.cve_ids[:20])}")
    lines.extend(("", "h3. Source observations"))
    for item in observations[:20]:
        lines.append(f"- {item.provider}: {item.external_id} ({item.source_status})")
    if include_remediation and finding.remediation_plan:
        lines.extend(
            (
                "",
                "h3. Suggested remediation (AI-generated, review before applying)",
                finding.remediation_plan.strip(),
            )
        )
    lines.extend(
        (
            "",
            "----",
            f"Cynux canonical finding: {settings.public_base_url.rstrip('/')}/findings/canonical/{finding.id}",
            "Filed automatically by Cynux. Do not edit the cynux-finding label; it prevents duplicate tickets.",
        )
    )
    body = "\n".join(lines)
    return (
        body
        if len(body) <= _MAX_DESCRIPTION_CHARS
        else body[:_MAX_DESCRIPTION_CHARS] + "\n\n_(truncated -- see Cynux)_"
    )


def _labels(finding: Finding) -> list[str]:
    labels = [f"severity-{finding.severity}"]
    if finding.enrichment is not None and finding.enrichment.in_kev is True:
        labels.append("cisa-kev")
    if finding.asset is not None and finding.asset.internet_exposed:
        labels.append("internet-facing")
    # Jira rejects labels containing whitespace with a 400 that names no field, so they are
    # normalised rather than sent and debugged.
    return [label.replace(" ", "-")[:255] for label in labels]


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


def _record(
    principal: Principal,
    finding: Finding,
    issue: JiraIssue,
    *,
    project_key: str | None,
    issue_type: str | None,
    by_agent: bool,
) -> TicketLink:
    return TicketLink(
        organization_id=principal.organization_id,
        finding_id=finding.id,
        provider="jira",
        external_key=issue.key[:80],
        external_id=(issue.id or None) and issue.id[:80],
        url=issue.url[:1000] if issue.url else None,
        project_key=(project_key or None) and project_key[:40],
        issue_type=(issue_type or None) and issue_type[:60],
        external_status=issue.status[:80] if issue.status else None,
        created_by_id=principal.user_id,
        created_by_agent=by_agent,
    )


async def create_canonical_ticket(
    session: AsyncSession,
    principal: Principal,
    canonical_finding_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Redis | None = None,
    project_key: str | None = None,
    issue_type: str | None = None,
    assignee: str | None = None,
    include_remediation: bool = True,
    by_agent: bool = False,
    provider: str = "jira",
) -> TicketLink:
    """File one idempotent provider ticket for a unified exposure."""
    principal.require(Permission.TICKET_CREATE)
    if provider not in SUPPORTED_PROVIDERS:
        raise InvalidConfigurationError("Unsupported ticket provider")
    finding = await TenantRepository(
        session, CanonicalFinding, principal.organization_id
    ).get_or_404(canonical_finding_id)
    existing = await find_canonical_ticket(
        session, principal, canonical_finding_id, provider=provider
    )
    if existing is not None:
        return existing
    # Any native observation may already have filed Jira, not only the newest one.
    existing = next(
        (
            link
            for link in await list_canonical_tickets(session, principal, canonical_finding_id)
            if link.provider == provider
        ),
        None,
    )
    if existing is not None:
        return existing
    if finding.status in {"closed", "false_positive", "accepted_risk"}:
        raise ConflictError(
            "inactive canonical finding", user_message="This finding is not active for remediation."
        )

    # Reuse the richer native ticket path where a DefectDojo observation exists.
    native_id = (
        await session.execute(
            select(Finding.id)
            .join(
                FindingObservation,
                FindingObservation.source_record_id == Finding.id,
            )
            .where(
                Finding.organization_id == principal.organization_id,
                FindingObservation.organization_id == principal.organization_id,
                FindingObservation.canonical_finding_id == canonical_finding_id,
                FindingObservation.provider == "defectdojo",
            )
            .order_by(FindingObservation.last_seen_at.desc(), Finding.id)
            .limit(1)
        )
    ).scalar_one_or_none()
    if native_id is not None and provider == "jira":
        return await create_ticket(
            session,
            principal,
            native_id,
            settings=settings,
            redis=redis,
            project_key=project_key,
            issue_type=issue_type,
            assignee=assignee,
            include_remediation=include_remediation,
            by_agent=by_agent,
        )

    asset_name = (
        await session.execute(
            select(Asset.name).where(
                Asset.id == finding.asset_id,
                Asset.organization_id == principal.organization_id,
            )
        )
    ).scalar_one_or_none()
    if asset_name is None:
        raise ResourceNotFoundError("Canonical finding asset is unavailable in this organization")
    observations = (
        (
            await session.execute(
                tenant_select(FindingObservation, principal.organization_id)
                .where(FindingObservation.canonical_finding_id == canonical_finding_id)
                .order_by(FindingObservation.provider, FindingObservation.external_id)
                .limit(20)
            )
        )
        .scalars()
        .all()
    )
    kind = IntegrationKind(provider)
    scoped = await resolve_settings(session, principal, kind, settings=settings)
    client = None
    try:
        description = build_canonical_description(
            finding,
            asset_name=asset_name,
            observations=observations,
            settings=scoped,
            include_remediation=include_remediation,
        )
        if provider == "jira":
            client = JiraClient(scoped, redis)
            issue = await client.create_issue(
                summary=f"[{finding.severity.upper()}] {finding.title}",
                description=description,
                finding_id=str(canonical_finding_id),
                priority=SEVERITY_PRIORITY.get(Severity(finding.severity)),
                labels=[f"severity-{finding.severity}"],
                issue_type=issue_type,
                project_key=project_key,
                assignee_account_id=assignee,
            )
        elif provider == "github":
            client = GitHubClient(scoped, redis)
            issue = await client.create_issue(
                summary=f"[{finding.severity.upper()}] {finding.title}",
                description=description,
                finding_id=str(canonical_finding_id),
                labels=[f"severity-{finding.severity}"],
            )
        elif provider == "gitlab":
            client = GitLabClient(scoped, redis)
            issue = await client.create_issue(
                summary=f"[{finding.severity.upper()}] {finding.title}",
                description=description,
                finding_id=str(canonical_finding_id),
                labels=[f"severity-{finding.severity}"],
            )
        elif provider == "servicenow":
            client = ServiceNowClient(scoped, redis)
            issue = await client.create_issue(
                summary=f"[{finding.severity.upper()}] {finding.title}",
                description=description,
                finding_id=str(canonical_finding_id),
                labels=[f"severity-{finding.severity}"],
            )
        elif provider == "azure_devops":
            client = AzureDevOpsClient(scoped, redis)
            issue = await client.create_issue(
                summary=f"[{finding.severity.upper()}] {finding.title}",
                description=description,
                finding_id=str(canonical_finding_id),
                labels=[f"severity-{finding.severity}"],
            )
        elif provider == "linear":
            client = LinearClient(scoped, redis)
            issue = await client.create_issue(summary=f"[{finding.severity.upper()}] {finding.title}", description=description, finding_id=str(canonical_finding_id), labels=[f"severity-{finding.severity}"])
        else:  # Guard the enum-to-client boundary if a caller bypasses validation.
            raise InvalidConfigurationError("Unsupported ticket provider")
    except IntegrationError as exc:
        await audit_service.record(
            session,
            action=audit_service.AuditAction.TICKET_CREATE,
            principal=principal,
            resource_type="canonical_finding",
            resource_id=canonical_finding_id,
            outcome=AuditOutcome.FAILURE,
            reason=exc.user_message,
            detail={"provider": provider, "by_agent": by_agent},
        )
        raise
    finally:
        if client is not None:
            await client.aclose()
    resolved_project_key = project_key or (
        scoped.jira.project_key if provider == "jira" else None
    )
    resolved_issue_type = issue_type or (scoped.jira.issue_type if provider == "jira" else None)
    link = TicketLink(
        organization_id=principal.organization_id,
        canonical_finding_id=canonical_finding_id,
        finding_id=None,
        provider=provider,
        external_key=issue.key[:80],
        external_id=issue.id[:80] if issue.id else None,
        url=issue.url[:1000] if issue.url else None,
        project_key=resolved_project_key[:40] if resolved_project_key else None,
        issue_type=resolved_issue_type[:60] if resolved_issue_type else None,
        external_status=issue.status[:80] if issue.status else None,
        created_by_id=principal.user_id,
        created_by_agent=by_agent,
    )
    session.add(link)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.TICKET_CREATE,
        principal=principal,
        resource_type="canonical_finding",
        resource_id=canonical_finding_id,
        detail={"provider": provider, "issue_key": issue.key, "by_agent": by_agent},
    )
    return link


async def create_ticket(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Redis | None = None,
    project_key: str | None = None,
    issue_type: str | None = None,
    assignee: str | None = None,
    include_remediation: bool = True,
    provider: str = "jira",
    by_agent: bool = False,
    notify: bool = True,
) -> TicketLink:
    """File a Jira issue for a finding, or return the existing link (FR-027).

    Idempotent in both directions -- see the module docstring on why the local row and the
    remote label search are both checked. A caller that gets a ``TicketLink`` back cannot
    tell whether this call created it, which is the point: the actions node re-runs after a
    resume and must not file a second issue.

    Does not commit. The link row joins the caller's transaction so the ticket and the
    audit entry that records it land together.
    """
    principal.require(Permission.TICKET_CREATE)
    if provider not in SUPPORTED_PROVIDERS:
        # FR-028. Explicit rather than a silent fall-through to Jira: a ticket filed in the
        # wrong tracker is worse than no ticket.
        raise InvalidConfigurationError(
            f"Ticket provider '{provider}' is not supported in this release.",
            user_message=(
                f"Cynux cannot file tickets in {provider} yet. Jira is the only supported "
                "issue tracker in this release."
            ),
            context={"supported": sorted(SUPPORTED_PROVIDERS)},
        )

    finding = await get_finding(session, principal, finding_id, detail=True)

    existing = await find_ticket(session, principal, finding_id, provider=provider)
    if existing is not None:
        log.info(
            "ticket.already_linked",
            finding_id=str(finding_id),
            issue_key=existing.external_key,
        )
        return existing

    if provider != "jira":
        raise InvalidConfigurationError(
            "Native finding tickets currently require Jira; use canonical ticketing for repository trackers."
        )
    scoped = await resolve_settings(session, principal, IntegrationKind.JIRA, settings=settings)
    client = JiraClient(scoped, redis)

    remediation: Remediation | None = None
    if include_remediation:
        candidates = await list_remediations(session, principal, finding_id)
        # Newest first from the query. A reviewed remediation wins over a newer unreviewed
        # one: a human signed off on it, which is the strongest signal available.
        remediation = next(
            (r for r in candidates if r.reviewed_at is not None),
            candidates[0] if candidates else None,
        )

    description = build_description(finding, remediation=remediation, settings=scoped)
    priority = SEVERITY_PRIORITY.get(finding.severity_enum)

    try:
        issue = await client.create_issue(
            summary=f"[{finding.severity.upper()}] {finding.title}",
            description=description,
            finding_id=str(finding.id),
            priority=priority,
            labels=_labels(finding),
            issue_type=issue_type,
            project_key=project_key,
            assignee_account_id=assignee,
        )
    except IntegrationError as exc:
        await audit_service.record(
            session,
            action=audit_service.AuditAction.TICKET_CREATE,
            principal=principal,
            resource_type="finding",
            resource_id=finding.id,
            outcome=AuditOutcome.FAILURE,
            # ``user_message`` only. A Jira error body can echo the request headers back,
            # which is how an API token ends up in an audit row (SEC-002).
            reason=exc.user_message,
            detail={"provider": provider, "by_agent": by_agent},
        )
        raise
    finally:
        await client.aclose()

    link = _record(
        principal,
        finding,
        issue,
        project_key=project_key or scoped.jira.project_key,
        issue_type=issue_type or scoped.jira.issue_type,
        by_agent=by_agent,
    )
    session.add(link)
    await session.flush()

    await audit_service.record(
        session,
        action=audit_service.AuditAction.TICKET_CREATE,
        principal=principal,
        resource_type="finding",
        resource_id=finding.id,
        outcome=AuditOutcome.SUCCESS,
        detail={
            "provider": provider,
            "issue_key": issue.key,
            "url": issue.url,
            "by_agent": by_agent,
            "with_remediation": remediation is not None,
        },
    )

    if notify:
        await notification_service.notify_ticket_created(
            session,
            principal,
            finding_id=finding.id,
            ticket_key=issue.key,
            ticket_url=issue.url or "",
            settings=settings,
            redis=redis,
        )

    log.info("ticket.created", finding_id=str(finding.id), issue_key=issue.key)
    return link


async def apply_ticket_status_transition(
    session: AsyncSession,
    principal: Principal,
    link: TicketLink,
    *,
    current_status: str | None,
    provider_updated_at: dt.datetime | None,
    url: str | None,
    settings: Settings,
    redis: Redis | None = None,
) -> TicketLink:
    """Apply one confirmed provider state through the canonical lifecycle exactly once."""
    previous_status = link.external_status
    link.external_status = current_status[:80] if current_status else None
    link.updated_at = utcnow()
    if provider_updated_at is not None:
        link.external_updated_at = provider_updated_at
    if url:
        link.url = url[:1000]
    closed_transition = became_terminal_ticket_status(previous_status, link.external_status)
    reopened_transition = became_reopened_ticket_status(previous_status, link.external_status)
    if closed_transition:
        link.closure_generation = int(getattr(link, "closure_generation", 0) or 0) + 1
    if (closed_transition or reopened_transition) and link.canonical_finding_id:
        finding = (
            await session.execute(
                tenant_select(CanonicalFinding, principal.organization_id).where(
                    CanonicalFinding.id == link.canonical_finding_id
                )
            )
        ).scalar_one_or_none()
        if closed_transition and finding is not None:
            asset = (
                await session.execute(
                    tenant_select(Asset, principal.organization_id).where(
                        Asset.id == finding.asset_id
                    )
                )
            ).scalar_one_or_none()
            if asset is not None:
                await queue_finding_event(
                    session,
                    finding=finding,
                    asset=asset,
                    trigger="ticket.closed",
                    event_key_suffix=f":{link.id}:{link.closure_generation}",
                )
            try:
                from app.services.automation import schedule_ticket_close_retest

                await schedule_ticket_close_retest(
                    session,
                    principal=Principal.for_system(
                        organization_id=principal.organization_id
                    ),
                    finding=finding,
                    authorization_reference=(
                        f"ticket:{link.provider}:{link.id}:{link.closure_generation}"
                    ),
                    settings=settings,
                )
            except (CynuxError, ValueError) as exc:
                log.info(
                    "ticket.close_retest_not_scheduled",
                    ticket_id=str(link.id),
                    reason=type(exc).__name__,
                )
        elif (
            reopened_transition
            and finding is not None
            and finding.status in {"closed", "mitigated"}
        ):
            previous_finding_status = finding.status
            finding.status = "reopened"
            finding.status_version += 1
            finding.closed_at = None
            now = utcnow()
            session.add(
                FindingHistory(
                    id=uuid.uuid4(),
                    organization_id=principal.organization_id,
                    canonical_finding_id=finding.id,
                    previous_status=previous_finding_status,
                    new_status="reopened",
                    reason=f"Linked {link.provider} ticket reopened remotely",
                    occurred_at=now,
                )
            )
            await audit_service.record(
                session,
                action=audit_service.AuditAction.FINDING_STATUS_CHANGE,
                principal=principal,
                resource_type="canonical_finding",
                resource_id=finding.id,
                detail={
                    "from": previous_finding_status,
                    "to": "reopened",
                    "reason": "linked_ticket_reopened",
                    "ticket_id": str(link.id),
                    "provider": link.provider,
                },
            )
            asset = (
                await session.execute(
                    tenant_select(Asset, principal.organization_id).where(
                        Asset.id == finding.asset_id
                    )
                )
            ).scalar_one_or_none()
            if asset is not None:
                await queue_finding_event(
                    session,
                    finding=finding,
                    asset=asset,
                    trigger="finding.updated",
                    event_key_suffix=f":version:{finding.status_version}",
                )
    if closed_transition:
        await notification_service.notify_ticket_closed(
            session,
            principal,
            ticket_id=link.id,
            closure_generation=link.closure_generation,
            ticket_key=link.external_key,
            ticket_url=link.url or "",
            settings=settings,
            redis=redis,
        )
    return link


async def refresh_ticket_status(
    session: AsyncSession,
    principal: Principal,
    ticket_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> TicketLink:
    """Pull a confirmed tracker state, or propagate a provider failure.

    Used by explicit UI/agent actions and the bounded maintenance poller. A failed
    lookup must never masquerade as successful work using an old cached status.
    Serialize refreshes so one close transition produces one closure generation.
    """
    principal.require(Permission.FINDING_READ)
    stmt = (
        tenant_select(TicketLink, principal.organization_id)
        .where(TicketLink.id == ticket_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    link = (await session.execute(stmt)).scalar_one_or_none()
    if link is None:
        raise ResourceNotFoundError(
            f"Ticket link {ticket_id} not found in this organization.",
            context={"ticket_id": str(ticket_id)},
        )

    if link.provider not in SUPPORTED_PROVIDERS:
        raise InvalidConfigurationError("Unsupported ticket provider")
    scoped = await resolve_settings(
        session, principal, IntegrationKind(link.provider), settings=settings
    )
    if link.provider == "jira":
        client = JiraClient(scoped, redis)
    elif link.provider == "github":
        client = GitHubClient(scoped, redis)
    elif link.provider == "gitlab":
        client = GitLabClient(scoped, redis)
    elif link.provider == "servicenow":
        client = ServiceNowClient(scoped, redis)
    elif link.provider == "azure_devops":
        client = AzureDevOpsClient(scoped, redis)
    elif link.provider == "linear":
        client = LinearClient(scoped, redis)
    else:  # Defensive: SUPPORTED_PROVIDERS was checked above.
        raise InvalidConfigurationError("Unsupported ticket provider")
    try:
        issue = await client.get_issue(link.external_key)
    except IntegrationError as exc:
        log.warning(
            "ticket.status_refresh_failed",
            ticket_id=str(ticket_id),
            reason=exc.user_message,
        )
        raise
    finally:
        await client.aclose()

    return await apply_ticket_status_transition(
        session,
        principal,
        link,
        current_status=issue.status,
        provider_updated_at=None,
        url=issue.url,
        settings=settings,
        redis=redis,
    )


async def push_ticket_status(
    session: AsyncSession,
    principal: Principal,
    ticket_id: uuid.UUID,
    *,
    closed: bool,
    comment: str | None,
    settings: Settings,
    redis: Redis | None = None,
) -> TicketLink:
    """Push an explicit close/reopen command to a linked provider, then record it locally."""
    principal.require(Permission.FINDING_REMEDIATE)
    link = await session.scalar(
        tenant_select(TicketLink, principal.organization_id)
        .where(TicketLink.id == ticket_id)
        .with_for_update()
    )
    if link is None:
        raise ResourceNotFoundError("Ticket link not found")
    if link.provider not in {
        "jira",
        "github",
        "gitlab",
        "servicenow",
        "azure_devops",
    }:
        raise InvalidConfigurationError(
            "Ticket provider does not support lifecycle writes",
            user_message="This ticket provider does not support status updates.",
        )

    scoped = await resolve_settings(
        session,
        principal,
        IntegrationKind(link.provider),
        settings=settings,
        require=True,
    )
    client: JiraClient | GitHubClient | GitLabClient | ServiceNowClient | AzureDevOpsClient
    if link.provider == "jira":
        client = JiraClient(scoped, redis)
    elif link.provider == "github":
        client = GitHubClient(scoped, redis)
    elif link.provider == "gitlab":
        client = GitLabClient(scoped, redis)
    elif link.provider == "servicenow":
        client = ServiceNowClient(scoped, redis)
    else:
        client = AzureDevOpsClient(scoped, redis)

    try:
        await client.set_issue_state(link.external_key, closed=closed)
        clean_comment = (comment or "").strip()
        if clean_comment:
            await client.add_comment(link.external_key, clean_comment[:16_000])
    finally:
        await client.aclose()

    await apply_ticket_status_transition(
        session,
        principal,
        link,
        current_status="closed" if closed else "open",
        provider_updated_at=utcnow(),
        url=None,
        settings=settings,
        redis=redis,
    )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.TICKET_STATUS_PUSH,
        principal=principal,
        resource_type="ticket_link",
        resource_id=link.id,
        detail={
            "provider": link.provider,
            "external_key": link.external_key,
            "requested_status": "closed" if closed else "open",
            "comment_added": bool((comment or "").strip()),
        },
    )
    return link


async def refresh_due_ticket_statuses(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Redis | None = None,
    limit: int = 100,
) -> int:
    """Refresh a rate-bounded batch of linked tickets across tenants.

    Reusing :func:`refresh_ticket_status` preserves the existing terminal-ticket
    transition behavior: a remote closure queues ``ticket.closed`` automation, which
    can schedule the authorized evidence-based retest already supported by Cynux.  Closed
    tickets remain in the rotation because external trackers can reopen them; otherwise a
    later close would never begin a fresh remediation-verification cycle.
    """
    cutoff = utcnow() - dt.timedelta(seconds=_TICKET_STATUS_REFRESH_SECONDS)
    candidates = list(
        (
            await session.execute(
                select(TicketLink)
                .where(
                    TicketLink.updated_at < cutoff,
                )
                .order_by(TicketLink.updated_at.asc(), TicketLink.id.asc())
                .limit(max(1, min(limit, 500)))
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()
    )
    refreshed = 0
    for link in candidates:
        try:
            await refresh_ticket_status(
                session,
                Principal.for_system(organization_id=link.organization_id),
                link.id,
                settings=settings,
                redis=redis,
            )
            refreshed += 1
        except CynuxError as exc:
            # An unconfigured provider must not block other tenants. Advance the local
            # poll window to prevent the same failed link consuming every pulse.
            link.updated_at = utcnow()
            log.info(
                "ticket.background_status_refresh_skipped",
                ticket_id=str(link.id),
                provider=link.provider,
                error_code=exc.code,
            )
    return refreshed


async def comment_on_ticket(
    session: AsyncSession,
    principal: Principal,
    ticket_id: uuid.UUID,
    text: str,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> None:
    """Add a comment to an existing ticket.

    Used when a re-scan confirms a finding is still present. Deliberately not exposed as an
    agent tool: an agent that can write into a tracker at will produces comment spam on
    every re-run, and the value of a Cynux comment comes from its rarity.
    """
    principal.require(Permission.TICKET_CREATE)
    stmt = tenant_select(TicketLink, principal.organization_id).where(TicketLink.id == ticket_id)
    link = (await session.execute(stmt)).scalar_one_or_none()
    if link is None:
        raise ResourceNotFoundError(
            f"Ticket link {ticket_id} not found in this organization.",
            context={"ticket_id": str(ticket_id)},
        )
    if link.provider not in SUPPORTED_PROVIDERS:
        # The provider-specific clients intentionally expose only operations they can
        # perform correctly.  Never fall through to Jira credentials for another
        # provider: that would either fail confusingly or target an unrelated issue.
        raise InvalidConfigurationError(
            "Ticket comments are not available for this provider yet.",
            user_message="Adding a comment is not supported for this ticket provider.",
        )

    scoped = await resolve_settings(
        session, principal, IntegrationKind(link.provider), settings=settings
    )
    if link.provider == "jira":
        client = JiraClient(scoped, redis)
    elif link.provider == "github":
        client = GitHubClient(scoped, redis)
    elif link.provider == "gitlab":
        client = GitLabClient(scoped, redis)
    elif link.provider == "servicenow":
        client = ServiceNowClient(scoped, redis)
    elif link.provider == "azure_devops":
        client = AzureDevOpsClient(scoped, redis)
    else:
        client = LinearClient(scoped, redis)
    try:
        await client.add_comment(link.external_key, text[:16_000])
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Bulk selection for the agent's actions node
# ---------------------------------------------------------------------------


async def ticket_candidates(
    session: AsyncSession,
    principal: Principal,
    assessment_id: uuid.UUID,
    *,
    organization_policy_floor: Severity | None = None,
    limit: int = 15,
) -> Sequence[Finding]:
    """Findings in an assessment that warrant a ticket, worst first.

    The floor comes from the organization's ``ticket_min_severity`` policy rather than a
    constant, because the severity at which a team wants a Jira issue is a workflow
    decision. Findings that already have a link are excluded in SQL so ``limit`` bounds
    tickets actually filed rather than rows examined.
    """
    floor = organization_policy_floor or Severity.HIGH
    ranked = [s.value for s in Severity if s.rank >= floor.rank]
    # A plain ``select`` rather than ``tenant_select``: the helper takes a model, and the
    # tenant filter is spelled out here because this is a column subquery, not a row read.
    linked = select(TicketLink.finding_id).where(
        TicketLink.organization_id == principal.organization_id,
        TicketLink.finding_id.is_not(None),
    )
    canonical_linked = (
        select(FindingObservation.source_record_id)
        .join(
            TicketLink,
            TicketLink.canonical_finding_id == FindingObservation.canonical_finding_id,
        )
        .where(
            FindingObservation.organization_id == principal.organization_id,
            FindingObservation.provider == "defectdojo",
            FindingObservation.source_record_id.is_not(None),
            TicketLink.organization_id == principal.organization_id,
            TicketLink.provider == "jira",
        )
    )
    stmt = (
        tenant_select(Finding, principal.organization_id)
        .where(
            Finding.assessment_id == assessment_id,
            Finding.severity.in_(ranked),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
            Finding.id.notin_(linked),
            Finding.id.notin_(canonical_linked),
        )
        .order_by(Finding.risk_score.desc().nullslast(), Finding.created_at.asc())
        .limit(limit)
    )
    return (await session.execute(stmt)).scalars().all()


async def policy_ticket_floor(
    session: AsyncSession,
    principal: Principal,
) -> Severity | None:
    """The organization's ``ticket_min_severity``, or ``None`` when ticketing is off.

    ``None`` is meaningful: an organization that has not set a floor has not opted into
    automatic ticket creation, and defaulting it to a severity would have the agent filing
    Jira issues nobody asked for on its first run.
    """
    from app.db.models.identity import Organization

    organization = await session.get(Organization, principal.organization_id)
    if organization is None:
        return None
    return load_policy(organization).ticket_min_severity


__all__ = [
    "SUPPORTED_PROVIDERS",
    "build_description",
    "build_canonical_description",
    "apply_ticket_status_transition",
    "comment_on_ticket",
    "create_ticket",
    "create_canonical_ticket",
    "find_ticket",
    "find_canonical_ticket",
    "list_canonical_tickets",
    "list_tickets",
    "policy_ticket_floor",
    "refresh_ticket_status",
    "refresh_due_ticket_statuses",
    "push_ticket_status",
    "ticket_candidates",
]
