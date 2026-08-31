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

import uuid
from collections.abc import Sequence

import structlog
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import IntegrationError, InvalidConfigurationError, ResourceNotFoundError
from app.db.enums import AuditOutcome, IntegrationKind, Permission, Severity
from app.db.models.finding import Finding, Remediation, TicketLink
from app.db.repository import tenant_select
from app.integrations.jira import SEVERITY_PRIORITY, JiraClient, JiraIssue
from app.services import audit as audit_service
from app.services import notification as notification_service
from app.services.context import Principal
from app.services.finding import get_finding
from app.services.integration import resolve_settings
from app.services.organization import load_policy
from app.services.remediation import list_remediations

log = structlog.get_logger(__name__)

#: FR-028. Widened only when a provider is actually implemented -- an unimplemented value
#: accepted here becomes a ticket_links row pointing at nothing.
SUPPORTED_PROVIDERS: frozenset[str] = frozenset({"jira"})

_MAX_DESCRIPTION_CHARS = 24_000


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
    stmt = (
        tenant_select(TicketLink, principal.organization_id)
        .where(TicketLink.finding_id == finding_id)
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
    return (await session.execute(stmt)).scalar_one_or_none()


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


async def refresh_ticket_status(
    session: AsyncSession,
    principal: Principal,
    ticket_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> TicketLink:
    """Pull the tracker's current state onto the link row.

    On demand rather than polled. Cynux is not the system of record for issue state, and a
    background poller over every open ticket would spend an organization's Jira rate limit
    keeping a column fresh that only matters when somebody is looking at it.

    A tracker error is swallowed: a stale status is a better answer to "show me this
    finding" than an error page.
    """
    principal.require(Permission.FINDING_READ)
    stmt = tenant_select(TicketLink, principal.organization_id).where(TicketLink.id == ticket_id)
    link = (await session.execute(stmt)).scalar_one_or_none()
    if link is None:
        raise ResourceNotFoundError(
            f"Ticket link {ticket_id} not found in this organization.",
            context={"ticket_id": str(ticket_id)},
        )

    scoped = await resolve_settings(session, principal, IntegrationKind.JIRA, settings=settings)
    client = JiraClient(scoped, redis)
    try:
        issue = await client.get_issue(link.external_key)
    except IntegrationError as exc:
        log.warning(
            "ticket.status_refresh_failed",
            ticket_id=str(ticket_id),
            reason=exc.user_message,
        )
        return link
    finally:
        await client.aclose()

    link.external_status = issue.status[:80] if issue.status else None
    if issue.url:
        link.url = issue.url[:1000]
    return link


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

    scoped = await resolve_settings(session, principal, IntegrationKind.JIRA, settings=settings)
    client = JiraClient(scoped, redis)
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
        TicketLink.organization_id == principal.organization_id
    )
    stmt = (
        tenant_select(Finding, principal.organization_id)
        .where(
            Finding.assessment_id == assessment_id,
            Finding.severity.in_(ranked),
            Finding.is_false_positive.is_(False),
            Finding.is_duplicate.is_(False),
            Finding.id.notin_(linked),
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
    "comment_on_ticket",
    "create_ticket",
    "find_ticket",
    "list_tickets",
    "policy_ticket_floor",
    "refresh_ticket_status",
    "ticket_candidates",
]
