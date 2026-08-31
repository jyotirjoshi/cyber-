"""Outbound notifications for the six events users care about (FR-029, FR-032).

The ordering here is deliberate and is the whole design: **a row is written before delivery
is attempted, and delivery failure never propagates to the caller.**

Every notification in Cynux is a side effect of something more important -- an assessment
starting, an approval blocking a run, a critical finding landing. If a Slack outage could
raise out of :func:`dispatch`, a transient 503 from Slack would fail the assessment that
was merely trying to mention itself. So the row is the durable artifact and the send is
best-effort: a ``pending`` row that never became ``sent`` is a visible, queryable backlog,
whereas an exception swallowed at the call site is nothing at all.

Three consequences worth stating:

**Suppression is recorded, not silent.** When an organization's policy filters an event out
(a high-severity finding on a workspace configured for critical only) the row is still
written, with ``status=suppressed`` and a ``suppressed_reason``. "Why didn't I get an
alert?" is then answerable from the database instead of from a support call. This is also
why a suppressed notification audits as ``SUCCESS`` with ``detail={"skipped": True}`` --
``AuditOutcome`` has no ``SKIPPED`` member, and calling a correctly-applied policy a
``FAILURE`` would poison every alerting query built on the audit log.

**Deduplication is a pre-read, not a caught constraint violation.** ``notifications`` has a
unique index on ``(organization_id, dedupe_key)``, but relying on the ``IntegrityError``
would poison the caller's transaction -- and the caller is mid-assessment with real work to
commit. The existing row is looked up first instead.

**Websocket rows are delivered by existing.** :class:`~app.db.enums.NotificationChannel`
has a ``websocket`` member, but a notification is organization-scoped while the event bus is
session-scoped, so there is no socket to push an org-wide alert down. An in-app
notification is therefore *stored* and the dashboard reads it; the row is the delivery,
which is why those go straight to ``sent``. Live agent progress is a different mechanism
entirely (:mod:`app.services.events`) and deliberately does not route through here.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import structlog
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import CynuxError
from app.db.base import utcnow
from app.db.enums import (
    AuditOutcome,
    IntegrationKind,
    NotificationChannel,
    NotificationEvent,
    NotificationStatus,
    Severity,
)
from app.db.models.identity import Organization
from app.db.models.notification import Notification
from app.db.repository import tenant_select
from app.integrations.email import EmailSender, html_to_text
from app.integrations.slack import (
    SlackClient,
    context_line,
    escape_slack,
    link_button,
    section,
    severity_emoji,
)
from app.schemas.organization import OrgPolicy
from app.services import audit as audit_service
from app.services.audit import AuditAction
from app.services.context import Principal
from app.services.integration import resolve_settings
from app.services.organization import load_policy

log = structlog.get_logger(__name__)

#: Events that bypass the severity floor. An approval request is a *block* -- the run is
#: stopped until a human answers -- and a failure means the user's request did not happen.
#: Filtering either on severity would silence the two events with no alternative signal.
_ALWAYS_DELIVER: frozenset[NotificationEvent] = frozenset(
    {
        NotificationEvent.APPROVAL_REQUIRED,
        NotificationEvent.ASSESSMENT_FAILED,
    }
)

#: Which channels each event goes to by default. Assessment start is in-app only: it is
#: confirmation of something the user just did, and paging a channel about it is how
#: an integration gets muted.
_DEFAULT_CHANNELS: dict[NotificationEvent, tuple[NotificationChannel, ...]] = {
    NotificationEvent.ASSESSMENT_STARTED: (NotificationChannel.WEBSOCKET,),
    NotificationEvent.APPROVAL_REQUIRED: (
        NotificationChannel.WEBSOCKET,
        NotificationChannel.SLACK,
        NotificationChannel.EMAIL,
    ),
    NotificationEvent.CRITICAL_FINDING: (
        NotificationChannel.WEBSOCKET,
        NotificationChannel.SLACK,
    ),
    NotificationEvent.ASSESSMENT_COMPLETED: (
        NotificationChannel.WEBSOCKET,
        NotificationChannel.SLACK,
        NotificationChannel.EMAIL,
    ),
    NotificationEvent.ASSESSMENT_FAILED: (
        NotificationChannel.WEBSOCKET,
        NotificationChannel.SLACK,
        NotificationChannel.EMAIL,
    ),
    NotificationEvent.TICKET_CREATED: (NotificationChannel.WEBSOCKET,),
}

_MAX_DEDUPE_KEY = 300
_MAX_SUBJECT = 500


@dataclass(frozen=True, slots=True)
class NotificationContent:
    """One notification rendered for every transport that might carry it.

    Rendered once by the caller rather than per channel, because the caller is the only
    party that knows the domain facts. ``blocks`` and ``html`` are optional refinements:
    a channel with neither falls back to ``body``, so a new event type is useful before
    it is pretty.
    """

    subject: str
    body: str
    blocks: list[dict[str, Any]] = field(default_factory=list)
    html: str | None = None
    #: Deep link into Cynux. Appended to Slack as a button and to email as a paragraph.
    link: str | None = None


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


async def _policy(session: AsyncSession, organization_id: uuid.UUID) -> OrgPolicy:
    """Load the organization's notification policy.

    Fetched by primary key rather than through ``tenant_select`` because
    ``organizations`` *is* the tenant boundary, not a row inside one, and the id comes
    from the authenticated principal. Falls back to defaults if the row is somehow gone:
    a missing organization must not stop an in-flight assessment from reporting itself.
    """
    organization = await session.get(Organization, organization_id)
    if organization is None:
        log.warning("notification.organization_missing", organization_id=str(organization_id))
        return OrgPolicy()
    return load_policy(organization)


def _suppression_reason(
    event: NotificationEvent,
    severity: Severity | None,
    policy: OrgPolicy,
) -> str | None:
    if event in _ALWAYS_DELIVER or severity is None:
        return None
    if severity.rank < policy.notify_min_severity.rank:
        return (
            f"severity {severity.value} is below the configured floor "
            f"{policy.notify_min_severity.value}"
        )
    return None


def _recipients(
    channel: NotificationChannel,
    *,
    policy: OrgPolicy,
    slack_default: str | None,
    extra_emails: Sequence[str],
    user_id: uuid.UUID | None,
) -> list[str]:
    if channel is NotificationChannel.SLACK:
        target = policy.slack_channel or slack_default
        return [target] if target else []
    if channel is NotificationChannel.EMAIL:
        # Ordered-unique: the requester should be first, and duplicates would produce two
        # rows whose dedupe keys differ only by position.
        seen: dict[str, None] = {}
        for address in [*extra_emails, *(str(a) for a in policy.email_recipients)]:
            if address:
                seen.setdefault(address.strip().lower(), None)
        return list(seen)
    # In-app: addressed to the user who will read it, or to the organization at large.
    return [str(user_id)] if user_id is not None else ["*"]


def _dedupe_key(
    event: NotificationEvent,
    resource_id: str | None,
    channel: NotificationChannel,
    recipient: str,
) -> str:
    return f"{event.value}:{resource_id or '-'}:{channel.value}:{recipient}"[:_MAX_DEDUPE_KEY]


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


def _slack_blocks(content: NotificationContent, severity: Severity | None) -> list[dict[str, Any]]:
    """Build Slack blocks, escaping anything that came from a scanner (SEC-005).

    ``escape_slack`` is not optional here. Notification bodies quote finding titles, and a
    finding titled ``<!channel>`` would otherwise page an entire workspace on the strength
    of a scanner's output.
    """
    if content.blocks:
        return content.blocks
    prefix = f"{severity_emoji(severity)} " if severity is not None else ""
    blocks: list[dict[str, Any]] = [
        section(f"*{prefix}{escape_slack(content.subject)}*\n{escape_slack(content.body)}")
    ]
    if content.link:
        blocks.append(link_button("Open in Cynux", content.link))
    blocks.append(context_line("Sent by Cynux"))
    return blocks


def _email_html(content: NotificationContent) -> str:
    if content.html:
        return content.html
    # ``body`` is plain text that may quote scanner output, so it is escaped rather than
    # interpolated: the email client would otherwise render smuggled markup.
    escaped = (
        content.body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    ).replace("\n", "<br>")
    link = f'<p><a href="{content.link}">Open in Cynux</a></p>' if content.link else ""
    return f"<h2>{content.subject}</h2><p>{escaped}</p>{link}"


async def _deliver(
    session: AsyncSession,
    principal: Principal,
    notification: Notification,
    content: NotificationContent,
    *,
    severity: Severity | None,
    settings: Settings,
    redis: Redis | None,
) -> None:
    """Attempt one delivery and record the outcome on the row.

    Never raises. See the module docstring: the caller has real work to commit and a
    provider outage is not its problem.
    """
    channel = notification.channel_enum
    notification.attempts += 1
    try:
        if channel is NotificationChannel.WEBSOCKET:
            # Storing it *is* delivering it. See the module docstring.
            pass
        elif channel is NotificationChannel.SLACK:
            scoped = await resolve_settings(
                session, principal, IntegrationKind.SLACK, settings=settings
            )
            await SlackClient(scoped, redis).notify(
                content.subject,
                channel=notification.recipient,
                blocks=_slack_blocks(content, severity),
            )
        elif channel is NotificationChannel.EMAIL:
            scoped = await resolve_settings(
                session, principal, IntegrationKind.EMAIL, settings=settings
            )
            html = _email_html(content)
            await EmailSender(scoped).send(
                notification.recipient,
                notification.subject or content.subject,
                html,
                html_to_text(html),
            )
    except CynuxError as exc:
        notification.status = NotificationStatus.FAILED.value
        # The user-safe message only. A provider response body can echo a credential back
        # (SEC-002), and this column is rendered in the UI.
        notification.last_error = exc.user_message
        log.warning(
            "notification.delivery_failed",
            notification_id=str(notification.id),
            channel=channel.value,
            code=exc.code,
        )
        return
    except Exception as exc:  # - an unexpected client bug is still a failed send
        notification.status = NotificationStatus.FAILED.value
        notification.last_error = "Delivery failed unexpectedly."
        log.error(
            "notification.delivery_error",
            notification_id=str(notification.id),
            channel=channel.value,
            error=type(exc).__name__,
        )
        return

    notification.status = NotificationStatus.SENT.value
    notification.sent_at = utcnow()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def dispatch(
    session: AsyncSession,
    principal: Principal,
    *,
    event: NotificationEvent,
    content: NotificationContent,
    settings: Settings,
    redis: Redis | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    severity: Severity | None = None,
    channels: Sequence[NotificationChannel] | None = None,
    extra_emails: Sequence[str] = (),
    recipient_user_id: uuid.UUID | None = None,
) -> list[Notification]:
    """Record and attempt one notification across every applicable channel.

    Returns the rows it created, including suppressed and failed ones -- the caller may
    want to report "3 sent, 1 suppressed" and cannot reconstruct that from a boolean.
    Rows that already existed for this ``(event, resource, channel, recipient)`` are
    skipped and not returned: a resumed assessment re-running a node must not re-alert.

    Does not commit. The rows join the caller's transaction, which is what makes
    "notification recorded" and "assessment advanced" atomic.
    """
    policy = await _policy(session, principal.organization_id)
    suppressed_reason = _suppression_reason(event, severity, policy)
    targets = tuple(channels) if channels is not None else _DEFAULT_CHANNELS.get(event, ())

    # The client is constructed only to read its configured default channel, which is a
    # settings lookup and does no I/O.
    slack_default = SlackClient(settings).default_channel

    created: list[Notification] = []
    for channel in targets:
        for recipient in _recipients(
            channel,
            policy=policy,
            slack_default=slack_default,
            extra_emails=extra_emails,
            user_id=recipient_user_id or principal.user_id,
        ):
            key = _dedupe_key(event, resource_id, channel, recipient)
            if await _already_recorded(session, principal.organization_id, key):
                log.debug("notification.deduplicated", event=event.value, channel=channel.value)
                continue

            notification = Notification(
                organization_id=principal.organization_id,
                event=event.value,
                channel=channel.value,
                status=NotificationStatus.PENDING.value,
                recipient=recipient[:320],
                recipient_user_id=recipient_user_id or principal.user_id,
                subject=content.subject[:_MAX_SUBJECT],
                body=content.body,
                payload={"link": content.link} if content.link else {},
                resource_type=resource_type,
                resource_id=resource_id[:80] if resource_id else None,
                dedupe_key=key,
            )
            session.add(notification)
            # Flushed per row so ``notification.id`` is available for the delivery log line
            # and so a constraint violation names the row that caused it.
            await session.flush()

            if suppressed_reason is not None:
                notification.status = NotificationStatus.SUPPRESSED.value
                notification.suppressed_reason = suppressed_reason[:200]
            else:
                await _deliver(
                    session,
                    principal,
                    notification,
                    content,
                    severity=severity,
                    settings=settings,
                    redis=redis,
                )
            created.append(notification)

    if created:
        sent = sum(1 for n in created if n.status == NotificationStatus.SENT.value)
        failed = sum(1 for n in created if n.status == NotificationStatus.FAILED.value)
        skipped = suppressed_reason is not None
        await audit_service.record(
            session,
            action=AuditAction.NOTIFICATION_SEND,
            principal=principal,
            resource_type=resource_type,
            resource_id=resource_id,
            # A correctly-applied policy is not a failure. See the module docstring.
            outcome=AuditOutcome.SUCCESS if not failed else AuditOutcome.FAILURE,
            reason=suppressed_reason,
            detail={
                "event": event.value,
                "sent": sent,
                "failed": failed,
                "channels": sorted({n.channel for n in created}),
                **({"skipped": True} if skipped else {}),
            },
        )
    log.info(
        "notification.dispatched",
        event=event.value,
        rows=len(created),
        suppressed=suppressed_reason is not None,
    )
    return created


async def _already_recorded(
    session: AsyncSession, organization_id: uuid.UUID, dedupe_key: str
) -> bool:
    stmt = (
        tenant_select(Notification, organization_id)
        .where(Notification.dedupe_key == dedupe_key)
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none() is not None


async def pending_for_organization(
    session: AsyncSession, principal: Principal, *, limit: int = 50
) -> Sequence[Notification]:
    """Unread in-app notifications, newest first (the bell menu).

    ``sent`` rather than ``pending``, because a websocket row is marked sent on creation
    -- ``pending`` here would mean "a Slack post we have not managed to make", which is an
    operator concern rather than something to show the user.
    """
    stmt = (
        tenant_select(Notification, principal.organization_id)
        .where(
            Notification.channel == NotificationChannel.WEBSOCKET.value,
            Notification.status == NotificationStatus.SENT.value,
        )
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    return (await session.execute(stmt)).scalars().all()


# ---------------------------------------------------------------------------
# Event helpers
#
# Thin by design: the wording of a user-facing alert is a product decision, and having it
# in one place means changing it does not mean auditing every call site.
# ---------------------------------------------------------------------------


def _assessment_url(settings: Settings, assessment_id: uuid.UUID) -> str:
    return f"{settings.public_base_url.rstrip('/')}/assessments/{assessment_id}"


async def notify_assessment_started(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    target: str,
    settings: Settings,
    redis: Redis | None = None,
) -> list[Notification]:
    return await dispatch(
        session,
        principal,
        event=NotificationEvent.ASSESSMENT_STARTED,
        content=NotificationContent(
            subject=f"Assessment started for {target}",
            body=f"Cynux has begun an assessment of {target}.",
            link=_assessment_url(settings, assessment_id),
        ),
        settings=settings,
        redis=redis,
        resource_type="assessment",
        resource_id=str(assessment_id),
    )


async def notify_approval_required(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    asset_count: int,
    recommended_count: int,
    settings: Settings,
    redis: Redis | None = None,
) -> list[Notification]:
    """FR-011. Never suppressed: the run is stopped until somebody answers."""
    return await dispatch(
        session,
        principal,
        event=NotificationEvent.APPROVAL_REQUIRED,
        content=NotificationContent(
            subject="Approval required before scanning",
            body=(
                f"Discovery found {asset_count} live assets. Cynux recommends actively "
                f"scanning {recommended_count} of them and is waiting for your approval "
                "before it starts."
            ),
            link=_assessment_url(settings, assessment_id),
        ),
        settings=settings,
        redis=redis,
        resource_type="assessment",
        resource_id=str(assessment_id),
    )


async def notify_critical_finding(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    finding_id: uuid.UUID,
    title: str,
    severity: Severity,
    asset: str | None,
    settings: Settings,
    redis: Redis | None = None,
) -> list[Notification]:
    """FR-029. ``title`` and ``asset`` are scanner output and are escaped downstream."""
    where = f" on {asset}" if asset else ""
    return await dispatch(
        session,
        principal,
        event=NotificationEvent.CRITICAL_FINDING,
        content=NotificationContent(
            subject=f"{severity.value.title()} finding: {title}",
            body=f"A {severity.value} severity finding was identified{where}.",
            link=f"{settings.public_base_url.rstrip('/')}/findings/{finding_id}",
        ),
        settings=settings,
        redis=redis,
        resource_type="finding",
        resource_id=str(finding_id),
        severity=severity,
    )


async def notify_assessment_completed(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    target: str,
    counts: dict[str, int],
    settings: Settings,
    redis: Redis | None = None,
    degraded: bool = False,
) -> list[Notification]:
    summary = (
        ", ".join(f"{count} {name}" for name, count in counts.items() if count) or "no findings"
    )
    caveat = (
        " Some steps degraded; see the report appendix for what was unavailable."
        if degraded
        else ""
    )
    return await dispatch(
        session,
        principal,
        event=NotificationEvent.ASSESSMENT_COMPLETED,
        content=NotificationContent(
            subject=f"Assessment complete: {target}",
            body=f"Cynux finished assessing {target}. Findings: {summary}.{caveat}",
            link=_assessment_url(settings, assessment_id),
        ),
        settings=settings,
        redis=redis,
        resource_type="assessment",
        resource_id=str(assessment_id),
    )


async def notify_assessment_failed(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    target: str,
    reason: str,
    settings: Settings,
    redis: Redis | None = None,
) -> list[Notification]:
    """FR-040. ``reason`` must already be a user-safe message (SEC-002)."""
    return await dispatch(
        session,
        principal,
        event=NotificationEvent.ASSESSMENT_FAILED,
        content=NotificationContent(
            subject=f"Assessment failed: {target}",
            body=f"The assessment of {target} could not be completed. {reason}",
            link=_assessment_url(settings, assessment_id),
        ),
        settings=settings,
        redis=redis,
        resource_type="assessment",
        resource_id=str(assessment_id),
    )


async def notify_ticket_created(
    session: AsyncSession,
    principal: Principal,
    *,
    finding_id: uuid.UUID,
    ticket_key: str,
    ticket_url: str,
    settings: Settings,
    redis: Redis | None = None,
) -> list[Notification]:
    return await dispatch(
        session,
        principal,
        event=NotificationEvent.TICKET_CREATED,
        content=NotificationContent(
            subject=f"Ticket {ticket_key} created",
            body=f"Cynux filed {ticket_key} for a security finding.",
            link=ticket_url,
        ),
        settings=settings,
        redis=redis,
        resource_type="finding",
        resource_id=str(finding_id),
    )


__all__ = [
    "NotificationContent",
    "dispatch",
    "notify_approval_required",
    "notify_assessment_completed",
    "notify_assessment_failed",
    "notify_assessment_started",
    "notify_critical_finding",
    "notify_ticket_created",
    "pending_for_organization",
]
