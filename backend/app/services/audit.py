"""Audit trail writes and reads (FR-032).

FR-032 names the events that must be recorded: authentication (including failures),
assessment create / approve / cancel, scanner start and stop, integration configuration
changes, finding status changes, ticket creation, report generation, permission denials,
and **every agent tool invocation**.  :data:`AuditAction` is the closed vocabulary for
those, so a caller cannot invent a verb that no query will ever match.

Two properties are load-bearing:

* **``detail`` is redacted on the way in.**  The audit table is durable in a way logs
  are not, so a credential that lands here outlives every rotation.  It goes through
  the same :func:`~app.core.logging_conf.redact_mapping` the logger uses -- one
  implementation, not two (SEC-002).
* **Every string is truncated to its column width.**  A 5 KB ``User-Agent`` header is
  free for a client to send, and an un-truncated insert would raise
  ``StringDataRightTruncation``.  That would not merely drop one row: it poisons the
  surrounding transaction, so the *request* fails too.  An attacker who can make audit
  writes fail can act unobserved, which turns a cosmetic bug into an evidence-tampering
  primitive.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence
from typing import Any, Final

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import CynuxError
from app.core.logging_conf import redact_mapping
from app.db.enums import AuditOutcome, Permission
from app.db.models.audit import AuditEvent
from app.db.session import session_scope
from app.schemas.audit import AuditFilter
from app.schemas.common import PaginationParams
from app.services.context import ACTOR_SYSTEM, Principal

log = structlog.get_logger(__name__)


class AuditAction:
    """Dotted verbs written to ``audit_events.action``.

    Grouped by subject so ``action LIKE 'assessment.%'`` selects a coherent slice -- the
    reason the names are dotted rather than flat.  Every value is under the column's
    80-character limit.
    """

    # -- authentication (FR-001) --------------------------------------------
    REGISTER = "auth.register"
    LOGIN = "auth.login"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_LOCKED = "auth.login.locked"
    OIDC_LOGIN = "auth.oidc.login"
    SAML_LOGIN = "auth.saml.login"
    LOGOUT = "auth.logout"
    # S105 fires on the names below because they contain "token" and "password". They are
    # audit verbs -- the dotted names of events -- and the whole point of this class is
    # that no credential is ever the value. Suppressed per line rather than per file so a
    # real secret assigned in this module would still be flagged.
    TOKEN_REFRESH = "auth.token.refresh"  # noqa: S105
    TOKEN_REVOKED = "auth.token.revoked"  # noqa: S105
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"  # noqa: S105
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"  # noqa: S105

    # -- organizations and membership (FR-002) ------------------------------
    ORG_CREATE = "organization.create"
    ORG_UPDATE = "organization.update"
    MSSP_CLIENT_CREATE = "organization.client.create"
    MEMBER_INVITE = "membership.invite"
    MEMBER_ROLE_CHANGE = "membership.role.change"
    MEMBER_REMOVE = "membership.remove"
    SCIM_TOKEN_CREATE = "scim.token.create"  # noqa: S105
    SCIM_TOKEN_REVOKE = "scim.token.revoke"  # noqa: S105
    OIDC_CONNECTION_UPSERT = "sso.oidc.configure"
    SAML_CONNECTION_UPSERT = "sso.saml.configure"
    COMPLIANCE_CONTROL_CREATE = "compliance_control.create"
    COMPLIANCE_CONTROL_UPDATE = "compliance_control.update"
    COMPLIANCE_FRAMEWORK_SEED = "compliance_framework.seed"
    COMPLIANCE_MAPPING_CREATE = "compliance_mapping.create"
    COMPLIANCE_MAPPING_DELETE = "compliance_mapping.delete"

    # -- assessments (FR-007, FR-011, FR-039) -------------------------------
    ASSESSMENT_CREATE = "assessment.create"
    ASSESSMENT_TRANSITION = "assessment.transition"
    ASSESSMENT_DEGRADED = "assessment.degraded"
    ASSESSMENT_CANCEL = "assessment.cancel"
    ASSESSMENT_CHECKLIST_UPDATE = "assessment.checklist.update"
    SCAN_PROFILE_DEACTIVATE = "scan_profile.deactivate"
    ATTACK_SIMULATION_PAUSE = "attack_simulation.pause"
    ATTACK_SIMULATION_UPDATE = "attack_simulation.update"
    ATTACK_SIMULATION_DELETE = "attack_simulation.delete"
    ATTACK_SIMULATION_RUN = "attack_simulation.run"
    PLATFORM_API_KEY_CREATE = "platform_api_key.create"
    PLATFORM_API_KEY_REVOKE = "platform_api_key.revoke"
    SAVED_VIEW_CREATE = "saved_view.create"
    SAVED_VIEW_UPDATE = "saved_view.update"
    SAVED_VIEW_DELETE = "saved_view.delete"
    DASHBOARD_LAYOUT_CREATE = "dashboard_layout.create"
    DASHBOARD_LAYOUT_UPDATE = "dashboard_layout.update"
    DASHBOARD_LAYOUT_DELETE = "dashboard_layout.delete"
    WEBHOOK_CREATE = "webhook.create"
    WEBHOOK_DISABLE = "webhook.disable"
    WEBHOOK_SECRET_ROTATE = "webhook.secret.rotate"  # noqa: S105 - audit action, not a secret
    WEBHOOK_DELIVERY_RETRY = "webhook.delivery.retry"
    NOTIFICATION_DELIVERY_RETRY = "notification.delivery.retry"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_CUSTOMIZED = "approval.customized"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_EXPIRED = "approval.expired"
    AGENT_ACTION_PROPOSED = "agent.action.proposed"
    AGENT_ACTION_APPROVED = "agent.action.approved"
    AGENT_ACTION_REJECTED = "agent.action.rejected"
    AGENT_ACTION_EXECUTED = "agent.action.executed"
    AGENT_AUTONOMY_UPDATE = "agent.autonomy.update"
    AGENT_ACTION_FAILED = "agent.action.failed"

    # -- assets (FR-009, FR-010, FR-022) ------------------------------------
    ASSET_TAG = "asset.tag"
    ASSET_CRITICALITY_SET = "asset.criticality.set"
    ASSET_CONTEXT_SET = "asset.context.set"
    ASSET_SCOPE_SELECT = "asset.scope.select"

    # -- scanners (FR-012 .. FR-015) ----------------------------------------
    SCANNER_ENQUEUE = "scanner.enqueue"
    SCANNER_START = "scanner.start"
    SCANNER_COMPLETE = "scanner.complete"
    SCANNER_FAIL = "scanner.fail"
    SCANNER_CANCEL = "scanner.cancel"
    SCANNER_TIMEOUT = "scanner.timeout"

    # -- findings (FR-016 .. FR-023) ----------------------------------------
    FINDING_IMPORT = "finding.import"
    FINDING_STATUS_CHANGE = "finding.status.change"
    FINDING_WORK_UPDATE = "finding.work.update"
    FINDING_COLLABORATION_COMMENT = "finding.collaboration.comment"
    FINDING_ANALYZE = "finding.analyze"
    FINDING_VALIDATE = "finding.validate"
    FINDING_PRIORITIZE = "finding.prioritize"
    FINDING_ENRICH = "finding.enrich"
    EXTERNAL_ALERT_TRIAGE = "external_alert.triage"
    EXTERNAL_ALERT_SOURCE_UPDATE = "external_alert.source_update"
    REMEDIATION_GENERATE = "remediation.generate"
    REMEDIATION_VALIDATE = "remediation.validate"
    RISK_ACCEPTANCE_REQUEST = "risk_acceptance.request"
    RISK_ACCEPTANCE_APPROVE = "risk_acceptance.approve"
    RETEST_REQUEST = "retest.request"
    RETEST_SCHEDULE = "retest.schedule"
    RETEST_COMPLETE = "retest.complete"
    AUTOMATION_RULE_CREATE = "automation_rule.create"
    AUTOMATION_RULE_UPDATE = "automation_rule.update"
    AUTOMATION_RULE_DELETE = "automation_rule.delete"
    AUTOMATION_EXECUTION = "automation.execution"

    # -- external actions (FR-027 .. FR-029) --------------------------------
    TICKET_CREATE = "ticket.create"
    TICKET_STATUS_PUSH = "ticket.status.push"
    TICKET_WEBHOOK_RECEIVE = "ticket.webhook.receive"
    NOTIFICATION_QUEUE = "notification.queue"
    NOTIFICATION_SEND = "notification.send"
    INTEGRATION_CONFIGURE = "integration.configure"
    INTEGRATION_CREDENTIAL_UPDATE = "integration.credential.update"
    INTEGRATION_TEST = "integration.test"
    INTEGRATION_DISABLE = "integration.disable"
    INTEGRATION_SYNC = "integration.sync"
    INTEGRATION_SCAN_LAUNCH = "integration.scan.launch"

    # -- reports (FR-030) ---------------------------------------------------
    REPORT_GENERATE = "report.generate"
    REPORT_DOWNLOAD = "report.download"
    REPORT_SHARE_CREATE = "report.share.create"
    REPORT_SHARE_DOWNLOAD = "report.share.download"
    REPORT_SHARE_REVOKE = "report.share.revoke"
    REPORT_SCHEDULE_CREATE = "report_schedule.create"
    REPORT_SCHEDULE_PAUSE = "report_schedule.pause"
    REPORT_SCHEDULE_RESUME = "report_schedule.resume"

    # -- agent (FR-033 .. FR-036) -------------------------------------------
    AGENT_SESSION_CREATE = "agent.session.create"
    AGENT_DEFINITION_CREATE = "agent.definition.create"
    AGENT_DEFINITION_VERSION_CREATE = "agent.definition.version.create"
    AGENT_DEFINITION_DISABLE = "agent.definition.disable"
    AGENT_MEMORY_UPSERT = "agent.memory.upsert"
    AGENT_MEMORY_DISABLE = "agent.memory.disable"
    AGENT_MESSAGE = "agent.message"
    AGENT_RUN_START = "agent.run.start"
    AGENT_RUN_COMPLETE = "agent.run.complete"
    AGENT_RUN_FAIL = "agent.run.fail"
    AGENT_RUN_INTERRUPT = "agent.run.interrupt"
    AGENT_TOOL_INVOKE = "agent.tool.invoke"
    AGENT_TOOL_DENIED = "agent.tool.denied"

    # -- security guardrails -------------------------------------------------
    PERMISSION_DENIED = "authz.permission.denied"
    #: SEC-003. Distinct from a permission denial: reaching this means a query was built
    #: without a tenant filter, which is a defect rather than a user acting out of turn.
    TENANT_VIOLATION = "authz.tenant.violation"
    TARGET_DENIED = "authz.target.denied"
    UNSAFE_INVOCATION = "authz.unsafe_invocation"


#: Column widths from ``app/db/models/audit.py``, restated so truncation happens here
#: rather than as a database error. Kept in sync by ``tests/unit/test_audit_service.py``,
#: which reads the real ``Column.type.length`` -- a widened column with a stale entry
#: here would silently keep truncating.
_MAX_LENGTHS: Final[dict[str, int]] = {
    "action": 80,
    "actor_email": 320,
    "actor_type": 20,
    "outcome": 20,
    "request_id": 64,
    "resource_id": 80,
    "resource_type": 60,
    "source_ip": 64,
    "trace_id": 64,
    "user_agent": 512,
}

#: ``reason`` is ``Text`` so the database imposes no limit, but an unbounded reason is
#: still a way to bloat the table with one request. Long enough for a real explanation.
_MAX_REASON = 2000


def _fit(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    limit = _MAX_LENGTHS[field]
    return value if len(value) <= limit else value[:limit]


async def record(
    session: AsyncSession,
    *,
    action: str,
    principal: Principal | None = None,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    detail: dict[str, Any] | None = None,
    reason: str | None = None,
    organization_id: uuid.UUID | None = None,
) -> AuditEvent:
    """Stage one audit row on ``session``.

    Joins the caller's transaction rather than opening its own, so the trail and the
    change it describes commit together: an assessment that exists with no audit row, or
    an audit row for an assessment that was rolled back, are both worse than either
    succeeding or both failing.  The consequence is that a row recording a *refusal*
    must not be written this way -- the refusal usually raises, the transaction rolls
    back, and the evidence goes with it.  Use :func:`record_independently` there.

    ``organization_id`` overrides the principal's.  It is how a failed login (no
    principal at all) and a cross-tenant access attempt (a principal whose organization
    is precisely the wrong one to file the event under) both get recorded.
    """
    event = AuditEvent(
        organization_id=organization_id
        if organization_id is not None
        else (principal.organization_id if principal else None),
        actor_id=principal.user_id if principal else None,
        actor_email=_fit(principal.email if principal else None, "actor_email"),
        actor_type=_fit(principal.actor_type if principal else ACTOR_SYSTEM, "actor_type")
        or ACTOR_SYSTEM,
        action=_fit(action, "action") or action[:80],
        resource_type=_fit(resource_type, "resource_type"),
        resource_id=_fit(str(resource_id) if resource_id is not None else None, "resource_id"),
        outcome=outcome.value,
        # Redacted, then bounded. A tool result or provider response passed as detail can
        # be arbitrarily large, and JSONB has no length limit to stop it.
        detail=_bounded(redact_mapping(detail)) if detail else {},
        reason=reason[:_MAX_REASON] if reason else None,
        source_ip=_fit(principal.source_ip if principal else None, "source_ip"),
        user_agent=_fit(principal.user_agent if principal else None, "user_agent"),
        request_id=_fit(principal.request_id if principal else None, "request_id"),
        trace_id=_fit(principal.trace_id if principal else None, "trace_id"),
        created_at=_now(),
    )
    session.add(event)
    # Flushed so a constraint violation -- a bad ``outcome``, an ``actor_id`` pointing at
    # a deleted user -- is raised at this call site instead of at the route's commit,
    # where the traceback no longer says which audited action was responsible.
    await session.flush()
    return event


async def record_denial(
    session: AsyncSession,
    *,
    action: str,
    principal: Principal | None,
    reason: str,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    """A refused action, recorded with ``outcome=denied``.

    Separate from :func:`record` only so the outcome cannot be forgotten: a denial
    written with the default ``SUCCESS`` reads in the trail as the opposite of what
    happened.
    """
    return await record(
        session,
        action=action,
        principal=principal,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=AuditOutcome.DENIED,
        detail=detail,
        reason=reason,
    )


async def record_independently(
    *,
    action: str,
    principal: Principal | None = None,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.FAILURE,
    detail: dict[str, Any] | None = None,
    reason: str | None = None,
    organization_id: uuid.UUID | None = None,
    settings: Settings | None = None,
) -> bool:
    """Write an audit row in its own transaction, for events whose caller is failing.

    A permission denial, a tenant-isolation violation and a failed login all raise, and
    the raise rolls back the request's session -- taking a row written by :func:`record`
    with it.  Exactly the events FR-032 most wants kept are the ones that cannot share
    the caller's transaction.

    Never raises.  It is called from exception handlers, and an audit failure that
    replaced the original error would hide the very thing being reported.  It logs at
    CRITICAL instead and returns ``False``, because an audit trail that has started
    silently dropping writes is itself an incident.
    """
    try:
        async with session_scope(settings) as session:
            await record(
                session,
                action=action,
                principal=principal,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome,
                detail=detail,
                reason=reason,
                organization_id=organization_id,
            )
        return True
    except Exception as exc:  # deliberately total; see the docstring
        log.critical(
            "audit.write_failed",
            audit_action=action,
            audit_outcome=outcome.value,
            error=type(exc).__name__,
            **(principal.to_log_fields() if principal else {}),
        )
        return False


async def record_error(
    session: AsyncSession,
    *,
    action: str,
    principal: Principal | None,
    error: CynuxError,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
) -> AuditEvent:
    """Record a failed action from a taxonomy error.

    ``reason`` gets the *user-safe* message, never ``str(error)``: the internal message
    may name an internal host or embed a provider response, and the audit trail is read
    by anyone with ``audit:read`` (SEC-002).
    """
    return await record(
        session,
        action=action,
        principal=principal,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=AuditOutcome.FAILURE,
        detail=error.to_log_fields(),
        reason=error.user_message,
    )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def list_audit_events(
    session: AsyncSession,
    principal: Principal,
    *,
    filters: AuditFilter | None = None,
    pagination: PaginationParams | None = None,
) -> tuple[Sequence[AuditEvent], int]:
    """Newest first, filtered to the caller's organization.

    ``audit_events`` deliberately does not use ``TenantMixin`` -- a failed login has no
    organization -- so :func:`~app.db.repository.tenant_select` cannot be used and the
    filter is written explicitly here.  Rows with a NULL ``organization_id`` are *not*
    returned: they are global security events, and attributing them to whichever tenant
    happens to be looking would be wrong in both directions.
    """
    principal.require(Permission.AUDIT_READ)
    filters = filters or AuditFilter()
    page = pagination or PaginationParams()

    conditions = _audit_conditions(principal, filters)
    total = int(
        (
            await session.execute(select(func.count()).select_from(AuditEvent).where(*conditions))
        ).scalar_one()
    )
    stmt = (
        select(AuditEvent)
        .where(*conditions)
        # ``id`` breaks ties: two rows written in the same transaction share
        # ``created_at`` to the microsecond, and an unstable order makes paging skip and
        # repeat rows.
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return rows, total


async def export_audit_events(
    session: AsyncSession,
    principal: Principal,
    *,
    filters: AuditFilter | None = None,
    maximum_rows: int = 10_000,
) -> Sequence[AuditEvent]:
    """Return a bounded, consistently ordered export for the caller's organization.

    CSV exports are intended for evidence collection and downstream analysis, not a
    bulk-exfiltration path.  They use the exact same visibility and filters as the
    interactive audit view and are capped deliberately so a long-lived tenant cannot
    monopolize an application worker.
    """
    principal.require(Permission.AUDIT_READ)
    filters = filters or AuditFilter()
    conditions = _audit_conditions(principal, filters)
    stmt = (
        select(AuditEvent)
        .where(*conditions)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(maximum_rows)
    )
    return (await session.execute(stmt)).scalars().all()


def _audit_conditions(principal: Principal, filters: AuditFilter) -> list[Any]:
    """Build the shared tenant-scoped predicate used by the feed and export."""
    conditions: list[Any] = [AuditEvent.organization_id == principal.organization_id]
    if filters.actor_id:
        conditions.append(AuditEvent.actor_id == filters.actor_id)
    if filters.actor_type:
        conditions.append(AuditEvent.actor_type == filters.actor_type)
    if filters.action:
        # Prefix match, so "assessment." selects the whole group. ``like`` rather than
        # ``ilike``: actions are generated from the constants above and are always
        # lower-case, and a case-insensitive scan cannot use the index on ``action``.
        conditions.append(AuditEvent.action.like(f"{filters.action}%"))
    if filters.resource_type:
        conditions.append(AuditEvent.resource_type == filters.resource_type)
    if filters.resource_id:
        conditions.append(AuditEvent.resource_id == str(filters.resource_id))
    if filters.outcome:
        conditions.append(AuditEvent.outcome == filters.outcome.value)
    if filters.since:
        conditions.append(AuditEvent.created_at >= filters.since)
    if filters.until:
        conditions.append(AuditEvent.created_at <= filters.until)
    if filters.q:
        term = f"%{_escape_like(filters.q)}%"
        conditions.append(
            or_(
                AuditEvent.actor_email.ilike(term, escape="\\"),
                AuditEvent.action.ilike(term, escape="\\"),
                AuditEvent.reason.ilike(term, escape="\\"),
            )
        )
    return conditions


async def resource_history(
    session: AsyncSession,
    principal: Principal,
    *,
    resource_type: str,
    resource_id: str | uuid.UUID,
    limit: int = 200,
) -> Sequence[AuditEvent]:
    """Everything that has happened to one resource, oldest first.

    Oldest first because this is read as a narrative -- "created, approved, scanned,
    reported" -- not as a feed.
    """
    principal.require(Permission.AUDIT_READ)
    stmt = (
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == principal.organization_id,
            AuditEvent.resource_type == resource_type,
            AuditEvent.resource_id == str(resource_id),
        )
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        .limit(limit)
    )
    return (await session.execute(stmt)).scalars().all()


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

#: Cap on the serialized size of ``detail``. Generous for structured context, small
#: enough that a scanner log or a provider response body cannot be smuggled into the
#: audit table one row at a time (SEC-006 applies to storage, not only to prompts).
_MAX_DETAIL_CHARS = 8000


def _bounded(detail: dict[str, Any]) -> dict[str, Any]:
    """Keep ``detail`` under budget by replacing oversized values, not by dropping keys.

    A single huge value -- a stack trace, a scanner's stdout, a base64 artifact -- is
    replaced by a marker naming its size, so the trail still records that something was
    there and how big it was.  Silently discarding the key would leave a reader unable to
    tell a small event from a truncated one.

    The marker is charged against the budget rather than zeroing it, so the *small* keys
    that follow a large one survive.  That distinction is the whole value of the function
    in practice: in ``{"stdout": <8 KB>, "exit_code": 137}`` the second field is the one
    that says the scanner was OOM-killed, and an implementation that spent the budget on
    the first would throw it away.
    """
    out: dict[str, Any] = {}
    budget = _MAX_DETAIL_CHARS
    for key, value in detail.items():
        text = value if isinstance(value, str) else repr(value)
        size = len(text)
        if size <= budget:
            out[key] = value
            budget -= size
            continue
        marker = f"[omitted: {size} chars, audit detail budget exhausted]"
        if len(marker) > budget:
            # Not even room to say something was dropped. Record how many keys went
            # unwritten and stop, rather than spending what is left of the budget on a
            # run of omission notices.
            out["_truncated_keys"] = len(detail) - len(out)
            break
        out[key] = marker
        budget -= len(marker)
    return out


def _escape_like(term: str) -> str:
    """Neutralize LIKE wildcards in user input.

    Without this, a search for ``%`` matches every row -- not a security hole, but a
    full table scan any user can trigger on the largest table in the schema.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "AuditAction",
    "list_audit_events",
    "export_audit_events",
    "record",
    "record_denial",
    "record_error",
    "record_independently",
    "resource_history",
]
