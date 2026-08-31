"""Node: create_actions -- file tickets and send notifications (FR-027, FR-028, FR-029).

With the findings analyzed, ranked and (where possible) remediated, this node turns the assessment
into the two outbound actions a security team actually works from: a Jira issue for each finding
worth tracking, and a Slack/in-app alert for every critical one.  It runs during the ``remediating``
status at stage ``creating_actions``.

**Two independent sub-tasks, deliberately ordered alerts-first.**  A critical-finding alert is the
time-sensitive signal -- somebody should hear about a critical before a ticket is filed -- so
notifications go out first, then tickets.  The two do not share a failure fate:

*Notifications never fail the run.*  :func:`app.services.notification.dispatch` writes the
notification row first and treats delivery as best-effort: a Slack outage marks the row ``failed``
(a queryable backlog) and returns rather than raising.  So the alert loop has no fatal path -- an
unreachable Slack workspace is an operator concern, not a reason to fail an assessment that was
merely trying to mention itself.

*Tickets degrade; they do not fail (FR-040).*  Filing is opt-in: an organization that has not set a
``ticket_min_severity`` policy has not asked Cynux to file issues, so the sub-task is skipped
outright.  When it is enabled but Jira is not configured, or Jira is unreachable, that is recorded as
an FR-039 degradation and the run continues -- a missing ticket does not lose the finding, which is
safe in Cynux.  Jira errors are :class:`IntegrationError` (degradable); only DefectDojo and object
storage are fatal, and neither is touched here.  A Jira outage fails every remaining ticket
identically, so the loop stops on the first failure rather than issuing N doomed calls behind an
already-tripped circuit breaker.

Both services self-audit (``TICKET_CREATE``, ``NOTIFICATION_SEND``), so this node leaves
``audit_action`` unset.  A finding title and asset name are passed to the notification service on
purpose -- that is what the alert is about, and the service escapes them for Slack (SEC-005) -- but
this node's own logs and the step digest carry counts and error codes only, never a title, a
hostname, or a credential (SEC-002).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import structlog
from sqlalchemy.orm import selectinload

from app.agent.nodes._common import (
    StepHandle,
    load_assessment,
    principal_from,
    record_step,
)
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.errors import IntegrationError
from app.db.enums import AssessmentStage, AssessmentStatus, IntegrationKind, Severity
from app.db.models.finding import Finding
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.integrations.jira import JiraClient
from app.services.assessment import record_degradation, transition
from app.services.context import Principal
from app.services.integration import resolve_settings
from app.services.notification import notify_critical_finding
from app.services.ticket import create_ticket, policy_ticket_floor, ticket_candidates

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "create_actions"

#: Cap on individual critical-finding alerts. Criticals are rare, so this almost never binds; it
#: exists so a pathological assessment cannot page a Slack channel hundreds of times. The
#: assessment-completed summary (sent by the report node) still names the total, and the digest
#: below records both counts so the cap is never silent.
_MAX_CRITICAL_ALERTS = 50

_IMPACT_TICKETS = (
    "Some findings could not be filed as Jira issues, so they are not tracked in the issue "
    "tracker. The findings themselves remain recorded in Cynux and are unaffected."
)

_NOT_CONFIGURED_REASON = (
    "Automatic ticketing is enabled by policy, but the Jira integration is not configured, so no "
    "issues were filed."
)
_NOT_CONFIGURED_NOTE = "Ticketing is enabled but Jira is not configured; no issues were filed."

_UNAVAILABLE_REASON = "Jira was unavailable while filing issues; some findings have no ticket."
_UNAVAILABLE_NOTE = "Jira was unavailable; some findings were not filed as issues."


@dataclass(frozen=True, slots=True)
class _Critical:
    """The scalars an alert needs, lifted out of the ORM before the loading session closes."""

    id: uuid.UUID
    title: str
    asset: str | None


@dataclass(frozen=True, slots=True)
class _CriticalResult:
    criticals: int
    alerts_sent: int


@dataclass(frozen=True, slots=True)
class _TicketResult:
    enabled: bool
    configured: bool
    candidates: int
    filed: int
    unavailable: bool


async def create_actions(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """File tickets for ticket-worthy findings and alert on critical ones (FR-027..FR-029)."""
    await _advance_to_actions(state, deps=deps)

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.ACTIONS,
        label="Creating tickets and notifications",
    ) as step:
        await _create_actions(state, deps=deps, step=step)

    return {"stage": AssessmentStage.ACTIONS.value}


async def _advance_to_actions(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Advance the stage cursor to ``creating_actions`` within the ``remediating`` status.

    Idempotent: remediation already moved the assessment to ``remediating``, so this only advances
    the stage; were remediation somehow skipped it would carry ``analyzing -> remediating`` (an
    allowed transition).  A terminal or cancelling status raises :class:`ConflictError`, which
    correctly refuses to act on an assessment that is being torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await transition(
            session, assessment, AssessmentStatus.REMEDIATING, stage=AssessmentStage.ACTIONS
        )


async def _create_actions(state: AssessmentState, *, deps: AgentDeps, step: StepHandle) -> None:
    """Run the two sub-tasks and record a counts-only summary of both."""
    principal = principal_from(state)

    criticals = await _notify_criticals(state, deps=deps, principal=principal, step=step)
    tickets = await _file_tickets(state, deps=deps, principal=principal, step=step)

    step.record_output(
        {
            "critical_findings": criticals.criticals,
            "critical_alerts_sent": criticals.alerts_sent,
            "ticketing_enabled": tickets.enabled,
            "jira_configured": tickets.configured,
            "ticket_candidates": tickets.candidates,
            "tickets_filed": tickets.filed,
            "jira_unavailable": tickets.unavailable,
        }
    )


# ---------------------------------------------------------------------------
# FR-029: critical-finding alerts
# ---------------------------------------------------------------------------


async def _notify_criticals(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal, step: StepHandle
) -> _CriticalResult:
    """Send one alert per critical finding; delivery is best-effort and never raises.

    Each alert commits in its own transaction so the notification service's dedupe (keyed on the
    finding) is durable: a resumed run re-reads the recorded rows and does not alert twice.  The
    finding title and asset name are handed to the service -- it escapes them for Slack -- but are
    never logged here (SEC-002).
    """
    assessment_id = state_uuid(state, "assessment_id")
    criticals = await _critical_findings(state, deps=deps)

    if not criticals:
        await step.thinking("No critical-severity findings required an alert.")
        return _CriticalResult(criticals=0, alerts_sent=0)

    await step.thinking(f"Sending alerts for {len(criticals)} critical finding(s).")
    sent = 0
    for critical in criticals:
        async with session_scope(deps.settings) as session:
            await notify_critical_finding(
                session,
                principal,
                assessment_id=assessment_id,
                finding_id=critical.id,
                title=critical.title,
                severity=Severity.CRITICAL,
                asset=critical.asset,
                settings=deps.settings,
                redis=deps.redis,
            )
        sent += 1

    return _CriticalResult(criticals=len(criticals), alerts_sent=sent)


async def _critical_findings(state: AssessmentState, *, deps: AgentDeps) -> list[_Critical]:
    """The assessment's open critical findings, worst first, capped (SEC-003 tenant filter).

    Read in one transaction with the asset eager-loaded, and reduced to plain scalars before the
    session closes so the alert loop can open a fresh session per finding without touching a
    detached ORM instance.
    """
    org_id = state_uuid(state, "organization_id")
    assessment_id = state_uuid(state, "assessment_id")

    async with session_scope(deps.settings) as session:
        stmt = (
            tenant_select(Finding, org_id, selectinload(Finding.asset))
            .where(
                Finding.assessment_id == assessment_id,
                Finding.severity == Severity.CRITICAL.value,
                Finding.is_false_positive.is_(False),
                Finding.is_duplicate.is_(False),
            )
            .order_by(Finding.risk_score.desc().nullslast(), Finding.created_at.asc())
            .limit(_MAX_CRITICAL_ALERTS)
        )
        findings = (await session.execute(stmt)).scalars().all()
        return [
            _Critical(
                id=finding.id,
                title=finding.title,
                asset=finding.asset.name if finding.asset is not None else None,
            )
            for finding in findings
        ]


# ---------------------------------------------------------------------------
# FR-027, FR-028: Jira tickets
# ---------------------------------------------------------------------------


async def _file_tickets(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal, step: StepHandle
) -> _TicketResult:
    """File a Jira issue for each ticket-worthy finding, degrading on any Jira failure.

    Opt-in: ``policy_ticket_floor`` returns ``None`` when the organization has not enabled
    automatic ticketing, and Cynux does not file issues nobody asked for.  When it is enabled but
    Jira is unconfigured, or Jira errors mid-batch, that is a degradation (FR-039/FR-040), not a
    failed run.  Each ticket commits in its own transaction so ``create_ticket``'s idempotency is
    durable across a resume; ``ticket_candidates`` already excludes linked findings, so a resumed
    run files only what is still missing.
    """
    assessment_id = state_uuid(state, "assessment_id")

    async with session_scope(deps.settings) as session:
        floor = await policy_ticket_floor(session, principal)

    if floor is None:
        await step.thinking("Automatic ticketing is not enabled for this organization.")
        return _TicketResult(
            enabled=False, configured=False, candidates=0, filed=0, unavailable=False
        )

    if not await _jira_configured(state, deps=deps, principal=principal):
        await _degrade(state, deps=deps, reason=_NOT_CONFIGURED_REASON)
        step.degrade(_NOT_CONFIGURED_NOTE)
        return _TicketResult(
            enabled=True, configured=False, candidates=0, filed=0, unavailable=False
        )

    async with session_scope(deps.settings) as session:
        candidates = await ticket_candidates(
            session, principal, assessment_id, organization_policy_floor=floor
        )
        candidate_ids = [finding.id for finding in candidates]

    if not candidate_ids:
        await step.thinking("No findings met the ticketing threshold; no issues filed.")
        return _TicketResult(
            enabled=True, configured=True, candidates=0, filed=0, unavailable=False
        )

    await step.thinking(f"Filing Jira issues for {len(candidate_ids)} finding(s).")
    filed = 0
    unavailable = False
    for finding_id in candidate_ids:
        try:
            async with session_scope(deps.settings) as session:
                await create_ticket(
                    session,
                    principal,
                    finding_id,
                    settings=deps.settings,
                    redis=deps.redis,
                    by_agent=True,
                )
            filed += 1
        except IntegrationError as exc:
            # Jira is down/misconfigured; every remaining finding would fail identically behind the
            # tripped circuit breaker. Stop and degrade rather than issue N doomed calls.
            unavailable = True
            log.warning("agent.actions.jira_unavailable", error=exc.code)
            break

    if unavailable:
        await _degrade(state, deps=deps, reason=_UNAVAILABLE_REASON)
        step.degrade(_UNAVAILABLE_NOTE)

    return _TicketResult(
        enabled=True,
        configured=True,
        candidates=len(candidate_ids),
        filed=filed,
        unavailable=unavailable,
    )


async def _jira_configured(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal
) -> bool:
    """Whether Jira is set up for this tenant, checked once before the filing loop.

    Resolving per-tenant settings and asking the client avoids attempting -- and auditing a
    FAILURE for -- a whole batch of tickets against an integration nobody configured.
    """
    async with session_scope(deps.settings) as session:
        scoped = await resolve_settings(
            session, principal, IntegrationKind.JIRA, settings=deps.settings
        )
    return JiraClient(scoped, deps.redis).configured


async def _degrade(state: AssessmentState, *, deps: AgentDeps, reason: str) -> None:
    """Record an FR-039 ticketing degradation; never fail the run over it.

    ``record_degradation`` writes its own ASSESSMENT_DEGRADED audit row.  ``except Exception``
    leaves a ``CancelledError`` to propagate untouched (mirrors :mod:`app.agent.nodes.analyze`).
    """
    try:
        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            await record_degradation(
                session,
                assessment,
                stage=AssessmentStage.ACTIONS,
                component="jira",
                reason=reason,
                impact=_IMPACT_TICKETS,
            )
    except Exception as exc:
        log.warning("agent.actions.degrade_record_failed", error=type(exc).__name__)


__all__ = ["create_actions"]
