"""Finding, remediation and ticket endpoints (FR-017, FR-021, FR-025, FR-027).

WHY this router carries wiring the services do not: analysis, remediation and ticket
creation each need a client a service has no business owning -- the LLM gateway, the
per-tenant Dify knowledge base, the Redis used for notifications -- and each mutating
service deliberately stops short of committing.  So this module supplies those clients as
dependencies, commits the unit of work at the point the write is meant to be durable, and
then *re-reads* the row it just wrote before projecting it.

The re-read is load-bearing, not a habit.  ``lazy="raise_on_sql"`` makes a projection that
touches an unloaded relationship raise rather than emit a query, and a freshly INSERTed
row's server-default ``created_at`` is not fetched back on a client-PK insert -- so
projecting the object a service just handed back would either raise or trigger sync IO.
Reloading through the service's own loader (``get_finding``/``get_remediation``/
``find_ticket``) yields a fully-populated, correctly eager-loaded row.

Two contracts are surfaced deliberately.  A remediation the model declined to produce -- a
false positive, a duplicate, or guidance that failed the invented-CVE guard -- comes back
from the service as ``None`` after its audit row is recorded; the commit persists that audit
and the request answers ``409`` rather than fabricating an empty remediation.  And there is
no status-write endpoint: DefectDojo owns finding state (FR-016 / FR-018) and Cynux has no
service to write it, so :class:`~app.schemas.finding.FindingStatusIn` has no route here.

Cross-tenant ids are a ``404`` throughout because every read goes through the services'
``tenant_select`` (SEC-003), and no scanned host, credential or raw provider error ever
reaches a response body (SEC-002).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import (
    DbSession,
    DifyDep,
    GatewayDep,
    PaginationDep,
    PrincipalDep,
    RedisDep,
    SettingsDep,
)
from app.api.v1.projections import finding_detail_out, finding_out, remediation_out
from app.core.errors import ConflictError
from app.schemas.common import Page
from app.schemas.finding import (
    AnalyzeIn,
    FindingDetailOut,
    FindingFilter,
    FindingOut,
    JiraTicketIn,
    RemediateIn,
    RemediationOut,
    TicketLinkOut,
)
from app.services import finding as finding_service
from app.services import remediation as remediation_service
from app.services import ticket as ticket_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=Page[FindingOut])
async def list_findings(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    filters: Annotated[FindingFilter, Query()],
) -> Page[FindingOut]:
    """A page of findings, worst first (FR-023): priority, then risk score, then severity.

    Duplicates and DefectDojo-flagged false positives are hidden unless the filter opts them
    in -- the default queue is what a triager should act on, not the raw import.
    """
    rows, total = await finding_service.list_findings(
        session, principal, filters=filters, pagination=pagination
    )
    return Page.build(
        [finding_out(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/{finding_id}", response_model=FindingDetailOut)
async def get_finding(
    finding_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> FindingDetailOut:
    """One finding in full: analysis, threat-intel enrichment, remediations and tickets."""
    finding = await finding_service.get_finding(session, principal, finding_id, detail=True)
    return await finding_detail_out(session, principal, finding)


@router.get("/{finding_id}/remediations", response_model=list[RemediationOut])
async def list_finding_remediations(
    finding_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> list[RemediationOut]:
    """Every generated fix for a finding, newest first."""
    remediations = await remediation_service.list_remediations(session, principal, finding_id)
    return [remediation_out(item) for item in remediations]


@router.get("/{finding_id}/tickets", response_model=list[TicketLinkOut])
async def list_finding_tickets(
    finding_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> list[TicketLinkOut]:
    """Tracker issues linked to a finding, newest first."""
    tickets = await ticket_service.list_tickets(session, principal, finding_id)
    return [TicketLinkOut.model_validate(ticket) for ticket in tickets]


@router.post("/{finding_id}/analyze", response_model=FindingDetailOut)
async def analyze_finding(
    finding_id: uuid.UUID,
    payload: AnalyzeIn,
    principal: PrincipalDep,
    session: DbSession,
    gateway: GatewayDep,
    dify: DifyDep,
    settings: SettingsDep,
) -> FindingDetailOut:
    """Generate the AI explanation, business impact and attack scenario for a finding (FR-021).

    Idempotent unless ``force`` is set, so a double-clicked button cannot bill an operator
    twice for the same analysis.  A false positive, a duplicate or a below-floor finding is
    recorded as skipped and returned unchanged rather than analyzed.
    """
    await finding_service.analyze_finding(
        session,
        principal,
        finding_id,
        gateway=gateway,
        dify=dify,
        settings=settings,
        force=payload.force,
    )
    await session.commit()
    finding = await finding_service.get_finding(session, principal, finding_id, detail=True)
    return await finding_detail_out(session, principal, finding)


@router.post("/{finding_id}/remediate", response_model=RemediationOut)
async def remediate_finding(
    finding_id: uuid.UUID,
    payload: RemediateIn,
    principal: PrincipalDep,
    session: DbSession,
    gateway: GatewayDep,
    dify: DifyDep,
    settings: SettingsDep,
) -> RemediationOut:
    """Generate one candidate fix for a finding (FR-025, FR-026).

    Idempotent per approach unless ``force`` is set.  The guidance is advisory: Cynux never
    applies a patch (FR-034).  When no remediation can be produced -- the finding is a false
    positive or duplicate, or the generated guidance cited a CVE or CVSS score it was never
    shown -- the service records the outcome and returns nothing, and this answers ``409``
    rather than inventing an empty fix.
    """
    remediation = await remediation_service.generate_remediation(
        session,
        principal,
        finding_id,
        gateway=gateway,
        dify=dify,
        settings=settings,
        approach=payload.approach,
        force=payload.force,
    )
    await session.commit()
    if remediation is None:
        raise ConflictError(
            "no remediation was generated",
            user_message=(
                "Cynux could not generate remediation for this finding. It may be a false "
                "positive or a duplicate, or the generated guidance failed verification."
            ),
            context={"finding_id": str(finding_id)},
        )
    refreshed = await remediation_service.get_remediation(session, principal, remediation.id)
    return remediation_out(refreshed)


@router.post("/{finding_id}/tickets", response_model=TicketLinkOut)
async def create_finding_ticket(
    finding_id: uuid.UUID,
    payload: JiraTicketIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> TicketLinkOut:
    """File a Jira issue for a finding, or return the existing link (FR-027).

    Idempotent: one finding gets one ticket per provider, so a re-file returns the issue
    already linked rather than opening a duplicate.  Jira is the only supported tracker in
    this release (FR-028); an unreachable Jira surfaces as a 502, not a half-written link.
    """
    await ticket_service.create_ticket(
        session,
        principal,
        finding_id,
        settings=settings,
        redis=redis,
        project_key=payload.project_key,
        issue_type=payload.issue_type,
        assignee=payload.assignee,
        include_remediation=payload.include_remediation,
    )
    await session.commit()
    link = await ticket_service.find_ticket(session, principal, finding_id, provider="jira")
    assert link is not None  # noqa: S101 - create_ticket guarantees a jira link for this finding
    return TicketLinkOut.model_validate(link)


__all__ = ["router"]
