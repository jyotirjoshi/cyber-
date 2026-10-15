"""Canonical finding read API with each provider observation preserved."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PaginationDep, PrincipalDep, RedisDep, SettingsDep
from app.schemas.canonical import (
    BulkCanonicalWorkIn,
    CanonicalFindingDetailOut,
    CanonicalFindingOut,
    CanonicalRemediationOperationOut,
    CanonicalStatusDecisionIn,
    CanonicalWorkIn,
    FindingHistoryOut,
    FindingObservationOut,
    RemediationGroupOut,
    RetestRequestIn,
    RetestRequestOut,
    RiskAcceptanceIn,
    RiskAcceptanceOut,
)
from app.schemas.collaboration import (
    FindingCollaborationCommentCreateIn,
    FindingCollaborationCommentOut,
)
from app.schemas.common import Page
from app.schemas.finding import JiraTicketIn, TicketLinkOut
from app.services import canonical_query, finding_collaboration, remediation_governance
from app.services import ticket as ticket_service
from app.services.canonical_decision import decide_status
from app.services.canonical_work import bulk_update_work, update_work

router = APIRouter(prefix="/canonical-findings", tags=["findings"])


@router.get("", response_model=Page[CanonicalFindingOut])
async def list_canonical_findings(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    mine: bool = Query(default=False),
    overdue: bool = Query(default=False),
    severity: str | None = Query(
        default=None, pattern="^(critical|high|medium|low|info)$"
    ),
    status: str | None = Query(
        default=None,
        pattern="^(new|open|reopened|mitigated|accepted_risk|false_positive|closed)$",
    ),
    q: str | None = Query(default=None, min_length=1, max_length=200),
    query: str | None = Query(default=None, min_length=1, max_length=1000),
) -> Page[CanonicalFindingOut]:
    rows, total = await canonical_query.list_canonical_findings(
        session,
        principal,
        pagination,
        mine=mine,
        overdue=overdue,
        severity=severity,
        status=status,
        q=q,
        query=query,
    )
    return Page.build(
        [CanonicalFindingOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/operations", response_model=Page[CanonicalRemediationOperationOut])
async def list_canonical_remediation_operations(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    mine: bool = Query(default=False),
    overdue: bool = Query(default=False),
    attention_only: bool = Query(default=True),
    asset_group: str | None = Query(default=None, min_length=1, max_length=120),
    remediation_group: str | None = Query(default=None, min_length=1, max_length=160),
) -> Page[CanonicalRemediationOperationOut]:
    """A work queue joining canonical remediation, tickets, exceptions, and retests."""
    rows, total = await canonical_query.list_remediation_operations(
        session,
        principal,
        pagination,
        mine=mine,
        overdue=overdue,
        attention_only=attention_only,
        asset_group=asset_group,
        remediation_group=remediation_group,
    )
    return Page.build(
        [
            CanonicalRemediationOperationOut(
                finding=CanonicalFindingOut.model_validate(finding),
                tickets=[TicketLinkOut.model_validate(ticket) for ticket in tickets],
                latest_risk_acceptance=(
                    RiskAcceptanceOut.model_validate(acceptance) if acceptance is not None else None
                ),
                latest_retest=RetestRequestOut.model_validate(retest) if retest is not None else None,
                next_action=next_action,
                priority_reasons=priority_reasons,
                source_observations=source_observations,
                sla_escalation_level=sla_escalation_level,
            )
            for finding, tickets, acceptance, retest, next_action, priority_reasons, source_observations, sla_escalation_level in rows
        ],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/remediation-groups", response_model=list[RemediationGroupOut])
async def list_remediation_groups(
    principal: PrincipalDep,
    session: DbSession,
    limit: int = Query(default=100, ge=1, le=100),
) -> list[RemediationGroupOut]:
    rows = await canonical_query.list_remediation_groups(session, principal, limit=limit)
    return [
        RemediationGroupOut(
            name=name,
            active_findings=active,
            overdue_findings=overdue,
            highest_risk_score=highest,
            last_seen_at=last_seen,
        )
        for name, active, overdue, highest, last_seen in rows
    ]


@router.patch("/work/bulk", response_model=list[CanonicalFindingOut])
async def set_bulk_canonical_work(
    body: BulkCanonicalWorkIn,
    principal: PrincipalDep,
    session: DbSession,
) -> list[CanonicalFindingOut]:
    """Apply a version-checked remediation batch atomically within one tenant."""
    findings = await bulk_update_work(session, principal, body)
    await session.commit()
    return [CanonicalFindingOut.model_validate(finding) for finding in findings]


@router.get("/{finding_id}", response_model=CanonicalFindingDetailOut)
async def get_canonical_finding(
    finding_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> CanonicalFindingDetailOut:
    finding, observations, history = await canonical_query.get_canonical_finding(
        session, principal, finding_id
    )
    return CanonicalFindingDetailOut(
        **CanonicalFindingOut.model_validate(finding).model_dump(),
        observations=[FindingObservationOut.model_validate(item) for item in observations],
        history=[FindingHistoryOut.model_validate(item) for item in history],
        tickets=[
            TicketLinkOut.model_validate(item)
            for item in await ticket_service.list_canonical_tickets(session, principal, finding_id)
        ],
    )


@router.get("/{finding_id}/comments", response_model=list[FindingCollaborationCommentOut])
async def list_finding_comments(
    finding_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[FindingCollaborationCommentOut]:
    comments = await finding_collaboration.list_comments(session, principal, finding_id)
    return [FindingCollaborationCommentOut.model_validate(item) for item in comments]


@router.post("/{finding_id}/comments", response_model=FindingCollaborationCommentOut)
async def add_finding_comment(
    finding_id: uuid.UUID,
    body: FindingCollaborationCommentCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> FindingCollaborationCommentOut:
    comment = await finding_collaboration.create_comment(session, principal, finding_id, body)
    await session.commit()
    await session.refresh(comment)
    return FindingCollaborationCommentOut.model_validate(comment)


@router.post("/{finding_id}/tickets", response_model=TicketLinkOut)
async def create_canonical_finding_ticket(
    finding_id: uuid.UUID,
    body: JiraTicketIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> TicketLinkOut:
    link = await ticket_service.create_canonical_ticket(
        session,
        principal,
        finding_id,
        settings=settings,
        redis=redis,
        project_key=body.project_key,
        issue_type=body.issue_type,
        assignee=body.assignee,
        include_remediation=body.include_remediation,
        provider=body.provider,
    )
    await session.commit()
    await session.refresh(link)
    return TicketLinkOut.model_validate(link)


@router.patch("/{finding_id}/status", response_model=CanonicalFindingOut)
async def set_canonical_status(
    finding_id: uuid.UUID,
    body: CanonicalStatusDecisionIn,
    principal: PrincipalDep,
    session: DbSession,
) -> CanonicalFindingOut:
    await decide_status(
        session,
        principal,
        finding_id,
        status=body.status,
        reason=body.reason,
        expected_version=body.expected_version,
    )
    await session.commit()
    finding, _, _ = await canonical_query.get_canonical_finding(session, principal, finding_id)
    return CanonicalFindingOut.model_validate(finding)


@router.patch("/{finding_id}/work", response_model=CanonicalFindingOut)
async def set_canonical_work(
    finding_id: uuid.UUID,
    body: CanonicalWorkIn,
    principal: PrincipalDep,
    session: DbSession,
) -> CanonicalFindingOut:
    await update_work(session, principal, finding_id, body)
    await session.commit()
    finding, _, _ = await canonical_query.get_canonical_finding(session, principal, finding_id)
    return CanonicalFindingOut.model_validate(finding)


@router.post("/{finding_id}/risk-acceptances", response_model=RiskAcceptanceOut)
async def request_canonical_risk_acceptance(
    finding_id: uuid.UUID, body: RiskAcceptanceIn, principal: PrincipalDep, session: DbSession
) -> RiskAcceptanceOut:
    acceptance = await remediation_governance.request_risk_acceptance(
        session, principal, finding_id, rationale=body.rationale, expires_at=body.expires_at
    )
    await session.commit()
    await session.refresh(acceptance)
    return RiskAcceptanceOut.model_validate(acceptance)


@router.post("/risk-acceptances/{acceptance_id}/approve", response_model=RiskAcceptanceOut)
async def approve_canonical_risk_acceptance(
    acceptance_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> RiskAcceptanceOut:
    acceptance = await remediation_governance.approve_risk_acceptance(session, principal, acceptance_id)
    await session.commit()
    await session.refresh(acceptance)
    return RiskAcceptanceOut.model_validate(acceptance)


@router.post("/{finding_id}/retests", response_model=RetestRequestOut)
async def request_canonical_retest(
    finding_id: uuid.UUID, body: RetestRequestIn, principal: PrincipalDep, session: DbSession
) -> RetestRequestOut:
    request = await remediation_governance.request_retest(session, principal, finding_id, note=body.note)
    await session.commit()
    await session.refresh(request)
    return RetestRequestOut.model_validate(request)


@router.post("/remediation-groups/{remediation_group}/retests", response_model=list[RetestRequestOut])
async def request_remediation_group_retests(
    remediation_group: str,
    body: RetestRequestIn,
    principal: PrincipalDep,
    session: DbSession,
) -> list[RetestRequestOut]:
    """Request evidence-based verification across active findings sharing one fix group."""
    requests = await remediation_governance.request_remediation_group_retests(
        session,
        principal,
        remediation_group=remediation_group,
        note=body.note,
    )
    await session.commit()
    return [RetestRequestOut.model_validate(request) for request in requests]
