"""Canonical finding read API with each provider observation preserved."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PaginationDep, PrincipalDep, RedisDep, SettingsDep
from app.schemas.canonical import (
    CanonicalFindingDetailOut,
    CanonicalFindingOut,
    CanonicalStatusDecisionIn,
    CanonicalWorkIn,
    FindingHistoryOut,
    FindingObservationOut,
)
from app.schemas.common import Page
from app.schemas.finding import JiraTicketIn, TicketLinkOut
from app.services import canonical_query
from app.services import ticket as ticket_service
from app.services.canonical_decision import decide_status
from app.services.canonical_work import update_work

router = APIRouter(prefix="/canonical-findings", tags=["findings"])


@router.get("", response_model=Page[CanonicalFindingOut])
async def list_canonical_findings(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    mine: bool = Query(default=False),
    overdue: bool = Query(default=False),
) -> Page[CanonicalFindingOut]:
    rows, total = await canonical_query.list_canonical_findings(
        session,
        principal,
        pagination,
        mine=mine,
        overdue=overdue,
    )
    return Page.build(
        [CanonicalFindingOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


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
