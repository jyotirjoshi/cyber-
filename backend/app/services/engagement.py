"""PTaaS engagement lifecycle using canonical assessments and findings."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.assessment import Assessment
from app.db.models.engagement import (
    Engagement,
    EngagementDocument,
    EngagementMilestone,
    EngagementParticipant,
    EngagementRetestRound,
    EngagementTimeEntry,
)
from app.db.models.identity import Membership
from app.db.repository import tenant_select
from app.schemas.engagement import (
    EngagementCreateIn,
    EngagementDocumentCreateIn,
    EngagementMilestoneCreateIn,
    EngagementParticipantCreateIn,
    EngagementRetestRoundCreateIn,
    EngagementTimeEntryCreateIn,
)
from app.services import audit as audit_service
from app.services.context import Principal

_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"scoping", "cancelled"}),
    "scoping": frozenset({"draft", "active", "cancelled"}),
    "active": frozenset({"retesting", "completed", "cancelled"}),
    "retesting": frozenset({"active", "completed", "cancelled"}),
    "completed": frozenset(),
    "cancelled": frozenset(),
}


def validate_status_transition(current: str, target: str) -> None:
    if current == target:
        return
    if target not in _TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid engagement transition from {current} to {target}")


def next_retest_ordinal(existing: Sequence[int]) -> int:
    ordinal = max(existing, default=0) + 1
    if ordinal > 100:
        raise ValueError("engagement retest round limit reached")
    return ordinal


async def _assessment(
    session: AsyncSession, principal: Principal, assessment_id: uuid.UUID | None
) -> Assessment | None:
    if assessment_id is None:
        return None
    row = await session.scalar(
        tenant_select(Assessment, principal.organization_id).where(
            Assessment.id == assessment_id
        )
    )
    if row is None:
        raise ResourceNotFoundError("Assessment not found")
    return row


async def get_engagement(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> Engagement:
    principal.require(Permission.ASSESSMENT_READ)
    query = tenant_select(Engagement, principal.organization_id).where(
        Engagement.id == engagement_id
    )
    if for_update:
        query = query.with_for_update()
    row = await session.scalar(query)
    if row is None:
        raise ResourceNotFoundError("Engagement not found")
    return row


async def list_engagements(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[Engagement], int]:
    principal.require(Permission.ASSESSMENT_READ)
    scoped = Engagement.organization_id == principal.organization_id
    total = await session.scalar(select(func.count()).select_from(Engagement).where(scoped))
    rows = list(
        (
            await session.scalars(
                select(Engagement)
                .where(scoped)
                .order_by(Engagement.created_at.desc(), Engagement.id.desc())
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        ).all()
    )
    return rows, int(total or 0)


async def create_engagement(
    session: AsyncSession, principal: Principal, payload: EngagementCreateIn
) -> Engagement:
    principal.require(Permission.ASSESSMENT_CREATE)
    await _assessment(session, principal, payload.assessment_id)
    row = Engagement(
        organization_id=principal.organization_id,
        assessment_id=payload.assessment_id,
        title=payload.title,
        description=payload.description,
        scope=dict(payload.scope),
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        client_visible=payload.client_visible,
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="engagement.create",
        principal=principal,
        resource_type="engagement",
        resource_id=row.id,
        detail={"assessment_id": str(row.assessment_id) if row.assessment_id else None},
    )
    from app.services.automation import queue_rule_event

    await queue_rule_event(
        session,
        organization_id=principal.organization_id,
        trigger="engagement.created",
        event_key=f"engagement.created:{row.id}",
        context={
            "engagement_id": str(row.id),
            "assessment_id": str(row.assessment_id) if row.assessment_id else None,
            "status": row.status,
            "source": "ptaas",
        },
    )
    return row


async def update_status(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    *,
    status: str,
    expected_version: int,
) -> Engagement:
    principal.require(Permission.ASSESSMENT_CREATE)
    row = await get_engagement(session, principal, engagement_id, for_update=True)
    if row.version != expected_version:
        raise ConflictError("Engagement changed; reload before retrying")
    try:
        validate_status_transition(row.status, status)
    except ValueError as exc:
        raise ConflictError(str(exc)) from exc
    previous = row.status
    if previous != status:
        row.status = status
        row.version += 1
        await audit_service.record(
            session,
            action="engagement.status.change",
            principal=principal,
            resource_type="engagement",
            resource_id=row.id,
            detail={"from": previous, "to": status},
        )
        from app.services.automation import queue_rule_event

        await queue_rule_event(
            session,
            organization_id=principal.organization_id,
            trigger="engagement.status_changed",
            event_key=f"engagement.status_changed:{row.id}:{row.version}",
            context={
                "engagement_id": str(row.id),
                "status": status,
                "previous_status": previous,
                "source": "ptaas",
            },
        )
    return row


async def add_participant(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    payload: EngagementParticipantCreateIn,
) -> EngagementParticipant:
    principal.require(Permission.ASSESSMENT_CREATE)
    await get_engagement(session, principal, engagement_id)
    if payload.user_id is not None:
        membership = await session.scalar(
            select(Membership).where(
                Membership.organization_id == principal.organization_id,
                Membership.user_id == payload.user_id,
            )
        )
        if membership is None:
            raise ResourceNotFoundError("Organization member not found")
    row = EngagementParticipant(
        organization_id=principal.organization_id,
        engagement_id=engagement_id,
        user_id=payload.user_id,
        email=str(payload.email).lower(),
        display_name=payload.display_name,
        role=payload.role,
        status="active" if payload.user_id else "invited",
    )
    session.add(row)
    await session.flush()
    return row


async def add_milestone(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    payload: EngagementMilestoneCreateIn,
) -> EngagementMilestone:
    principal.require(Permission.ASSESSMENT_CREATE)
    await get_engagement(session, principal, engagement_id)
    row = EngagementMilestone(
        organization_id=principal.organization_id,
        engagement_id=engagement_id,
        **payload.model_dump(),
    )
    session.add(row)
    await session.flush()
    return row


async def add_time_entry(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    payload: EngagementTimeEntryCreateIn,
) -> EngagementTimeEntry:
    principal.require(Permission.ASSESSMENT_CREATE)
    engagement = await get_engagement(session, principal, engagement_id)
    if engagement.status in {"completed", "cancelled"}:
        raise ConflictError("Time cannot be added to a closed engagement")
    row = EngagementTimeEntry(
        organization_id=principal.organization_id,
        engagement_id=engagement_id,
        user_id=principal.user_id,
        **payload.model_dump(),
    )
    session.add(row)
    await session.flush()
    return row


async def add_document(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    payload: EngagementDocumentCreateIn,
    *,
    document_id: uuid.UUID | None = None,
) -> EngagementDocument:
    principal.require(Permission.ASSESSMENT_CREATE)
    await get_engagement(session, principal, engagement_id)
    expected_prefix = f"org/{principal.organization_id}/engagements/{engagement_id}/documents/"
    if not payload.storage_key.startswith(expected_prefix):
        raise ConflictError("Document storage reference is outside this engagement")
    row = EngagementDocument(
        id=document_id or uuid.uuid4(),
        organization_id=principal.organization_id,
        engagement_id=engagement_id,
        uploaded_by_id=principal.user_id,
        **payload.model_dump(),
    )
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="engagement.document.add",
        principal=principal,
        resource_type="engagement_document",
        resource_id=row.id,
        detail={
            "engagement_id": str(engagement_id),
            "kind": row.kind,
            "size_bytes": row.size_bytes,
            "client_visible": row.client_visible,
        },
    )
    return row


async def create_retest_round(
    session: AsyncSession,
    principal: Principal,
    engagement_id: uuid.UUID,
    payload: EngagementRetestRoundCreateIn,
) -> EngagementRetestRound:
    principal.require(Permission.FINDING_VALIDATE)
    engagement = await get_engagement(session, principal, engagement_id, for_update=True)
    if engagement.status not in {"active", "retesting"}:
        raise ConflictError("Retesting requires an active engagement")
    await _assessment(session, principal, payload.assessment_id)
    ordinals = list(
        (
            await session.scalars(
                tenant_select(EngagementRetestRound, principal.organization_id).where(
                    EngagementRetestRound.engagement_id == engagement_id
                )
            )
        ).all()
    )
    row = EngagementRetestRound(
        organization_id=principal.organization_id,
        engagement_id=engagement_id,
        assessment_id=payload.assessment_id,
        ordinal=next_retest_ordinal([item.ordinal for item in ordinals]),
        requested_by_id=principal.user_id,
        note=payload.note,
    )
    engagement.status = "retesting"
    engagement.version += 1
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="engagement.retest.request",
        principal=principal,
        resource_type="engagement_retest_round",
        resource_id=row.id,
        detail={"engagement_id": str(engagement_id), "ordinal": row.ordinal},
    )
    return row


async def list_children(session: AsyncSession, principal: Principal, model, engagement_id):
    await get_engagement(session, principal, engagement_id)
    return list(
        (
            await session.scalars(
                tenant_select(model, principal.organization_id)
                .where(model.engagement_id == engagement_id)
                .order_by(model.created_at, model.id)
            )
        ).all()
    )


__all__ = [
    "add_document",
    "add_milestone",
    "add_participant",
    "add_time_entry",
    "create_engagement",
    "create_retest_round",
    "get_engagement",
    "list_children",
    "list_engagements",
    "next_retest_ordinal",
    "update_status",
    "validate_status_transition",
]
