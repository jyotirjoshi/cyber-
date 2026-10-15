"""Tenant operations for the durable external-notification outbox."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PrincipalDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import NotificationStatus, Permission
from app.db.models.notification import Notification
from app.db.repository import tenant_select
from app.schemas.notification import ExternalDeliveryOut
from app.services.audit import AuditAction, record

router = APIRouter(prefix="/notifications", tags=["notifications"])

_EXTERNAL_CHANNELS = ("slack", "email", "pagerduty", "webhook", "splunk")


@router.get("/deliveries", response_model=list[ExternalDeliveryOut])
async def list_external_deliveries(
    principal: PrincipalDep,
    session: DbSession,
    status: str | None = Query(default=None, pattern="^(pending|sent|failed)$"),
    limit: int = Query(default=100, ge=1, le=250),
) -> list[Notification]:
    """List recent durable outbound deliveries for integration operations."""
    principal.require(Permission.ORG_MANAGE)
    stmt = (
        tenant_select(Notification, principal.organization_id)
        .where(Notification.channel.in_(_EXTERNAL_CHANNELS))
        .order_by(Notification.created_at.desc(), Notification.id.desc())
        .limit(limit)
    )
    if status is not None:
        stmt = stmt.where(Notification.status == status)
    return list((await session.scalars(stmt)).all())


@router.post("/deliveries/{delivery_id}/retry", response_model=ExternalDeliveryOut)
async def retry_external_delivery(
    delivery_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> Notification:
    """Requeue a terminal external delivery after an operator fixes its integration."""
    principal.require(Permission.ORG_MANAGE)
    delivery = await session.scalar(
        tenant_select(Notification, principal.organization_id)
        .where(Notification.id == delivery_id, Notification.channel.in_(_EXTERNAL_CHANNELS))
        .with_for_update()
    )
    if delivery is None:
        raise ResourceNotFoundError("External delivery not found")
    if delivery.status == NotificationStatus.FAILED.value:
        previous_attempts = delivery.attempts
        delivery.status = NotificationStatus.PENDING.value
        # An explicit retry follows a configuration change or a human decision, so it
        # starts a fresh bounded delivery budget rather than instantly exhausting again.
        delivery.attempts = 0
        delivery.last_error = None
        delivery.next_retry_at = None
        await record(
            session,
            action=AuditAction.NOTIFICATION_DELIVERY_RETRY,
            principal=principal,
            resource_type="notification",
            resource_id=delivery.id,
            detail={"channel": delivery.channel, "previous_attempts": previous_attempts},
        )
        await session.commit()
    return delivery


__all__ = ["router"]
