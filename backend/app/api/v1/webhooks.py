"""Tenant-managed signed outbound webhook subscriptions."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import DbSession, PrincipalDep, SettingsDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import NotificationStatus, Permission
from app.db.models.notification import Notification
from app.db.models.platform import WebhookSubscription
from app.db.repository import tenant_select
from app.schemas.webhook import (
    WebhookSubscriptionCreateIn,
    WebhookDeliveryOut,
    WebhookSubscriptionIssuedOut,
    WebhookSubscriptionOut,
)
from app.services import webhook as webhook_service
from app.services.audit import AuditAction, record

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.get("", response_model=list[WebhookSubscriptionOut])
async def list_webhook_subscriptions(
    principal: PrincipalDep, session: DbSession
) -> list[WebhookSubscription]:
    principal.require(Permission.ORG_MANAGE)
    return list(
        (
            await session.scalars(
                tenant_select(WebhookSubscription, principal.organization_id)
                .order_by(WebhookSubscription.created_at.desc())
                .limit(200)
            )
        ).all()
    )


@router.get("/{subscription_id}/deliveries", response_model=list[WebhookDeliveryOut])
async def list_webhook_deliveries(
    subscription_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> list[WebhookDeliveryOut]:
    """Return recent signed delivery outcomes without exposing delivery payloads."""
    principal.require(Permission.ORG_MANAGE)
    subscription = await session.scalar(
        tenant_select(WebhookSubscription, principal.organization_id).where(
            WebhookSubscription.id == subscription_id
        )
    )
    if subscription is None:
        raise ResourceNotFoundError("Webhook subscription not found")

    deliveries = list(
        (
            await session.scalars(
                tenant_select(Notification, principal.organization_id)
                .where(
                    Notification.channel == "webhook",
                    Notification.payload["webhook_subscription_id"].astext == str(subscription_id),
                )
                .order_by(Notification.created_at.desc())
                .limit(100)
            )
        ).all()
    )
    return [WebhookDeliveryOut.model_validate(delivery) for delivery in deliveries]


@router.post(
    "/{subscription_id}/deliveries/{delivery_id}/retry",
    response_model=WebhookDeliveryOut,
)
async def retry_webhook_delivery(
    subscription_id: uuid.UUID,
    delivery_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> WebhookDeliveryOut:
    """Requeue one failed webhook delivery for the durable outbox worker."""
    principal.require(Permission.ORG_MANAGE)
    subscription = await session.scalar(
        tenant_select(WebhookSubscription, principal.organization_id).where(
            WebhookSubscription.id == subscription_id,
            WebhookSubscription.is_enabled.is_(True),
        )
    )
    if subscription is None:
        raise ResourceNotFoundError("Active webhook subscription not found")
    delivery = await session.scalar(
        tenant_select(Notification, principal.organization_id)
        .where(
            Notification.id == delivery_id,
            Notification.channel == "webhook",
            Notification.payload["webhook_subscription_id"].astext == str(subscription_id),
        )
        .with_for_update()
    )
    if delivery is None:
        raise ResourceNotFoundError("Webhook delivery not found")
    if delivery.status == NotificationStatus.FAILED.value:
        previous_attempts = delivery.attempts
        delivery.status = NotificationStatus.PENDING.value
        delivery.attempts = 0
        delivery.last_error = None
        delivery.next_retry_at = None
        await record(
            session,
            action=AuditAction.WEBHOOK_DELIVERY_RETRY,
            principal=principal,
            resource_type="notification",
            resource_id=delivery.id,
            detail={"webhook_subscription_id": str(subscription_id), "previous_attempts": previous_attempts},
        )
        await session.commit()
    return WebhookDeliveryOut.model_validate(delivery)


@router.post("", response_model=WebhookSubscriptionIssuedOut, status_code=status.HTTP_201_CREATED)
async def create_webhook_subscription(
    payload: WebhookSubscriptionCreateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> WebhookSubscriptionIssuedOut:
    issued = await webhook_service.create_subscription(session, principal, payload, settings=settings)
    subscription = issued.subscription
    await record(
        session,
        action=AuditAction.WEBHOOK_CREATE,
        principal=principal,
        resource_type="webhook_subscription",
        resource_id=subscription.id,
        detail={"event_types": subscription.event_types, "url_host": subscription.url.split("/", 3)[2]},
    )
    await session.commit()
    return WebhookSubscriptionIssuedOut.model_validate(
        {**WebhookSubscriptionOut.model_validate(subscription).model_dump(), "secret": issued.secret}
    )


@router.post("/{subscription_id}/disable", response_model=WebhookSubscriptionOut)
async def disable_webhook_subscription(
    subscription_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> WebhookSubscriptionOut:
    subscription = await webhook_service.disable_subscription(session, principal, subscription_id)
    await record(
        session,
        action=AuditAction.WEBHOOK_DISABLE,
        principal=principal,
        resource_type="webhook_subscription",
        resource_id=subscription.id,
        detail={"event_types": subscription.event_types},
    )
    await session.commit()
    return WebhookSubscriptionOut.model_validate(subscription)


@router.post(
    "/{subscription_id}/rotate-secret",
    response_model=WebhookSubscriptionIssuedOut,
)
async def rotate_webhook_subscription_secret(
    subscription_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> WebhookSubscriptionIssuedOut:
    issued = await webhook_service.rotate_subscription_secret(
        session,
        principal,
        subscription_id,
        settings=settings,
    )
    subscription = issued.subscription
    await record(
        session,
        action=AuditAction.WEBHOOK_SECRET_ROTATE,
        principal=principal,
        resource_type="webhook_subscription",
        resource_id=subscription.id,
        detail={"event_types": subscription.event_types},
    )
    await session.commit()
    return WebhookSubscriptionIssuedOut.model_validate(
        {**WebhookSubscriptionOut.model_validate(subscription).model_dump(), "secret": issued.secret}
    )


__all__ = ["router"]
