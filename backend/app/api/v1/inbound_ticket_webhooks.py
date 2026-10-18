"""Signed inbound tracker events for bidirectional finding lifecycle sync."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSession, RedisDep, SettingsDep
from app.core.errors import AuthenticationError, ResourceNotFoundError, UserError
from app.db.models.integration import Integration
from app.services import inbound_ticket_event as inbound_service
from app.services.integration import credentials_for

router = APIRouter(prefix="/integrations", tags=["integration-webhooks"])

_MAX_WEBHOOK_BYTES = 1_048_576


class TicketWebhookReceiptOut(BaseModel):
    accepted: bool
    duplicate: bool
    processing_status: str
    receipt_id: uuid.UUID


@router.post(
    "/{integration_id}/webhooks/{provider}",
    response_model=TicketWebhookReceiptOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def receive_ticket_webhook(
    integration_id: uuid.UUID,
    provider: str,
    request: Request,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> TicketWebhookReceiptOut:
    """Authenticate, deduplicate, and apply a provider ticket event.

    This endpoint intentionally has no bearer-token dependency: the exact request body
    is authenticated with the per-integration signing secret before any provider state
    can mutate a finding. The integration row is locked to serialize replay checks.
    """
    provider = provider.strip().lower()
    if provider not in inbound_service.SUPPORTED_INBOUND_TICKET_PROVIDERS:
        raise ResourceNotFoundError("Unsupported ticket webhook provider")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_WEBHOOK_BYTES:
                raise UserError("ticket webhook payload is too large")
        except ValueError as exc:
            raise UserError("ticket webhook content length is invalid") from exc
    body = await request.body()
    if not body or len(body) > _MAX_WEBHOOK_BYTES:
        raise UserError("ticket webhook payload is empty or too large")

    integration = await session.scalar(
        select(Integration)
        .where(Integration.id == integration_id)
        .options(selectinload(Integration.credentials))
        .with_for_update()
    )
    if (
        integration is None
        or integration.kind != provider
        or not integration.is_usable
    ):
        raise ResourceNotFoundError("Active ticket integration not found")

    secrets = credentials_for(integration, settings=settings)
    webhook_secret = secrets.get("webhook_secret")
    if webhook_secret is None or not inbound_service.verify_provider_signature(
        provider,
        webhook_secret.reveal(),
        body,
        request.headers,
    ):
        raise AuthenticationError(
            "invalid ticket webhook signature",
            user_message="The webhook signature is invalid.",
        )
    delivery_id = inbound_service.provider_delivery_id(provider, request.headers)
    try:
        payload: Any = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UserError("ticket webhook body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise UserError("ticket webhook body must be a JSON object")

    event = inbound_service.normalize_ticket_event(
        provider,
        payload,
        delivery_id=delivery_id,
    )
    result = await inbound_service.process_ticket_event(
        session,
        integration,
        event,
        body=body,
        settings=settings,
        redis=redis,
    )
    await session.commit()
    return TicketWebhookReceiptOut(
        accepted=True,
        duplicate=result.duplicate,
        processing_status=result.receipt.processing_status,
        receipt_id=result.receipt.id,
    )


__all__ = ["router"]
