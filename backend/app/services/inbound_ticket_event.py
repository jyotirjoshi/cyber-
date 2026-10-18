"""Normalize and authenticate provider ticket webhooks before state mutation."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import UserError
from app.db.enums import InboundTicketEventStatus
from app.db.models.finding import TicketLink
from app.db.models.integration import InboundTicketEvent, Integration
from app.services import audit as audit_service
from app.services import ticket as ticket_service
from app.services.context import Principal

SUPPORTED_INBOUND_TICKET_PROVIDERS = frozenset(
    {"jira", "github", "gitlab", "servicenow", "azure_devops"}
)

_DELIVERY_HEADERS: dict[str, tuple[str, ...]] = {
    "jira": ("x-atlassian-webhook-identifier", "x-cynux-delivery-id"),
    "github": ("x-github-delivery", "x-cynux-delivery-id"),
    "gitlab": ("x-gitlab-event-uuid", "x-cynux-delivery-id"),
    "servicenow": ("x-cynux-delivery-id",),
    "azure_devops": ("x-vss-activityid", "x-cynux-delivery-id"),
}


@dataclass(frozen=True, slots=True)
class NormalizedTicketEvent:
    provider: str
    delivery_id: str
    event_type: str
    external_key: str
    external_id: str | None
    status: str
    occurred_at: dt.datetime
    url: str | None = None


@dataclass(frozen=True, slots=True)
class TicketEventResult:
    receipt: InboundTicketEvent
    duplicate: bool


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(value).strip() for key, value in headers.items()}


def provider_delivery_id(provider: str, headers: Mapping[str, str]) -> str:
    normalized = _headers(headers)
    for name in _DELIVERY_HEADERS.get(provider, ("x-cynux-delivery-id",)):
        value = normalized.get(name, "")
        if value and len(value) <= 160:
            return value
    raise UserError(
        "ticket webhook delivery identifier is missing",
        user_message="The webhook delivery identifier is missing.",
    )


def verify_provider_signature(
    provider: str,
    secret: str,
    body: bytes,
    headers: Mapping[str, str],
) -> bool:
    if provider not in SUPPORTED_INBOUND_TICKET_PROVIDERS or not secret:
        return False
    normalized = _headers(headers)
    if provider == "gitlab":
        return hmac.compare_digest(normalized.get("x-gitlab-token", ""), secret)
    provided = normalized.get("x-hub-signature-256") or normalized.get(
        "x-cynux-signature", ""
    )
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


def _timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise UserError("ticket webhook timestamp is missing")
    raw = value.strip()
    if raw.endswith(" UTC"):
        raw = raw[:-4] + "+00:00"
    elif raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        try:
            parsed = dt.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.UTC)
        except ValueError as exc:
            raise UserError("ticket webhook timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def _required(value: Any, name: str, *, limit: int = 160) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise UserError(f"ticket webhook {name} is invalid")
    return text


def normalize_ticket_event(
    provider: str, payload: Mapping[str, Any], *, delivery_id: str
) -> NormalizedTicketEvent:
    if provider not in SUPPORTED_INBOUND_TICKET_PROVIDERS:
        raise UserError("Unsupported ticket webhook provider")
    if not isinstance(payload, Mapping):
        raise UserError("ticket webhook payload is invalid")

    if provider == "jira":
        issue = payload.get("issue")
        if not isinstance(issue, Mapping):
            raise UserError("ticket webhook is not a Jira issue event")
        fields = issue.get("fields")
        fields = fields if isinstance(fields, Mapping) else {}
        status_obj = fields.get("status")
        status_obj = status_obj if isinstance(status_obj, Mapping) else {}
        return NormalizedTicketEvent(
            provider=provider,
            delivery_id=delivery_id,
            event_type=_required(payload.get("webhookEvent") or "issue_updated", "event type"),
            external_key=_required(issue.get("key"), "issue key", limit=80),
            external_id=_required(issue.get("id"), "issue id", limit=80),
            status=_required(status_obj.get("name"), "status", limit=80),
            occurred_at=_timestamp(fields.get("updated") or payload.get("timestamp")),
            url=None,
        )

    if provider == "github":
        issue = payload.get("issue")
        if not isinstance(issue, Mapping):
            raise UserError("ticket webhook is not a GitHub issue event")
        return NormalizedTicketEvent(
            provider=provider,
            delivery_id=delivery_id,
            event_type=_required(payload.get("action"), "event type"),
            external_key=f"#{int(issue['number'])}" if isinstance(issue.get("number"), int) and issue["number"] > 0 else _required(None, "issue key"),
            external_id=_required(issue.get("id") or issue.get("node_id"), "issue id", limit=80),
            status=_required(issue.get("state"), "status", limit=80),
            occurred_at=_timestamp(issue.get("updated_at")),
            url=str(issue.get("html_url") or "")[:1000] or None,
        )

    if provider == "gitlab":
        issue = payload.get("object_attributes")
        if payload.get("object_kind") != "issue" or not isinstance(issue, Mapping):
            raise UserError("ticket webhook is not a GitLab issue event")
        return NormalizedTicketEvent(
            provider=provider,
            delivery_id=delivery_id,
            event_type=_required(issue.get("action") or payload.get("event_type") or "update", "event type"),
            external_key=f"#{int(issue['iid'])}" if isinstance(issue.get("iid"), int) and issue["iid"] > 0 else _required(None, "issue key"),
            external_id=_required(issue.get("id"), "issue id", limit=80),
            status=_required(issue.get("state"), "status", limit=80),
            occurred_at=_timestamp(issue.get("updated_at")),
            url=str(issue.get("url") or "")[:1000] or None,
        )

    if provider == "servicenow":
        issue = payload.get("result", payload)
        if not isinstance(issue, Mapping):
            raise UserError("ticket webhook is not a ServiceNow issue event")
        raw_state = _required(issue.get("state"), "status", limit=80)
        status = "closed" if raw_state in {"6", "7"} else "open" if raw_state in {"-5", "-4", "-3", "-2", "-1", "0", "1", "2", "3"} else raw_state
        return NormalizedTicketEvent(
            provider=provider,
            delivery_id=delivery_id,
            event_type="incident.updated",
            external_key=_required(issue.get("number"), "issue key", limit=80),
            external_id=_required(issue.get("sys_id"), "issue id", limit=80),
            status=status,
            occurred_at=_timestamp(issue.get("sys_updated_on")),
            url=str(issue.get("url") or "")[:1000] or None,
        )

    resource = payload.get("resource")
    if not isinstance(resource, Mapping) or not str(payload.get("eventType") or "").startswith(
        "workitem."
    ):
        raise UserError("ticket webhook is not an Azure DevOps work item event")
    fields = resource.get("fields")
    fields = fields if isinstance(fields, Mapping) else {}
    state = fields.get("System.State")
    if isinstance(state, Mapping):
        state = state.get("newValue") or state.get("value")
    return NormalizedTicketEvent(
        provider=provider,
        delivery_id=delivery_id,
        event_type=_required(payload.get("eventType"), "event type"),
        external_key=f"#{int(resource['id'])}" if isinstance(resource.get("id"), int) and resource["id"] > 0 else _required(None, "issue key"),
        external_id=_required(resource.get("id"), "issue id", limit=80),
        status=_required(state, "status", limit=80),
        occurred_at=_timestamp(resource.get("revisedDate") or payload.get("createdDate")),
        url=str(resource.get("url") or "")[:1000] or None,
    )


def event_is_stale(
    previously_applied_at: dt.datetime | None, event_occurred_at: dt.datetime
) -> bool:
    return previously_applied_at is not None and event_occurred_at <= previously_applied_at


async def process_ticket_event(
    session: AsyncSession,
    integration: Integration,
    event: NormalizedTicketEvent,
    *,
    body: bytes,
    settings: Settings,
    redis: Redis | None = None,
) -> TicketEventResult:
    """Persist and apply one authenticated provider event exactly once.

    The caller locks the integration row before entering this function. That makes the
    ``(integration_id, delivery_id)`` lookup and insert serial for a provider account,
    while the database uniqueness constraint remains the final replay boundary.
    """
    if integration.kind != event.provider or not integration.is_usable:
        raise UserError("ticket webhook provider does not match the integration")

    duplicate = await session.scalar(
        select(InboundTicketEvent).where(
            InboundTicketEvent.integration_id == integration.id,
            InboundTicketEvent.delivery_id == event.delivery_id,
        )
    )
    if duplicate is not None:
        return TicketEventResult(receipt=duplicate, duplicate=True)

    conditions = [TicketLink.external_key == event.external_key]
    if event.external_id is not None:
        conditions.append(TicketLink.external_id == event.external_id)
    link = await session.scalar(
        select(TicketLink)
        .where(
            TicketLink.organization_id == integration.organization_id,
            TicketLink.provider == event.provider,
            or_(*conditions),
        )
        .with_for_update()
    )
    receipt = InboundTicketEvent(
        id=uuid.uuid4(),
        organization_id=integration.organization_id,
        integration_id=integration.id,
        ticket_link_id=link.id if link is not None else None,
        provider=event.provider,
        delivery_id=event.delivery_id,
        payload_digest=hashlib.sha256(body).hexdigest(),
        event_type=event.event_type,
        external_key=event.external_key,
        external_id=event.external_id,
        external_status=event.status,
        occurred_at=event.occurred_at,
        processing_status=InboundTicketEventStatus.RECEIVED.value,
        normalized={
            "provider": event.provider,
            "event_type": event.event_type,
            "external_key": event.external_key,
            "external_id": event.external_id,
            "status": event.status,
            "occurred_at": event.occurred_at.isoformat(),
            "url": event.url,
        },
    )
    session.add(receipt)

    if link is None:
        receipt.processing_status = InboundTicketEventStatus.IGNORED.value
        receipt.ignore_reason = "unlinked_ticket"
    elif event_is_stale(link.external_updated_at, event.occurred_at):
        receipt.processing_status = InboundTicketEventStatus.IGNORED.value
        receipt.ignore_reason = "stale_event"
    else:
        principal = Principal.for_system(organization_id=integration.organization_id)
        await ticket_service.apply_ticket_status_transition(
            session,
            principal,
            link,
            current_status=event.status,
            provider_updated_at=event.occurred_at,
            url=event.url,
            settings=settings,
            redis=redis,
        )
        receipt.processing_status = InboundTicketEventStatus.PROCESSED.value

    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.TICKET_WEBHOOK_RECEIVE,
        principal=Principal.for_system(organization_id=integration.organization_id),
        resource_type="ticket_link" if link is not None else "integration",
        resource_id=link.id if link is not None else integration.id,
        detail={
            "provider": event.provider,
            "delivery_id": event.delivery_id,
            "event_type": event.event_type,
            "processing_status": receipt.processing_status,
            "ignore_reason": receipt.ignore_reason,
            "payload_digest": receipt.payload_digest,
        },
    )
    return TicketEventResult(receipt=receipt, duplicate=False)


__all__ = [
    "NormalizedTicketEvent",
    "SUPPORTED_INBOUND_TICKET_PROVIDERS",
    "TicketEventResult",
    "event_is_stale",
    "normalize_ticket_event",
    "process_ticket_event",
    "provider_delivery_id",
    "verify_provider_signature",
]
