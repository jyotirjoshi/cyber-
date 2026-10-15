"""Safe tenant webhook subscription contracts."""

from __future__ import annotations

import datetime as dt
import ipaddress
import uuid
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

WEBHOOK_EVENTS = frozenset(
    {
        "assessment.completed",
        "assessment.failed",
        "asset.created",
        "finding.created",
        "ticket.created",
        "ticket.closed",
        "sla.breached",
    }
)


def validate_webhook_url(value: str) -> str:
    """Accept only an HTTPS public destination, never a local control plane."""
    try:
        parsed = urlsplit(value.strip())
    except ValueError as exc:
        raise ValueError("webhook url is invalid") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("webhook url must be a credential-free HTTPS URL")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.lower() == "localhost" or hostname.lower().endswith(".local"):
            raise ValueError("webhook url must target a public host") from None
    else:
        if not address.is_global:
            raise ValueError("webhook url must target a public address")
    return value.strip()


class WebhookSubscriptionCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=12, max_length=2048)
    event_types: list[str] = Field(min_length=1, max_length=16)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        if not (normalized := value.strip()):
            raise ValueError("webhook name cannot be blank")
        return normalized

    @field_validator("url")
    @classmethod
    def require_safe_url(cls, value: str) -> str:
        return validate_webhook_url(value)

    @field_validator("event_types")
    @classmethod
    def require_known_unique_events(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(value not in WEBHOOK_EVENTS for value in values):
            raise ValueError("event_types must be unique supported webhook events")
        return values


class WebhookSubscriptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    url: str
    event_types: list[str]
    is_enabled: bool
    disabled_at: dt.datetime | None
    created_at: dt.datetime


class WebhookSubscriptionIssuedOut(WebhookSubscriptionOut):
    """The verification secret, returned exactly once on creation."""

    secret: str


class WebhookDeliveryOut(BaseModel):
    """A safe, receiver-neutral audit record for one outbound delivery."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event: str
    status: str
    subject: str | None
    resource_type: str | None
    resource_id: str | None
    attempts: int
    sent_at: dt.datetime | None
    next_retry_at: dt.datetime | None
    last_error: str | None
    created_at: dt.datetime


__all__ = [
    "WEBHOOK_EVENTS",
    "WebhookSubscriptionCreateIn",
    "WebhookDeliveryOut",
    "WebhookSubscriptionIssuedOut",
    "WebhookSubscriptionOut",
    "validate_webhook_url",
]
