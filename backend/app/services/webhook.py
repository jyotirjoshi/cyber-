"""Signed outbound webhook primitives.

Transport orchestration belongs in the durable notification/outbox path. This
module intentionally owns only the cryptographic and destination guarantees so
every caller signs precisely the bytes it sends.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.core.config import Settings
from app.core.crypto import get_cipher
from app.core.errors import IntegrationError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.platform import WebhookSubscription
from app.db.repository import tenant_select
from app.schemas.webhook import WebhookSubscriptionCreateIn, validate_webhook_url
from app.services.context import Principal

if TYPE_CHECKING:
    from app.db.models.notification import Notification


def signature_for_payload(secret: str, payload: bytes) -> str:
    """Return an HMAC-SHA256 hex digest for the exact serialized body."""
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class IssuedWebhookSubscription:
    subscription: WebhookSubscription
    secret: str


async def create_subscription(
    session,
    principal: Principal,
    payload: WebhookSubscriptionCreateIn,
    *,
    settings: Settings,
) -> IssuedWebhookSubscription:
    """Create a tenant destination and reveal its verifier secret exactly once."""
    principal.require(Permission.ORG_MANAGE)
    secret = secrets.token_urlsafe(32)
    subscription = WebhookSubscription(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        url=payload.url,
        event_types=payload.event_types,
        secret_ciphertext=get_cipher(settings).encrypt(secret),
    )
    session.add(subscription)
    await session.flush()
    return IssuedWebhookSubscription(subscription=subscription, secret=secret)


async def disable_subscription(
    session, principal: Principal, subscription_id: uuid.UUID
) -> WebhookSubscription:
    """Turn off one tenant destination without deleting its delivery evidence."""
    principal.require(Permission.ORG_MANAGE)
    subscription = (
        await session.execute(
            tenant_select(WebhookSubscription, principal.organization_id)
            .where(WebhookSubscription.id == subscription_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if subscription is None:
        raise ResourceNotFoundError("Webhook subscription not found")
    if subscription.is_enabled:
        subscription.is_enabled = False
        subscription.disabled_at = dt.datetime.now(dt.UTC)
    return subscription


async def rotate_subscription_secret(
    session,
    principal: Principal,
    subscription_id: uuid.UUID,
    *,
    settings: Settings,
) -> IssuedWebhookSubscription:
    """Replace an active destination's signing secret and reveal it exactly once."""
    principal.require(Permission.ORG_MANAGE)
    subscription = (
        await session.execute(
            tenant_select(WebhookSubscription, principal.organization_id)
            .where(
                WebhookSubscription.id == subscription_id,
                WebhookSubscription.is_enabled.is_(True),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if subscription is None:
        raise ResourceNotFoundError("Active webhook subscription not found")

    secret = secrets.token_urlsafe(32)
    subscription.secret_ciphertext = get_cipher(settings).encrypt(secret)
    await session.flush()
    return IssuedWebhookSubscription(subscription=subscription, secret=secret)


def _delivery_body(notification: Notification) -> bytes:
    """The exact bounded JSON bytes covered by the receiver-visible signature."""
    payload = notification.payload if isinstance(notification.payload, dict) else {}
    event_name = str(payload.get("webhook_event") or "")
    body = {
        "id": str(notification.id),
        "event": event_name,
        "occurred_at": notification.created_at.isoformat()
        if notification.created_at is not None
        else dt.datetime.now(dt.UTC).isoformat(),
        "organization_id": str(notification.organization_id),
        "data": {
            "resource_type": notification.resource_type,
            "resource_id": notification.resource_id,
            "subject": notification.subject,
            "body": notification.body,
        },
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


async def _resolve_public_addresses(url: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Resolve a webhook once and reject the entire answer if any address is non-public.

    Returning the resolved addresses lets the caller connect to exactly the
    addresses checked here. Re-resolving the hostname inside the HTTP client
    would leave a DNS-rebinding window between validation and connection.
    """
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if hostname is None:  # ``validate_webhook_url`` should have rejected this.
        raise IntegrationError(
            "Webhook destination has no hostname.",
            provider="webhook",
            retryable=False,
        )
    try:
        ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii")
        port = parsed.port or 443
    except (UnicodeError, ValueError) as exc:
        raise IntegrationError(
            "Webhook destination is invalid.",
            provider="webhook",
            retryable=False,
        ) from exc

    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            ascii_hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, UnicodeError) as exc:
        raise IntegrationError(
            "Webhook destination could not be resolved.",
            provider="webhook",
            retryable=True,
        ) from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for record in records:
        try:
            addresses.add(ipaddress.ip_address(record[4][0]))
        except (IndexError, TypeError, ValueError):
            continue
    if not addresses:
        raise IntegrationError(
            "Webhook destination did not resolve to an IP address.",
            provider="webhook",
            retryable=True,
        )
    if any(not address.is_global for address in addresses):
        raise IntegrationError(
            "Webhook destination resolved to a non-public address.",
            provider="webhook",
            retryable=False,
        )
    return tuple(sorted(addresses, key=lambda address: (address.version, int(address))))


def _pinned_destination(
    url: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[str, str, str]:
    """Build an IP-pinned URL plus the original HTTP Host and TLS SNI names."""
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if hostname is None:
        raise IntegrationError(
            "Webhook destination has no hostname.",
            provider="webhook",
            retryable=False,
        )
    tls_hostname = hostname.rstrip(".").encode("idna").decode("ascii")
    address_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    explicit_port = parsed.port
    pinned_netloc = address_host
    host_header = f"[{tls_hostname}]" if ":" in tls_hostname else tls_hostname
    if explicit_port is not None and explicit_port != 443:
        pinned_netloc = f"{pinned_netloc}:{explicit_port}"
        host_header = f"{host_header}:{explicit_port}"
    pinned_url = urlunsplit(("https", pinned_netloc, parsed.path, parsed.query, ""))
    return pinned_url, host_header, tls_hostname


async def deliver_notification(session, notification: Notification, *, settings: Settings) -> None:
    """POST a subscription's signed delivery without following attacker-controlled redirects."""
    payload = notification.payload if isinstance(notification.payload, dict) else {}
    try:
        subscription_id = uuid.UUID(str(payload.get("webhook_subscription_id") or ""))
    except ValueError as exc:
        raise IntegrationError("Webhook delivery has no valid subscription.", provider="webhook") from exc
    subscription = (
        await session.execute(
            tenant_select(WebhookSubscription, notification.organization_id).where(
                WebhookSubscription.id == subscription_id,
                WebhookSubscription.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if subscription is None:
        raise IntegrationError(
            "Webhook subscription is unavailable.",
            provider="webhook",
            retryable=False,
        )
    url = validate_webhook_url(subscription.url)
    secret = get_cipher(settings).decrypt(subscription.secret_ciphertext).reveal()
    body = _delivery_body(notification)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Cynux-Webhook/1.0",
        "X-Cynux-Delivery": str(notification.id),
        "X-Cynux-Event": str(payload.get("webhook_event") or ""),
        "X-Cynux-Signature-256": f"sha256={signature_for_payload(secret, body)}",
    }
    addresses = await _resolve_public_addresses(url)
    response: httpx.Response | None = None
    last_transport_error: httpx.RequestError | None = None
    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for address in addresses:
            pinned_url, host_header, tls_hostname = _pinned_destination(url, address)
            request = client.build_request(
                "POST",
                pinned_url,
                content=body,
                headers={**headers, "Host": host_header},
                extensions={"sni_hostname": tls_hostname},
            )
            try:
                response = await client.send(request, follow_redirects=False)
                break
            except httpx.RequestError as exc:
                last_transport_error = exc
    if response is None:
        raise IntegrationError(
            "Webhook endpoint could not be reached.",
            provider="webhook",
            retryable=True,
        ) from last_transport_error
    if response.status_code < 200 or response.status_code >= 300:
        retryable = response.status_code >= 500 or response.status_code in {408, 429}
        raise IntegrationError(
            f"Webhook endpoint returned HTTP {response.status_code}.",
            provider="webhook",
            retryable=retryable,
        )


__all__ = [
    "IssuedWebhookSubscription",
    "create_subscription",
    "deliver_notification",
    "disable_subscription",
    "rotate_subscription_secret",
    "signature_for_payload",
]
