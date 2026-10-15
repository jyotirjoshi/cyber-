"""Production contracts for tenant-controlled outbound webhooks."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from pydantic import ValidationError


def test_webhook_subscription_is_tenant_owned_and_has_lifecycle_fields() -> None:
    from app.db.models.platform import WebhookSubscription

    columns = WebhookSubscription.__table__.c
    assert columns.organization_id.nullable is False
    assert {"url", "event_types", "secret_ciphertext", "is_enabled", "disabled_at"} <= set(
        columns.keys()
    )


def test_webhook_create_rejects_non_public_or_non_https_delivery_targets() -> None:
    from app.schemas.webhook import WebhookSubscriptionCreateIn

    accepted = WebhookSubscriptionCreateIn(
        name="SIEM export",
        url="https://hooks.example.net/cynux",
        event_types=["assessment.completed"],
    )
    assert str(accepted.url) == "https://hooks.example.net/cynux"

    for url in ("http://hooks.example.net/events", "https://localhost/events", "https://127.0.0.1/events"):
        with pytest.raises(ValidationError):
            WebhookSubscriptionCreateIn(
                name="unsafe",
                url=url,
                event_types=["assessment.completed"],
            )


def test_webhook_signatures_are_hmac_sha256_of_exact_delivery_bytes() -> None:
    from app.services.webhook import signature_for_payload

    payload = b'{"event":"assessment.completed"}'
    secret = "delivery-secret"

    assert signature_for_payload(secret, payload) == hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()


def test_webhook_events_are_explicit_allowlist() -> None:
    from app.schemas.webhook import WebhookSubscriptionCreateIn

    with pytest.raises(ValidationError, match="event_types"):
        WebhookSubscriptionCreateIn(
            name="bad event",
            url="https://hooks.example.net/cynux",
            event_types=["agent.raw_tool_output"],
        )


def test_webhook_catalog_exposes_existing_new_asset_event() -> None:
    from app.schemas.webhook import WebhookSubscriptionCreateIn

    subscription = WebhookSubscriptionCreateIn(
        name="ASM alerts",
        url="https://hooks.example.net/cynux",
        event_types=["asset.created"],
    )

    assert subscription.event_types == ["asset.created"]


def test_webhook_subscription_routes_are_mounted_and_never_list_the_secret() -> None:
    from app.api.v1.router import api_router
    from app.api.v1.webhooks import router
    from app.schemas.webhook import WebhookSubscriptionOut

    assert "/webhooks" in {route.path for route in api_router.routes}
    assert {"/webhooks", "/webhooks/{subscription_id}/disable"} <= {
        route.path for route in router.routes
    }
    assert "secret" not in WebhookSubscriptionOut.model_fields


def test_webhook_creation_has_a_distinct_issue_once_response_and_audit_actions() -> None:
    from app.schemas.webhook import WebhookSubscriptionIssuedOut
    from app.services.audit import AuditAction

    assert "secret" in WebhookSubscriptionIssuedOut.model_fields
    assert AuditAction.WEBHOOK_CREATE == "webhook.create"
    assert AuditAction.WEBHOOK_DISABLE == "webhook.disable"


@pytest.mark.asyncio
async def test_create_route_returns_the_issue_once_secret(monkeypatch) -> None:
    """The response projection must not validate before the secret is attached."""
    import datetime as dt
    import uuid
    from types import SimpleNamespace

    from app.api.v1 import webhooks
    from app.db.enums import Role
    from app.schemas.webhook import WebhookSubscriptionCreateIn
    from app.services.context import Principal

    subscription = SimpleNamespace(
        id=uuid.uuid4(),
        name="SIEM export",
        url="https://hooks.example.net/cynux",
        event_types=["assessment.completed"],
        is_enabled=True,
        disabled_at=None,
        created_at=dt.datetime.now(dt.UTC),
    )

    async def create(*_args, **_kwargs):
        return SimpleNamespace(subscription=subscription, secret="issue-once-secret")

    async def audit(*_args, **_kwargs):
        return None

    class Session:
        async def commit(self):
            return None

    monkeypatch.setattr(webhooks.webhook_service, "create_subscription", create)
    monkeypatch.setattr(webhooks, "record", audit)
    result = await webhooks.create_webhook_subscription(
        WebhookSubscriptionCreateIn(
            name="SIEM export",
            url="https://hooks.example.net/cynux",
            event_types=["assessment.completed"],
        ),
        Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER),
        Session(),
        SimpleNamespace(),
    )

    assert result.secret == "issue-once-secret"
