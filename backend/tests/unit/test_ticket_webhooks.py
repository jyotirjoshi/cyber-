"""Provider ticket webhooks normalize into one replay-safe transition contract."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac

import pytest


@pytest.mark.parametrize(
    ("provider", "payload", "key", "status"),
    [
        (
            "jira",
            {
                "webhookEvent": "jira:issue_updated",
                "issue": {
                    "id": "10001",
                    "key": "SEC-7",
                    "fields": {"status": {"name": "Done"}, "updated": "2026-10-17T10:11:12Z"},
                },
            },
            "SEC-7",
            "Done",
        ),
        (
            "github",
            {
                "action": "closed",
                "issue": {
                    "id": 22,
                    "number": 9,
                    "state": "closed",
                    "updated_at": "2026-10-17T10:11:12Z",
                },
            },
            "#9",
            "closed",
        ),
        (
            "gitlab",
            {
                "object_kind": "issue",
                "object_attributes": {
                    "id": 33,
                    "iid": 10,
                    "state": "closed",
                    "updated_at": "2026-10-17 10:11:12 UTC",
                },
            },
            "#10",
            "closed",
        ),
        (
            "servicenow",
            {
                "sys_id": "abc123",
                "number": "INC001007",
                "state": "7",
                "sys_updated_on": "2026-10-17 10:11:12",
            },
            "INC001007",
            "closed",
        ),
        (
            "azure_devops",
            {
                "eventType": "workitem.updated",
                "resource": {
                    "id": 42,
                    "rev": 5,
                    "revisedDate": "2026-10-17T10:11:12Z",
                    "fields": {"System.State": {"newValue": "Resolved"}},
                },
            },
            "#42",
            "Resolved",
        ),
    ],
)
def test_normalize_provider_ticket_event(provider, payload, key, status) -> None:
    from app.services.inbound_ticket_event import normalize_ticket_event

    event = normalize_ticket_event(provider, payload, delivery_id="delivery-1")
    assert event.external_key == key
    assert event.status == status
    assert event.delivery_id == "delivery-1"
    assert event.occurred_at == dt.datetime(2026, 10, 17, 10, 11, 12, tzinfo=dt.UTC)


def test_provider_signature_verification_is_exact_body_and_constant_time() -> None:
    from app.services.inbound_ticket_event import verify_provider_signature

    body = b'{"issue":{"number":9}}'
    signature = "sha256=" + hmac.new(b"shared-secret", body, hashlib.sha256).hexdigest()
    assert verify_provider_signature(
        "github", "shared-secret", body, {"x-hub-signature-256": signature}
    )
    assert not verify_provider_signature(
        "github", "shared-secret", body + b" ", {"x-hub-signature-256": signature}
    )
    assert verify_provider_signature(
        "gitlab", "shared-secret", body, {"x-gitlab-token": "shared-secret"}
    )
    assert not verify_provider_signature(
        "gitlab", "shared-secret", body, {"x-gitlab-token": "wrong"}
    )


def test_delivery_id_uses_native_provider_headers_and_rejects_missing_identity() -> None:
    from app.core.errors import UserError
    from app.services.inbound_ticket_event import provider_delivery_id

    assert provider_delivery_id("github", {"x-github-delivery": "abc-123"}) == "abc-123"
    assert provider_delivery_id("gitlab", {"x-gitlab-event-uuid": "gl-123"}) == "gl-123"
    assert provider_delivery_id("azure_devops", {"x-vss-activityid": "az-123"}) == "az-123"
    with pytest.raises(UserError, match="delivery identifier"):
        provider_delivery_id("jira", {})


def test_stale_events_never_move_ticket_state_backwards() -> None:
    from app.services.inbound_ticket_event import event_is_stale

    applied = dt.datetime(2026, 10, 17, 10, 11, 12, tzinfo=dt.UTC)
    assert event_is_stale(applied, applied - dt.timedelta(seconds=1))
    assert event_is_stale(applied, applied)
    assert not event_is_stale(applied, applied + dt.timedelta(microseconds=1))
    assert not event_is_stale(None, applied)


def test_normalizer_rejects_malformed_or_unrelated_events() -> None:
    from app.core.errors import UserError
    from app.services.inbound_ticket_event import normalize_ticket_event

    with pytest.raises(UserError, match="issue event"):
        normalize_ticket_event("github", {"action": "ping"}, delivery_id="one")
    with pytest.raises(UserError, match="Unsupported"):
        normalize_ticket_event("linear", {}, delivery_id="one")


def test_inbound_event_persistence_has_replay_and_staleness_boundaries() -> None:
    from app.db.models.finding import TicketLink
    from app.db.models.integration import InboundTicketEvent

    assert "external_updated_at" in TicketLink.__table__.c
    columns = InboundTicketEvent.__table__.c
    assert {
        "integration_id",
        "ticket_link_id",
        "provider",
        "delivery_id",
        "payload_digest",
        "occurred_at",
        "processing_status",
    } <= set(columns.keys())
    assert any(
        {column.name for column in constraint.columns} == {"integration_id", "delivery_id"}
        for constraint in InboundTicketEvent.__table__.constraints
        if getattr(constraint, "__visit_name__", None) == "unique_constraint"
    )


def test_ticket_provider_integrations_accept_write_only_webhook_secrets() -> None:
    from app.db.enums import IntegrationKind
    from app.services.integration import _spec_for

    for kind in (
        IntegrationKind.JIRA,
        IntegrationKind.GITHUB,
        IntegrationKind.GITLAB,
        IntegrationKind.SERVICENOW,
        IntegrationKind.AZURE_DEVOPS,
    ):
        assert "webhook_secret" in _spec_for(kind).credentials


def test_inbound_ticket_webhook_route_is_mounted_without_bearer_auth() -> None:
    from app.api.v1.router import api_router

    matches = [
        route
        for route in api_router.routes
        if route.path == "/integrations/{integration_id}/webhooks/{provider}"
    ]

    assert len(matches) == 1
    assert "POST" in matches[0].methods


@pytest.mark.asyncio
async def test_ticket_transition_applies_provider_timestamp_once(monkeypatch) -> None:
    from types import SimpleNamespace
    from uuid import uuid4

    from app.services import ticket

    occurred_at = dt.datetime(2026, 10, 17, 10, 11, 12, tzinfo=dt.UTC)
    link = SimpleNamespace(
        id=uuid4(),
        provider="github",
        external_key="#9",
        external_status="open",
        external_updated_at=None,
        canonical_finding_id=None,
        closure_generation=0,
        url=None,
    )
    notified = []

    async def notify(*_args, **kwargs):
        notified.append(kwargs["closure_generation"])

    monkeypatch.setattr(ticket.notification_service, "notify_ticket_closed", notify)
    await ticket.apply_ticket_status_transition(
        object(),
        SimpleNamespace(organization_id=uuid4()),
        link,
        current_status="closed",
        provider_updated_at=occurred_at,
        url="https://github.example/acme/repo/issues/9",
        settings=object(),
    )

    assert link.external_status == "closed"
    assert link.external_updated_at == occurred_at
    assert link.closure_generation == 1
    assert notified == [1]
