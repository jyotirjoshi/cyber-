from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.core.errors import PermissionDeniedError


def test_event_correlation_groups_related_sources_without_exposing_identity() -> None:
    from app.services.control_plane import correlation_key_for_event

    org = uuid.uuid4()
    asset = uuid.uuid4()
    occurred = dt.datetime(2026, 10, 20, 10, 30, tzinfo=dt.UTC)
    first = correlation_key_for_event(
        organization_id=org,
        occurred_at=occurred,
        asset_id=asset,
        resource_id=None,
        identity_ref="alice@example.com",
    )
    second = correlation_key_for_event(
        organization_id=org,
        occurred_at=occurred + dt.timedelta(hours=2),
        asset_id=asset,
        resource_id=None,
        identity_ref="alice@example.com",
    )

    assert first == second
    assert "alice" not in first
    assert str(asset) not in first


def test_threat_story_merge_is_deduplicated_and_time_ordered() -> None:
    from app.services.control_plane import merge_story_values

    initial = {
        "event_ids": ["event-a"],
        "asset_ids": ["asset-a"],
        "identity_refs": ["identity:a"],
        "timeline": [{"event_id": "event-a", "occurred_at": "2026-10-20T11:00:00+00:00"}],
        "severity": "medium",
    }
    merged = merge_story_values(
        initial,
        event_id="event-b",
        asset_id="asset-a",
        identity_ref="identity:a",
        occurred_at=dt.datetime(2026, 10, 20, 10, 0, tzinfo=dt.UTC),
        severity="critical",
        event_type="canary_triggered",
        resource_id="endpoint-7",
    )

    assert merged["event_ids"] == ["event-a", "event-b"]
    assert merged["asset_ids"] == ["asset-a"]
    assert merged["severity"] == "critical"
    assert merged["timeline"][0]["event_id"] == "event-b"
    assert merged["timeline"][0]["resource_id"] == "endpoint-7"


def test_endpoint_correlation_keeps_same_identity_separate_by_endpoint() -> None:
    """Removing endpoint identity from the anchor must fail this test."""

    from app.services.control_plane import correlation_key_for_event

    org = uuid.uuid4()
    occurred = dt.datetime(2026, 10, 21, tzinfo=dt.UTC)
    first = correlation_key_for_event(
        organization_id=org,
        occurred_at=occurred,
        asset_id=None,
        resource_id=uuid.uuid4(),
        identity_ref="employee-17",
    )
    second = correlation_key_for_event(
        organization_id=org,
        occurred_at=occurred,
        asset_id=None,
        resource_id=uuid.uuid4(),
        identity_ref="employee-17",
    )
    assert first != second


def test_only_actionable_endpoint_events_create_threat_stories() -> None:
    """Informational endpoint observations must not create hot-row threat stories."""

    from app.services.control_plane import should_correlate_security_event

    assert not should_correlate_security_event(category="endpoint", severity="info")
    assert not should_correlate_security_event(category="endpoint", severity="medium")
    assert should_correlate_security_event(category="endpoint", severity="high")
    assert should_correlate_security_event(category="incident", severity="low")


def test_experience_score_blends_availability_latency_and_errors() -> None:
    from app.services.control_plane import calculate_experience_score

    healthy = calculate_experience_score(availability=1, latency_ms=100, error_rate=0)
    degraded = calculate_experience_score(availability=0.98, latency_ms=1500, error_rate=0.08)

    assert healthy == Decimal("98.33")
    assert degraded < Decimal("60")


def test_native_experience_probe_contract_is_bounded_and_private() -> None:
    from app.schemas.control_plane import ExperienceProbeIn

    payload = ExperienceProbeIn(
        event_key="journey:checkout:1",
        journey_key="checkout",
        journey_name="Customer checkout",
        location="branch-mumbai",
        occurred_at=dt.datetime(2026, 10, 22, tzinfo=dt.UTC),
        available=True,
        status_code=200,
        dns_ms=12.1,
        connect_ms=18.2,
        tls_ms=24.3,
        ttfb_ms=95.4,
        total_ms=120.5,
        certificate_days_remaining=48,
        target_digest="a" * 64,
    )
    assert payload.total_ms == 120.5
    assert "https://" not in repr(payload)

    with pytest.raises(ValidationError):
        ExperienceProbeIn(**{**payload.model_dump(), "total_ms": -1})
    with pytest.raises(ValidationError):
        ExperienceProbeIn(**{**payload.model_dump(), "url": "https://secret.example"})


def test_experience_probe_score_accounts_for_certificate_and_outage() -> None:
    from app.services.control_plane import calculate_probe_score

    healthy = calculate_probe_score(
        available=True, status_code=200, total_ms=150, certificate_days_remaining=60
    )
    expiring = calculate_probe_score(
        available=True, status_code=200, total_ms=150, certificate_days_remaining=3
    )
    outage = calculate_probe_score(
        available=False, status_code=None, total_ms=0, certificate_days_remaining=None
    )

    assert healthy > Decimal("90")
    assert expiring < healthy
    assert outage == Decimal("0.00")


def test_deception_digests_are_stable_and_non_reversible() -> None:
    from app.services.control_plane import canary_digest, source_address_digest

    token = "long-random-canary-token-123456"
    first = canary_digest(token)
    assert first == canary_digest(token)
    assert token not in first
    assert source_address_digest("203.0.113.9") == source_address_digest("203.0.113.9")
    assert len(source_address_digest("203.0.113.9")) == 64


def test_control_plane_operational_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/control-plane/events" in paths
    assert "/control-plane/experience" in paths
    assert "/control-plane/threat-stories" in paths
    assert "/control-plane/canaries" in paths
    assert "/control-plane/canaries/{canary_id}/interactions" in paths
    assert "/control-plane/risk-simulations" in paths
    assert "/control-plane/endpoint/events" in paths
    assert "/control-plane/experience/probes" in paths


def test_native_endpoint_contract_bounds_and_hides_sensitive_telemetry() -> None:
    """Removing telemetry bounds or exposing command lines through repr must fail this test."""

    from app.schemas.control_plane import NativeEndpointEventIn

    payload = NativeEndpointEventIn(
        event_key="sensor-7:42",
        endpoint_key="sensor-7",
        hostname="finance-laptop-7",
        operating_system="windows",
        occurred_at=dt.datetime(2026, 10, 21, tzinfo=dt.UTC),
        event_type="process_start",
        process_name="powershell.exe",
        parent_process_name="winword.exe",
        command_line="powershell.exe -NoProfile Get-Date",
        identity_ref="employee-17",
    )
    assert payload.endpoint_key == "sensor-7"
    assert "Get-Date" not in repr(payload)

    with pytest.raises(ValidationError):
        NativeEndpointEventIn(
            event_key="sensor-7:43",
            endpoint_key="sensor-7",
            hostname="finance-laptop-7",
            operating_system="windows",
            occurred_at=dt.datetime(2026, 10, 21, tzinfo=dt.UTC),
            event_type="process_start",
            command_line="x" * 8193,
        )

    with pytest.raises(ValidationError):
        NativeEndpointEventIn(
            event_key="sensor-7:44",
            endpoint_key="sensor-7",
            hostname="finance-laptop-7",
            operating_system="windows",
            occurred_at=dt.datetime(2026, 10, 21, tzinfo=dt.UTC),
            event_type="process_start",
            attack_techniques=["not-a-technique"],
        )


def test_endpoint_ingest_has_a_machine_specific_permission() -> None:
    """Endpoint keys must not inherit broad integration-management authority."""

    from app.db.enums import Permission, Role, role_has

    assert Permission.ENDPOINT_INGEST.value == "endpoint:ingest"
    assert role_has(Role.ADMIN, Permission.ENDPOINT_INGEST)
    assert role_has(Role.OWNER, Permission.ENDPOINT_INGEST)
    assert not role_has(Role.DEVELOPER, Permission.ENDPOINT_INGEST)


@pytest.mark.asyncio
async def test_endpoint_ingest_scope_cannot_use_generic_control_plane_writes() -> None:
    """A sensor credential must be confined to the bounded endpoint ingestion route."""

    from app.db.enums import Permission
    from app.schemas.control_plane import SecurityEventIn, SecurityResourceUpsertIn
    from app.services.context import Principal
    from app.services.control_plane import ingest_event, upsert_resource

    principal = Principal.for_api_key(
        organization_id=uuid.uuid4(),
        scopes=frozenset({Permission.ENDPOINT_INGEST}),
    )
    now = dt.datetime(2026, 10, 21, tzinfo=dt.UTC)
    with pytest.raises(PermissionDeniedError):
        await upsert_resource(
            object(),
            principal,
            SecurityResourceUpsertIn(
                resource_key="arbitrary",
                kind="identity",
                name="Not allowed",
                source_kind="cynux_endpoint_sensor",
                source_key="sensor-7",
                observed_at=now,
                confidence=Decimal("1"),
            ),
        )
    with pytest.raises(PermissionDeniedError):
        await ingest_event(
            object(),
            principal,
            SecurityEventIn(
                event_key="arbitrary",
                category="endpoint",
                event_type="process_start",
                source_kind="cynux_endpoint_sensor",
                occurred_at=now,
                severity="critical",
                summary="Not allowed",
                evidence={"command_line": "raw"},
            ),
        )
