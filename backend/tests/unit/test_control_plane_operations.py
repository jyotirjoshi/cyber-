from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal


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
    )

    assert merged["event_ids"] == ["event-a", "event-b"]
    assert merged["asset_ids"] == ["asset-a"]
    assert merged["severity"] == "critical"
    assert merged["timeline"][0]["event_id"] == "event-b"


def test_experience_score_blends_availability_latency_and_errors() -> None:
    from app.services.control_plane import calculate_experience_score

    healthy = calculate_experience_score(availability=1, latency_ms=100, error_rate=0)
    degraded = calculate_experience_score(availability=0.98, latency_ms=1500, error_rate=0.08)

    assert healthy == Decimal("98.33")
    assert degraded < Decimal("60")


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
