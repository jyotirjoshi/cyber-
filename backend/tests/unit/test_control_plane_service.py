from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest


def test_observation_fingerprint_is_order_independent_and_secret_safe() -> None:
    from app.services.control_plane import observation_fingerprint, safe_metadata

    left = {"hostname": "api.example.com", "labels": {"env": "prod", "team": "edge"}}
    right = {"labels": {"team": "edge", "env": "prod"}, "hostname": "api.example.com"}
    assert observation_fingerprint("aws", "arn:1", left) == observation_fingerprint(
        "aws", "arn:1", right
    )
    assert safe_metadata({"api_token": "super-secret", "url": "https://u:pw@example.com"}) == {
        "api_token": "[REDACTED]",
        "url": "https://u:[REDACTED]@example.com",
    }


def test_identity_confidence_rewards_independent_fresh_sources_and_penalizes_stale_ones() -> None:
    from app.services.control_plane import calculate_identity_confidence

    now = dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    fresh = [
        (Decimal("0.8"), now - dt.timedelta(hours=1)),
        (Decimal("0.7"), now - dt.timedelta(hours=2)),
    ]
    stale = [(Decimal("0.8"), now - dt.timedelta(days=45))]

    assert calculate_identity_confidence(fresh, now=now) == Decimal("0.940")
    assert calculate_identity_confidence(stale, now=now) == Decimal("0.200")


def test_resource_reconciliation_preserves_curated_context() -> None:
    from app.services.control_plane import reconcile_resource_values

    merged = reconcile_resource_values(
        current={
            "owner_team": "Payments",
            "environment": "production",
            "approved": True,
            "attributes": {"curated": "keep", "old": "replace"},
        },
        observed={
            "owner_team": None,
            "environment": "unknown",
            "approved": None,
            "attributes": {"old": "new", "cloud_region": "eu-west-1"},
        },
    )

    assert merged["owner_team"] == "Payments"
    assert merged["environment"] == "production"
    assert merged["approved"] is True
    assert merged["attributes"] == {
        "curated": "keep",
        "old": "new",
        "cloud_region": "eu-west-1",
    }


def test_resource_policy_evaluation_is_deterministic() -> None:
    from app.services.control_plane import evaluate_resource_policy

    decision = evaluate_resource_policy(
        resource={
            "kind": "ai_application",
            "approved": False,
            "internet_exposed": True,
            "sensitivity": "restricted",
            "risk_score": 82,
        },
        rules={
            "require_approved": True,
            "deny_internet_exposed_sensitivities": ["restricted"],
            "max_risk_score": 70,
        },
    )

    assert decision["decision"] == "block"
    assert decision["severity"] == "critical"
    assert decision["score"] == Decimal("100.00")
    assert {item["code"] for item in decision["findings"]} == {
        "unapproved_resource",
        "sensitive_resource_exposed",
        "risk_threshold_exceeded",
    }


def test_recommendation_transition_rejects_invalid_or_replayed_actions() -> None:
    from app.core.errors import ConflictError
    from app.services.control_plane import next_recommendation_status

    assert next_recommendation_status("proposed", "approve") == "approved"
    assert next_recommendation_status("approved", "apply") == "applying"
    with pytest.raises(ConflictError):
        next_recommendation_status("applied", "apply")
    with pytest.raises(ConflictError):
        next_recommendation_status("proposed", "apply")


def test_control_plane_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/control-plane/resources" in paths
    assert "/control-plane/posture" in paths
    assert "/control-plane/policies" in paths
    assert "/control-plane/recommendations/{recommendation_id}/decision" in paths
