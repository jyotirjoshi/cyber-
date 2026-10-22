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


def test_private_access_policy_allows_only_explicitly_authorized_trusted_identity() -> None:
    from app.services.control_plane import evaluate_private_access_policy

    result = evaluate_private_access_policy(
        request={
            "identity_ref": "user:alice@example.com",
            "groups": ["engineering", "employees"],
            "application_ref": "app:payments-admin",
            "application_tags": ["production", "pci"],
            "device_posture": ["managed", "encrypted", "edr_healthy"],
            "mfa": True,
            "source_country": "IN",
            "identity_risk_score": 12,
            "requested_session_minutes": 120,
        },
        rules={
            "default_action": "deny",
            "allowed_groups": ["engineering"],
            "required_application_tags": ["production", "pci"],
            "required_device_posture": ["managed", "encrypted", "edr_healthy"],
            "require_mfa": True,
            "allowed_countries": ["IN", "SG"],
            "max_identity_risk_score": 40,
            "max_session_minutes": 60,
        },
        policy_mode="enforce",
    )

    assert result == {
        "decision": "allow",
        "enforced": True,
        "would_block": False,
        "session_minutes": 60,
        "reason_codes": ["explicit_group_allow"],
    }


def test_private_access_policy_denies_on_failed_device_posture_even_for_allowed_group() -> None:
    from app.services.control_plane import evaluate_private_access_policy

    result = evaluate_private_access_policy(
        request={
            "identity_ref": "user:alice@example.com",
            "groups": ["engineering"],
            "application_ref": "app:payments-admin",
            "application_tags": ["production"],
            "device_posture": ["managed"],
            "mfa": True,
            "source_country": "IN",
            "identity_risk_score": 5,
            "requested_session_minutes": 30,
        },
        rules={
            "default_action": "deny",
            "allowed_groups": ["engineering"],
            "required_device_posture": ["managed", "encrypted"],
            "require_mfa": True,
        },
        policy_mode="enforce",
    )

    assert result["decision"] == "deny"
    assert result["enforced"] is True
    assert result["would_block"] is True
    assert result["reason_codes"] == ["device_posture_failed:encrypted"]


def test_private_access_monitor_mode_records_would_block_without_denying() -> None:
    from app.services.control_plane import evaluate_private_access_policy

    result = evaluate_private_access_policy(
        request={
            "identity_ref": "user:bob@example.com",
            "groups": [],
            "application_ref": "app:finance",
            "application_tags": [],
            "device_posture": [],
            "mfa": False,
            "source_country": "US",
            "identity_risk_score": 90,
            "requested_session_minutes": 15,
        },
        rules={"default_action": "deny", "allowed_groups": ["finance"]},
        policy_mode="monitor",
    )

    assert result == {
        "decision": "allow",
        "enforced": False,
        "would_block": True,
        "session_minutes": 15,
        "reason_codes": ["no_explicit_allow"],
    }


def test_secure_web_policy_bundle_combines_enforced_rules_and_deny_wins() -> None:
    from app.services.control_plane import compile_secure_web_policy

    bundle = compile_secure_web_policy(
        [
            {
                "id": "policy-1",
                "version": 2,
                "kind": "secure_web_gateway",
                "mode": "enforce",
                "status": "active",
                "rules": {
                    "allow_domains": ["example.com", "*.corp.example"],
                    "deny_domains": ["bad.example.com"],
                },
            },
            {
                "id": "policy-2",
                "version": 1,
                "kind": "firewall",
                "mode": "enforce",
                "status": "active",
                "rules": {
                    "allow_domains": ["updates.example.com", "bad.example.com"],
                    "deny_domains": ["malware.example"],
                },
            },
            {
                "id": "ignored",
                "version": 1,
                "kind": "secure_web_gateway",
                "mode": "monitor",
                "status": "active",
                "rules": {"allow_domains": ["monitor-only.example"]},
            },
        ]
    )

    assert bundle["allow"] == ["*.corp.example", "example.com", "updates.example.com"]
    assert bundle["deny"] == ["bad.example.com", "malware.example"]
    assert bundle["policy_versions"] == ["policy-1:2", "policy-2:1"]
    assert len(bundle["digest"]) == 64


def test_native_ai_posture_detects_toxic_access_without_an_external_connector() -> None:
    from app.services.control_plane import evaluate_native_ai_posture

    decision = evaluate_native_ai_posture(
        {
            "kind": "ai_agent",
            "approved": False,
            "owner_team": None,
            "internet_exposed": True,
            "sensitivity": "restricted",
            "classifications": [],
            "permissions": {
                "principals": ["*"],
                "tool_scopes": ["admin", "write"],
            },
            "attributes": {
                "authentication": "none",
                "data_connections": [{"name": "customer-db", "reviewed": False}],
                "configuration_drift": True,
            },
        }
    )

    assert decision["decision"] == "block"
    assert decision["severity"] == "critical"
    assert decision["score"] == Decimal("100.00")
    assert {item["code"] for item in decision["findings"]} == {
        "unapproved_ai_resource",
        "ai_owner_missing",
        "sensitive_ai_endpoint_exposed",
        "anonymous_ai_access",
        "wildcard_principal",
        "privileged_tool_scope",
        "unreviewed_data_connection",
        "configuration_drift",
    }


def test_native_ai_posture_allows_a_governed_resource() -> None:
    from app.services.control_plane import evaluate_native_ai_posture

    decision = evaluate_native_ai_posture(
        {
            "kind": "ai_model",
            "approved": True,
            "owner_team": "AI Platform",
            "internet_exposed": False,
            "sensitivity": "internal",
            "classifications": ["model"],
            "permissions": {"principals": ["group:ai-platform"], "tool_scopes": ["read"]},
            "attributes": {
                "authentication": "oidc",
                "data_connections": [{"name": "catalog", "reviewed": True}],
                "configuration_drift": False,
            },
        }
    )

    assert decision == {
        "decision": "allow",
        "severity": "info",
        "score": Decimal("0.00"),
        "findings": [],
        "recommended_controls": [],
    }


def test_native_ai_posture_marks_non_ai_resources_not_applicable() -> None:
    from app.services.control_plane import evaluate_native_ai_posture

    decision = evaluate_native_ai_posture({"kind": "endpoint"})

    assert decision["decision"] == "not_applicable"
    assert decision["score"] == Decimal("0.00")


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
    assert "/control-plane/native-posture/assess" in paths
    assert "/control-plane/recommendations/{recommendation_id}/decision" in paths
    assert "/control-plane/private-access/evaluate" in paths
    assert "/control-plane/secure-web/policy-bundle" in paths


def test_private_access_request_rejects_unbounded_session_duration() -> None:
    from pydantic import ValidationError

    from app.schemas.control_plane import PrivateAccessEvaluateIn

    with pytest.raises(ValidationError):
        PrivateAccessEvaluateIn(
            policy_id="d631db3e-85a4-4e9d-a43d-d98b82608e21",
            request_id="access-1",
            identity_ref="user:alice@example.com",
            application_ref="app:payments",
            requested_session_minutes=10_081,
        )
