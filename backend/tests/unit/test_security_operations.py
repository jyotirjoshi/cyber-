"""DSPM, OCSF normalization, threat-story, and response-action tests."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest

from app.core.errors import ConflictError


def test_data_store_assessment_is_metadata_first_and_scores_posture() -> None:
    from app.services.security_operations import assess_data_store

    assessment = assess_data_store(
        resource={"id": "bucket-7", "provider": "aws", "service": "s3", "region": "eu-west-1"},
        metadata={
            "public_access": True,
            "encrypted": False,
            "identities": [{"principal": "*", "permissions": ["read"]}],
            "retention_days": 0,
            "classifications": ["customer_pii"],
            "approved_regions": ["eu-west-1"],
        },
        scan_mode="metadata_only",
    )
    assert assessment.scan_mode == "metadata_only"
    assert assessment.posture_score < 50
    assert {item["code"] for item in assessment.findings} >= {
        "public_data_store",
        "encryption_disabled",
        "wildcard_principal",
        "retention_missing",
    }
    assert "raw_samples" not in repr(assessment)


def test_controlled_sampling_keeps_only_classification_counts() -> None:
    from app.services.security_operations import controlled_sample_projection

    projection = controlled_sample_projection(
        values=["alice@example.test", "4111111111111111", "ordinary"],
        max_items=10,
    )
    assert projection["sampled_items"] == 3
    assert projection["classification_counts"]["email_address"] == 1
    assert projection["classification_counts"]["payment_card"] == 1
    assert "alice@example.test" not in repr(projection)
    assert "4111111111111111" not in repr(projection)


def test_ocsf_normalization_preserves_provenance_not_raw_event() -> None:
    from app.services.security_operations import normalize_ocsf_event

    event = normalize_ocsf_event(
        {
            "class_uid": 1001,
            "category_uid": 1,
            "activity_id": 1,
            "type_uid": 100101,
            "time": 1792454400000,
            "severity_id": 5,
            "message": "Credential used from unusual device",
            "actor": {"user": {"uid": "alice"}},
            "device": {"uid": "host-7"},
            "observables": [{"name": "203.0.113.7", "type": "ip_address"}],
            "metadata": {"product": {"name": "Example EDR"}, "version": "1.4.0"},
            "unmapped": {"raw_payload": "must-not-persist"},
        },
        source="edr-connector",
    )
    assert event["event_key"]
    assert event["actor_ref"] == "alice"
    assert event["device_ref"] == "host-7"
    assert event["source"] == "edr-connector"
    assert "must-not-persist" not in repr(event)


def test_threat_story_correlation_builds_attack_progression_and_balances_evidence() -> None:
    from app.services.security_operations import correlate_threat_story

    events = [
        {
            "event_key": "e-1",
            "time": "2026-10-20T10:00:00+00:00",
            "actor_ref": "alice",
            "device_ref": "host-7",
            "severity_id": 5,
            "attacks": [{"technique_id": "T1078", "tactic": "initial-access"}],
            "evidence_weight": 0.9,
        },
        {
            "event_key": "e-2",
            "time": "2026-10-20T10:05:00+00:00",
            "actor_ref": "alice",
            "device_ref": "host-7",
            "severity_id": 6,
            "attacks": [{"technique_id": "T1021", "tactic": "lateral-movement"}],
            "evidence_weight": 0.8,
        },
    ]
    story = correlate_threat_story(events, contradictory=[{"code": "known_admin", "weight": 0.4}])
    assert story["identity_compromise_score"] < 100
    assert [step["technique_id"] for step in story["attack_progression"]] == ["T1078", "T1021"]
    assert story["contradictory_evidence"][0]["code"] == "known_admin"


def _run_immediate(coroutine: object) -> object:
    """Drive a coroutine that intentionally uses only immediate test doubles."""

    try:
        coroutine.send(None)  # type: ignore[attr-defined]
    except StopIteration as stopped:
        return stopped.value
    raise AssertionError("test coroutine unexpectedly suspended")


def test_response_action_requires_exact_approval_and_is_idempotent() -> None:
    from app.services.security_operations import execute_response_action, preview_response_action

    action = SimpleNamespace(
        status="proposed",
        action_type="isolate_endpoint",
        target_ref="host-7",
        idempotency_key="response-1234567890",
        predicted_impact={},
        provider_receipt={},
        approval_id=None,
        executed_at=None,
        verification={},
        verified_at=None,
    )
    preview = preview_response_action(action, context={"active_sessions": 3, "critical_services": 1})
    assert preview["risk_level"] == "high"

    calls = 0

    async def apply(payload: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"status": "executed", "provider_request_id": "p-1"}

    with pytest.raises(ConflictError, match="approval"):
        _run_immediate(
            execute_response_action(action, approval_scope_digest="0" * 64, apply=apply)
        )
    action.status = "approved"
    action.approval_id = "approval-1"
    _run_immediate(
        execute_response_action(
            action,
            approval_scope_digest=preview["scope_digest"],
            apply=apply,
            now=dt.datetime(2026, 10, 20, tzinfo=dt.UTC),
        )
    )
    _run_immediate(
        execute_response_action(action, approval_scope_digest=preview["scope_digest"], apply=apply)
    )
    assert calls == 1
    assert action.status == "executed"

