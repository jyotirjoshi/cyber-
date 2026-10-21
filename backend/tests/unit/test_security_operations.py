"""DSPM, OCSF normalization, threat-story, and response-action tests."""

from __future__ import annotations

import datetime as dt
import uuid
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


def test_native_endpoint_detection_flags_credential_access_without_retaining_command() -> None:
    """Removing credential-access detection or persisting raw commands must fail this test."""

    from app.services.security_operations import evaluate_native_endpoint_event

    command = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 612 lsass.dmp full"
    decision = evaluate_native_endpoint_event(
        {
            "event_type": "process_start",
            "process_name": "rundll32.exe",
            "parent_process_name": "powershell.exe",
            "executable_path": "C:\\Windows\\System32\\rundll32.exe",
            "command_line": command,
            "signature_status": "signed",
            "destination_host": None,
            "destination_port": None,
            "file_activity_count": 0,
            "attack_techniques": [],
        }
    )

    assert decision["verdict"] == "detect"
    assert decision["severity"] == "critical"
    assert decision["score"] >= 90
    assert "credential_access_lsass" in {item["code"] for item in decision["detections"]}
    assert decision["command_digest"]
    assert command not in repr(decision)


def test_native_endpoint_detection_identifies_office_shell_chain() -> None:
    """Removing the suspicious parent/child rule must fail this test."""

    from app.services.security_operations import evaluate_native_endpoint_event

    decision = evaluate_native_endpoint_event(
        {
            "event_type": "process_start",
            "process_name": "powershell.exe",
            "parent_process_name": "winword.exe",
            "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NoProfile Get-Date",
            "signature_status": "signed",
            "destination_host": None,
            "destination_port": None,
            "file_activity_count": 0,
            "attack_techniques": [],
        }
    )

    assert decision["verdict"] == "detect"
    assert decision["severity"] == "high"
    assert "office_spawned_shell" in {item["code"] for item in decision["detections"]}


def test_native_endpoint_detection_keeps_benign_activity_as_observation() -> None:
    """A detector that marks ordinary signed processes as incidents must fail this test."""

    from app.services.security_operations import evaluate_native_endpoint_event

    decision = evaluate_native_endpoint_event(
        {
            "event_type": "process_start",
            "process_name": "explorer.exe",
            "parent_process_name": "userinit.exe",
            "executable_path": "C:\\Windows\\explorer.exe",
            "command_line": "explorer.exe",
            "signature_status": "signed",
            "destination_host": None,
            "destination_port": None,
            "file_activity_count": 0,
            "attack_techniques": [],
        }
    )

    assert decision == {
        "verdict": "observe",
        "severity": "info",
        "score": 0,
        "detections": [],
        "attack_techniques": [],
        "command_digest": "2981db8b203abf88148bf9861c76c7432f5d02a4abae048e3c9137ec69efee47",
        "destination_digest": None,
    }


def test_native_endpoint_detection_requires_specific_credential_and_ransomware_evidence() -> None:
    """Generic LSASS references and file volume alone must not become critical incidents."""

    from app.services.security_operations import evaluate_native_endpoint_event

    inventory = evaluate_native_endpoint_event(
        {
            "event_type": "process_start",
            "process_name": "tasklist.exe",
            "parent_process_name": "cmd.exe",
            "command_line": "tasklist /fi imagename eq lsass.exe",
            "signature_status": "signed",
        }
    )
    build = evaluate_native_endpoint_event(
        {
            "event_type": "file_change",
            "process_name": "msbuild.exe",
            "parent_process_name": "devenv.exe",
            "command_line": "msbuild solution.sln",
            "signature_status": "signed",
            "file_activity_count": 250,
        }
    )

    assert inventory["verdict"] == "observe"
    assert build["verdict"] == "observe"


def test_native_endpoint_event_key_binds_endpoint_and_has_fixed_length() -> None:
    """Cross-sensor sequence collisions and oversized persisted keys must fail this test."""

    from app.services.security_operations import native_endpoint_event_key

    first = native_endpoint_event_key("sensor-a", "x" * 512)
    second = native_endpoint_event_key("sensor-b", "x" * 512)
    assert first != second
    assert len(first) == 79


def test_endpoint_risk_reflects_current_deterministic_decision() -> None:
    """A later clean evaluation must not leave a permanent high-risk endpoint score."""

    from app.services.security_operations import next_endpoint_risk

    assert next_endpoint_risk(95, {"score": 0, "verdict": "observe"}) == 0
    assert next_endpoint_risk(0, {"score": 90, "verdict": "detect"}) == 90


def test_native_endpoint_replay_requires_the_original_payload_digest() -> None:
    """Changing an idempotent event payload must produce a conflict, not mutate state."""

    from app.services.security_operations import validate_native_endpoint_replay

    validate_native_endpoint_replay("a" * 64, "a" * 64)
    with pytest.raises(ConflictError, match="replay payload"):
        validate_native_endpoint_replay("a" * 64, "b" * 64)


def test_delayed_endpoint_event_cannot_clear_newer_risk() -> None:
    """Arrival order must not let stale benign telemetry clear a newer detection."""

    from app.services.security_operations import should_apply_endpoint_risk

    newest = dt.datetime(2026, 10, 21, 12, tzinfo=dt.UTC)
    assert should_apply_endpoint_risk(None, newest)
    assert should_apply_endpoint_risk(newest.isoformat(), newest)
    assert not should_apply_endpoint_risk(newest.isoformat(), newest - dt.timedelta(minutes=1))


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
    preview = preview_response_action(
        action, context={"active_sessions": 3, "critical_services": 1}
    )
    assert preview["risk_level"] == "high"

    calls = 0

    async def apply(payload: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"status": "executed", "provider_request_id": "p-1"}

    with pytest.raises(ConflictError, match="approval"):
        _run_immediate(execute_response_action(action, approval_scope_digest="0" * 64, apply=apply))
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
    with pytest.raises(ConflictError, match="exact action scope"):
        _run_immediate(execute_response_action(action, approval_scope_digest="f" * 64, apply=apply))


def test_response_action_approval_is_human_and_exact_scope_bound() -> None:
    from app.services.security_operations import approve_response_action

    action = SimpleNamespace(
        status="proposed",
        predicted_impact={"scope_digest": "a" * 64},
        approval_scope_digest=None,
        approved_by_id=None,
        approved_at=None,
    )
    actor_id = uuid.uuid4()
    approve_response_action(
        action,
        approved_by_id=actor_id,
        expected_scope_digest="a" * 64,
        now=dt.datetime(2026, 10, 20, tzinfo=dt.UTC),
    )
    assert action.status == "approved"
    assert action.approved_by_id == actor_id
    assert action.approval_scope_digest == "a" * 64

    with pytest.raises(ConflictError, match="exact action scope"):
        approve_response_action(
            SimpleNamespace(
                status="proposed",
                predicted_impact={"scope_digest": "b" * 64},
                approval_scope_digest=None,
                approved_by_id=None,
                approved_at=None,
            ),
            approved_by_id=actor_id,
            expected_scope_digest="c" * 64,
        )


def test_response_scope_covers_provider_and_requested_action() -> None:
    from app.services.security_operations import preview_response_action

    first = SimpleNamespace(
        action_type="restrict_access",
        target_ref="app-1",
        idempotency_key="idem-000000000001",
        provider="zscaler",
        requested_action={"provider_action": "zpa.update_application_access", "enabled": False},
        predicted_impact={},
    )
    second = SimpleNamespace(
        action_type=first.action_type,
        target_ref=first.target_ref,
        idempotency_key=first.idempotency_key,
        provider=first.provider,
        requested_action={"provider_action": "zpa.update_application_access", "enabled": True},
        predicted_impact={},
    )
    assert (
        preview_response_action(first, context={})["scope_digest"]
        != preview_response_action(second, context={})["scope_digest"]
    )
