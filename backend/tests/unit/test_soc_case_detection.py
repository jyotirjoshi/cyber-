from __future__ import annotations

import types

import pytest
from pydantic import ValidationError


def _event(**overrides: object) -> types.SimpleNamespace:
    values: dict[str, object] = {
        "category": "endpoint",
        "event_type": "process:suspicious",
        "severity": "high",
        "source_kind": "native_endpoint",
        "identity_ref": "user:alice@example.com",
        "metrics": {"risk_score": 91, "process": {"signed": False}},
        "evidence": {"techniques": ["T1059"], "host": "workstation-7"},
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def test_detection_rule_contract_rejects_unsafe_operators() -> None:
    from app.schemas.soc import DetectionCondition, DetectionRuleCreateIn

    with pytest.raises(ValidationError):
        DetectionRuleCreateIn(
            rule_key="unsigned-shell",
            name="Unsigned shell",
            severity="high",
            conditions=[
                DetectionCondition(
                    source="metrics",
                    path="process.signed",
                    operator="eval",
                    value=False,
                )
            ],
        )


def test_detection_rule_matches_bounded_nested_conditions() -> None:
    from app.schemas.soc import DetectionCondition
    from app.services.soc_operations import evaluate_detection_rule

    result = evaluate_detection_rule(
        _event(),
        categories=["endpoint"],
        event_types=["process:suspicious"],
        minimum_severity="medium",
        conditions=[
            DetectionCondition(
                source="metrics", path="risk_score", operator="gte", value=80
            ),
            DetectionCondition(
                source="metrics", path="process.signed", operator="eq", value=False
            ),
            DetectionCondition(
                source="evidence", path="techniques", operator="contains", value="T1059"
            ),
        ],
    )

    assert result.matched is True
    assert result.matched_conditions == 3
    assert result.total_conditions == 3
    assert result.reason_codes == ()


def test_detection_rule_reports_missing_field_without_matching() -> None:
    from app.schemas.soc import DetectionCondition
    from app.services.soc_operations import evaluate_detection_rule

    result = evaluate_detection_rule(
        _event(),
        categories=["endpoint"],
        event_types=[],
        minimum_severity="low",
        conditions=[
            DetectionCondition(
                source="evidence", path="network.destination.country", operator="eq", value="RU"
            )
        ],
    )

    assert result.matched is False
    assert result.reason_codes == ("condition_0_missing",)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("open", "investigating"),
        ("investigating", "contained"),
        ("contained", "resolved"),
        ("resolved", "investigating"),
        ("open", "dismissed"),
    ],
)
def test_soc_case_lifecycle_accepts_governed_transitions(current: str, target: str) -> None:
    from app.services.soc_operations import validate_case_transition

    validate_case_transition(current, target)


def test_soc_case_lifecycle_rejects_skipping_investigation() -> None:
    from app.core.errors import ConflictError
    from app.services.soc_operations import validate_case_transition

    with pytest.raises(ConflictError):
        validate_case_transition("open", "resolved")


def test_soc_case_and_detection_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/control-plane/soc/cases" in paths
    assert "/control-plane/soc/cases/{case_id}/transition" in paths
    assert "/control-plane/soc/cases/{case_id}/tasks" in paths
    assert "/control-plane/soc/detection-rules" in paths
    assert "/control-plane/soc/detection-rules/{rule_id}/dry-run" in paths
    assert "/control-plane/soc/detection-rules/{rule_id}/evaluate" in paths


def test_detection_case_key_is_stable_and_respects_grouping_fields() -> None:
    from app.services.soc_operations import detection_case_key

    first = detection_case_key(
        "unsigned-shell",
        _event(identity_ref="user:alice@example.com"),
        group_by=["identity_ref", "evidence.host"],
    )
    same = detection_case_key(
        "unsigned-shell",
        _event(identity_ref="user:alice@example.com"),
        group_by=["identity_ref", "evidence.host"],
    )
    different = detection_case_key(
        "unsigned-shell",
        _event(identity_ref="user:bob@example.com"),
        group_by=["identity_ref", "evidence.host"],
    )

    assert first == same
    assert first != different
    assert first.startswith("detection:unsigned-shell:")
