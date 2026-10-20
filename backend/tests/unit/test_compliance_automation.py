"""Compliance inheritance and evidence-request workflow tests."""

from __future__ import annotations

import datetime as dt

import pytest


def test_inheritance_graph_rejects_cycles_but_allows_multiple_parents() -> None:
    from app.services.compliance_automation import validate_inheritance_graph

    relationships = [
        {"control_id": "child", "parent_control_id": "parent-a"},
        {"control_id": "child", "parent_control_id": "parent-b"},
        {"control_id": "parent-a", "parent_control_id": "root"},
    ]
    validate_inheritance_graph(relationships)

    with pytest.raises(ValueError, match="cycle"):
        validate_inheritance_graph(
            [
                {"control_id": "a", "parent_control_id": "b"},
                {"control_id": "b", "parent_control_id": "c"},
                {"control_id": "c", "parent_control_id": "a"},
            ]
        )


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("open", "collecting"),
        ("open", "cancelled"),
        ("collecting", "submitted"),
        ("collecting", "cancelled"),
        ("submitted", "accepted"),
        ("submitted", "rejected"),
        ("rejected", "collecting"),
        ("rejected", "cancelled"),
    ],
)
def test_evidence_request_lifecycle_allows_governed_transitions(current: str, target: str) -> None:
    from app.services.compliance_automation import validate_evidence_request_transition

    validate_evidence_request_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("open", "accepted"),
        ("collecting", "accepted"),
        ("submitted", "collecting"),
        ("accepted", "rejected"),
        ("cancelled", "open"),
    ],
)
def test_evidence_request_lifecycle_rejects_unsafe_transitions(current: str, target: str) -> None:
    from app.services.compliance_automation import validate_evidence_request_transition

    with pytest.raises(ValueError, match="transition"):
        validate_evidence_request_transition(current, target)


def test_evidence_freshness_uses_request_window_and_artifact_expiry() -> None:
    from app.services.compliance_automation import evidence_freshness

    now = dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    fresh = evidence_freshness(
        collected_at=now - dt.timedelta(days=10),
        valid_until=now + dt.timedelta(days=1),
        freshness_days=30,
        measured_at=now,
    )
    assert fresh == {"fresh": True, "reason": "fresh", "age_days": 10}

    stale = evidence_freshness(
        collected_at=now - dt.timedelta(days=31),
        valid_until=None,
        freshness_days=30,
        measured_at=now,
    )
    assert stale["fresh"] is False
    assert stale["reason"] == "freshness_window_exceeded"

    expired = evidence_freshness(
        collected_at=now - dt.timedelta(days=1),
        valid_until=now - dt.timedelta(seconds=1),
        freshness_days=30,
        measured_at=now,
    )
    assert expired["fresh"] is False
    assert expired["reason"] == "artifact_expired"
