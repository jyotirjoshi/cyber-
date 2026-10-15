from __future__ import annotations

import datetime as dt
import uuid

import pytest

from app.core.errors import ApprovalRequiredError, InvalidTargetError
from app.db.enums import ApprovalDecision
from app.db.models.assessment import Approval
from app.services.bas_techniques import (
    CATALOG_VERSION,
    classify_control_result,
    compare_run_outcomes,
    get_technique,
    require_technique_approval,
)


def test_no_artifacts_never_claims_a_control_result() -> None:
    assert classify_control_result(exit_code=0, artifact_ids=[]) == "inconclusive"


def test_archived_evidence_can_support_detection_or_prevention() -> None:
    evidence = [uuid.uuid4()]
    assert classify_control_result(exit_code=0, artifact_ids=evidence) == "detected"
    assert (
        classify_control_result(exit_code=0, artifact_ids=evidence, blocked=True)
        == "prevented"
    )


def test_catalog_is_versioned_and_target_compatible() -> None:
    technique = get_technique("web_attack_surface", "https://app.example.com")
    assert technique.catalog_version == CATALOG_VERSION
    assert technique.mitre_technique == "T1190"
    assert technique.adapter.value == "nuclei"
    with pytest.raises(InvalidTargetError):
        get_technique("credential_exposure", "https://app.example.com")


def test_active_technique_requires_current_human_approval() -> None:
    technique = get_technique("external_exposure", "example.com")
    with pytest.raises(ApprovalRequiredError):
        require_technique_approval(technique, None)

    expired = Approval(
        organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        prompt="Approve BAS",
        decision=ApprovalDecision.APPROVED.value,
        resolved_by_id=uuid.uuid4(),
        expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1),
    )
    with pytest.raises(ApprovalRequiredError):
        require_technique_approval(technique, expired)


def test_rerun_comparison_reports_regressions_and_improvements() -> None:
    comparison = compare_run_outcomes(
        current={"a": "detected", "b": "prevented", "c": "inconclusive"},
        baseline={"a": "prevented", "b": "detected", "d": "detected"},
    )
    assert comparison == {
        "regressions": ["a"],
        "improvements": ["b", "d"],
        "unchanged": [],
        "inconclusive": ["c"],
    }
