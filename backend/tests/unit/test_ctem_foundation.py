"""Additive CTEM foundation contracts on the existing core models."""

from __future__ import annotations

from app.db.enums import EngagementType, ExecutionMode, ValidationStatus
from app.db.models.assessment import Assessment
from app.db.models.finding import Finding
from app.schemas.finding import ValidateFindingIn


def test_assessments_default_to_authorized_supervised_web_engagements() -> None:
    assert Assessment.__table__.c.engagement_type.default.arg == EngagementType.WEB_APPLICATION.value
    assert Assessment.__table__.c.execution_mode.default.arg == ExecutionMode.SUPERVISED.value


def test_findings_start_unvalidated_with_no_proof() -> None:
    assert Finding.__table__.c.validation_status.default.arg == ValidationStatus.UNVALIDATED.value
    proof_default = Finding.__table__.c.validation_proof.default
    assert proof_default is not None
    assert proof_default.arg(None) == {}


def test_confirming_a_finding_requires_human_readable_evidence() -> None:
    try:
        ValidateFindingIn(status=ValidationStatus.CONFIRMED)
    except ValueError as exc:
        assert "requires a validation summary" in str(exc)
    else:  # pragma: no cover - makes a missing guard fail loudly
        raise AssertionError("a confirmation without evidence was accepted")

    payload = ValidateFindingIn(
        status=ValidationStatus.CONFIRMED,
        summary="Observed the expected non-destructive response in the authorized test path.",
        evidence_references=["run-42"],
    )
    assert payload.status is ValidationStatus.CONFIRMED
