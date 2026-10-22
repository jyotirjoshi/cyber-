"""Remediation convergence is derived only from persisted tracker and retest evidence."""

from app.services.remediation_convergence import derive_remediation_convergence


def test_terminal_ticket_requires_verification_before_closure() -> None:
    result = derive_remediation_convergence(
        finding_status="open",
        ticket_statuses=["Done"],
        retest_status=None,
        retest_evidence={},
    )

    assert result.state == "verification_required"
    assert result.ticket_closed is True
    assert result.verification_evidence_complete is False


def test_covered_absence_is_verified_closed() -> None:
    result = derive_remediation_convergence(
        finding_status="closed",
        ticket_statuses=["Closed"],
        retest_status="not_confirmed",
        retest_evidence={
            "verification": {
                "assessment_complete": True,
                "coverage_complete": True,
                "finding_present": False,
                "uncovered_active_sources": 0,
            }
        },
    )

    assert result.state == "verified_closed"
    assert result.verification_evidence_complete is True
    assert result.next_action == "Monitor for recurrence"


def test_persistent_finding_after_retest_never_claims_closure() -> None:
    result = derive_remediation_convergence(
        finding_status="open",
        ticket_statuses=["Done"],
        retest_status="confirmed",
        retest_evidence={"verification": {"finding_present": True}},
    )

    assert result.state == "fix_not_verified"
    assert result.verification_evidence_complete is False
    assert "remediation" in result.next_action.lower()


def test_reopened_finding_takes_precedence_over_old_closure_evidence() -> None:
    result = derive_remediation_convergence(
        finding_status="reopened",
        ticket_statuses=["In Progress"],
        retest_status="not_confirmed",
        retest_evidence={
            "verification": {
                "assessment_complete": True,
                "coverage_complete": True,
                "finding_present": False,
                "uncovered_active_sources": 0,
            }
        },
    )

    assert result.state == "reopened"
    assert result.ticket_closed is False
    assert result.next_action == "Investigate recurrence and update the fix"
