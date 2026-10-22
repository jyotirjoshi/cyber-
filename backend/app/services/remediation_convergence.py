"""Auditable projection of ticket work, retest evidence, and finding disposition."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from app.services.ticket import is_terminal_ticket_status

RemediationConvergenceState = Literal[
    "untracked",
    "ticket_active",
    "verification_required",
    "verification_pending",
    "verified_closed",
    "closed_unverified",
    "fix_not_verified",
    "verification_failed",
    "reopened",
    "accepted_risk",
    "false_positive",
]


@dataclass(frozen=True, slots=True)
class RemediationConvergence:
    state: RemediationConvergenceState
    label: str
    detail: str
    next_action: str
    ticket_closed: bool
    verification_evidence_complete: bool


def _verified_absence(evidence: dict[str, Any] | None) -> bool:
    verification = evidence.get("verification") if isinstance(evidence, dict) else None
    return bool(
        isinstance(verification, dict)
        and verification.get("assessment_complete") is True
        and verification.get("coverage_complete") is True
        and verification.get("finding_present") is False
        and verification.get("uncovered_active_sources") == 0
    )


def derive_remediation_convergence(
    *,
    finding_status: str,
    ticket_statuses: list[str | None],
    retest_status: str | None,
    retest_evidence: dict[str, Any] | None,
) -> RemediationConvergence:
    """Derive a conservative lifecycle state without manufacturing closure evidence.

    A terminal tracker ticket proves only that the delivery team marked work complete.
    Closure is considered verified only when the retest has complete target coverage and
    records the finding as absent. A later recurrence always overrides older evidence.
    """
    tickets_closed = bool(ticket_statuses) and all(
        is_terminal_ticket_status(status) for status in ticket_statuses
    )
    verified_absence = _verified_absence(retest_evidence)

    if finding_status == "reopened":
        return RemediationConvergence(
            "reopened",
            "Reopened",
            "The exposure recurred or its linked tracker work was reopened after closure.",
            "Investigate recurrence and update the fix",
            tickets_closed,
            False,
        )
    if finding_status == "accepted_risk":
        return RemediationConvergence(
            "accepted_risk",
            "Risk accepted",
            "An approved, time-bound exception currently governs this exposure.",
            "Monitor the exception expiry",
            tickets_closed,
            False,
        )
    if finding_status == "false_positive":
        return RemediationConvergence(
            "false_positive",
            "False positive",
            "A human disposition removed this exposure from remediation work.",
            "Review if source evidence changes",
            tickets_closed,
            False,
        )
    if finding_status == "closed" and retest_status == "not_confirmed" and verified_absence:
        return RemediationConvergence(
            "verified_closed",
            "Verified closed",
            "A completed, fully covered retest found no matching exposure.",
            "Monitor for recurrence",
            tickets_closed,
            True,
        )
    if finding_status == "closed":
        return RemediationConvergence(
            "closed_unverified",
            "Closed without retest proof",
            "The finding is closed, but the latest retest does not contain complete absence evidence.",
            "Run a covered verification scan",
            tickets_closed,
            False,
        )
    if retest_status == "confirmed":
        return RemediationConvergence(
            "fix_not_verified",
            "Fix not verified",
            "The verification run still observed the exposure.",
            "Return remediation to the owner",
            tickets_closed,
            False,
        )
    if retest_status in {"failed", "cancelled"}:
        return RemediationConvergence(
            "verification_failed",
            "Verification interrupted",
            "The latest verification did not complete successfully.",
            "Repair and rerun verification",
            tickets_closed,
            False,
        )
    if retest_status in {"requested", "scheduled", "running"}:
        return RemediationConvergence(
            "verification_pending",
            "Verification pending",
            "Targeted retest work is queued or running.",
            "Complete retest and collect evidence",
            tickets_closed,
            False,
        )
    if tickets_closed:
        return RemediationConvergence(
            "verification_required",
            "Verification required",
            "All linked tracker work is complete, but no conclusive retest exists.",
            "Request a targeted retest",
            True,
            False,
        )
    if ticket_statuses:
        return RemediationConvergence(
            "ticket_active",
            "Remediation in progress",
            "At least one linked tracker item remains active or has unknown status.",
            "Complete linked remediation work",
            False,
            False,
        )
    return RemediationConvergence(
        "untracked",
        "Not ticketed",
        "No delivery-system ticket is linked to this exposure.",
        "Create or link a remediation ticket",
        False,
        False,
    )


__all__ = ["RemediationConvergence", "RemediationConvergenceState", "derive_remediation_convergence"]
