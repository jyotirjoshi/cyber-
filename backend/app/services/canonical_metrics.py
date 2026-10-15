"""Shared lifecycle timestamps for canonical remediation metrics."""

from sqlalchemy import func, or_, select

from app.db.models.canonical import CanonicalFinding, FindingHistory

RESOLVED_STATUSES = ("mitigated", "closed")


def remediation_timestamp():
    """First resolution in the latest active episode, not the last record edit.

    Reopening begins another episode. A later mitigated-to-closed transition or
    work-note edit must not move the original remediation timestamp. Historical
    closed_at remains a fallback for records without lifecycle history.
    The caller must restrict findings to currently resolved states.
    """
    last_active = (
        select(func.max(FindingHistory.occurred_at))
        .where(
            FindingHistory.organization_id == CanonicalFinding.organization_id,
            FindingHistory.canonical_finding_id == CanonicalFinding.id,
            FindingHistory.new_status.in_(("new", "open", "reopened")),
            FindingHistory.previous_status.is_distinct_from(FindingHistory.new_status),
        )
        .correlate(CanonicalFinding)
        .scalar_subquery()
    )
    resolution = (
        select(func.min(FindingHistory.occurred_at))
        .where(
            FindingHistory.organization_id == CanonicalFinding.organization_id,
            FindingHistory.canonical_finding_id == CanonicalFinding.id,
            FindingHistory.new_status.in_(RESOLVED_STATUSES),
            or_(
                FindingHistory.previous_status.is_(None),
                FindingHistory.previous_status.not_in(RESOLVED_STATUSES),
            ),
            FindingHistory.occurred_at >= func.coalesce(last_active, CanonicalFinding.first_seen_at),
        )
        .correlate(CanonicalFinding)
        .scalar_subquery()
    )
    return func.coalesce(resolution, CanonicalFinding.closed_at)
