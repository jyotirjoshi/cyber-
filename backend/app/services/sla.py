"""Deterministic SLA targets used by canonical remediation workflows."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping

from app.core.errors import InvalidConfigurationError
from app.db.enums import Severity

_DEFAULT_TARGET_DAYS = {"critical": 3, "high": 14, "medium": 30, "low": 90, "info": 180}
_CRITICAL_ASSET_TARGET_DAYS = {"critical": 1, "high": 7, "medium": 14, "low": 45, "info": 90}


def validate_sla_targets(value: Mapping[str, object] | None) -> dict[str, int]:
    """Validate a complete tenant SLA policy without accepting unknown severities."""
    if value is None:
        return dict(_DEFAULT_TARGET_DAYS)
    expected = set(_DEFAULT_TARGET_DAYS)
    if not set(value).issubset(expected) or any(
        isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 365
        for days in value.values()
    ):
        raise InvalidConfigurationError(
            "invalid SLA targets",
            user_message="SLA targets must use known severities and whole days from 1 to 365.",
        )
    return {**_DEFAULT_TARGET_DAYS, **{severity: int(days) for severity, days in value.items()}}


def calculate_due_at(
    severity: Severity,
    asset_criticality: str | None,
    *,
    opened_at: dt.datetime,
    targets: Mapping[str, object] | None = None,
) -> dt.datetime:
    """Calculate a timezone-preserving due date from approved tenant policy."""
    if opened_at.tzinfo is None or opened_at.utcoffset() is None:
        raise InvalidConfigurationError(
            "SLA opened_at is timezone-naive", user_message="SLA timing requires a timezone-aware timestamp."
        )
    days = validate_sla_targets(targets)[severity.value]
    if asset_criticality == "critical" and targets is None:
        days = _CRITICAL_ASSET_TARGET_DAYS[severity.value]
    return opened_at + dt.timedelta(days=days)


__all__ = ["calculate_due_at", "validate_sla_targets"]
