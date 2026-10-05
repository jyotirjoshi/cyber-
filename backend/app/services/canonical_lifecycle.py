"""Lifecycle policy for a tenant-owned, multi-source security finding."""

from __future__ import annotations

_ACTIVE = frozenset({"new", "open", "reopened"})
_HELD = frozenset({"accepted_risk", "false_positive"})
_OPEN_SOURCES = frozenset({"open", "active", "verified"})
_FIXED_SOURCES = frozenset({"fixed", "resolved", "mitigated", "closed"})


def next_status(
    current: str | None,
    source_statuses: list[str],
    *,
    complete: bool,
    consecutive_absences: int,
) -> str:
    """Derive status without treating a missing or partial feed as proof of a fix.

    ``consecutive_absences`` counts *complete, in-scope* observations only. The
    caller must not increment it for a failed run or for a source with reduced
    permissions. Human dispositions are never replaced by automated evidence.
    """
    if current in _HELD:
        return current
    states = {status.strip().lower() for status in source_statuses} - {"absent", "superseded"}
    if states & _OPEN_SOURCES:
        if current is None:
            return "new"
        if current in {"closed", "mitigated"}:
            return "reopened"
        return current
    if states & _FIXED_SOURCES:
        return "mitigated" if complete and current in _ACTIVE else current or "mitigated"
    if not states and complete and consecutive_absences >= 2:
        return "closed"
    return current or "new"
