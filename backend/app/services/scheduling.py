"""Cycle-free cron calculation shared by scheduled platform work."""

from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter


def next_cron_time(expression: str, timezone: str, after: dt.datetime) -> dt.datetime:
    if after.tzinfo is None:
        raise ValueError("A timezone-aware reference time is required")
    if len(expression.split()) != 5 or not croniter.is_valid(expression):
        raise ValueError("A valid five-field cron expression is required")
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("A valid IANA timezone is required") from exc
    return croniter(expression, after.astimezone(zone)).get_next(dt.datetime).astimezone(dt.UTC)


__all__ = ["next_cron_time"]
