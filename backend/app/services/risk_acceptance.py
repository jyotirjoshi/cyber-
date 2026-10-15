"""Risk-acceptance policy primitives shared by approval workflows."""

from __future__ import annotations

import datetime as dt


def validate_expiry(expires_at: dt.datetime, *, now: dt.datetime | None = None) -> dt.datetime:
    """Require a timezone-aware exception expiry no more than one year away."""
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ValueError("risk acceptance expiry must include a timezone")
    reference = now or dt.datetime.now(dt.UTC)
    if expires_at <= reference:
        raise ValueError("risk acceptance expiry must be in the future")
    if expires_at > reference + dt.timedelta(days=365):
        raise ValueError("risk acceptance expiry may not exceed one year")
    return expires_at


__all__ = ["validate_expiry"]
