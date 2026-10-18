from __future__ import annotations

import datetime as dt
from types import SimpleNamespace


def test_sync_quality_reports_current_stale_failed_and_never_states() -> None:
    from app.services.integration import integration_sync_quality

    now = dt.datetime(2026, 10, 18, 12, tzinfo=dt.UTC)
    base = {
        "is_enabled": True,
        "sync_interval_minutes": 60,
        "last_sync_status": "succeeded",
        "sync_failure_count": 0,
        "status": "configured",
    }

    current = integration_sync_quality(
        SimpleNamespace(**base, last_sync_at=now - dt.timedelta(minutes=30)), now=now
    )
    stale = integration_sync_quality(
        SimpleNamespace(**base, last_sync_at=now - dt.timedelta(hours=4)), now=now
    )
    failed = integration_sync_quality(
        SimpleNamespace(
            **{**base, "last_sync_status": "failed", "sync_failure_count": 3},
            last_sync_at=now - dt.timedelta(minutes=10),
        ),
        now=now,
        circuit_open=True,
    )
    never = integration_sync_quality(SimpleNamespace(**base, last_sync_at=None), now=now)

    assert current.coverage_state == "current" and current.confidence > 0.8
    assert stale.coverage_state == "stale" and stale.confidence < current.confidence
    assert failed.coverage_state == "blocked" and failed.confidence < 0.25
    assert never.coverage_state == "never_synced" and never.confidence == 0
    assert current.freshness_seconds == 1800
