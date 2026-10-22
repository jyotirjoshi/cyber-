from __future__ import annotations

import datetime as dt
import uuid


def test_sync_run_receipt_records_bounded_success_evidence() -> None:
    from app.db.models.integration import IntegrationSyncRun
    from app.services.integration_sync import settle_sync_run

    started = dt.datetime(2026, 10, 22, 10, tzinfo=dt.UTC)
    row = IntegrationSyncRun(
        organization_id=uuid.uuid4(),
        integration_id=uuid.uuid4(),
        run_key="scheduled:2026-10-22T10:00:00Z",
        mode="scheduled",
        status="running",
        started_at=started,
        checkpoint_before={"last_completed_at": "2026-10-22T09:00:00Z"},
    )

    settle_sync_run(
        row,
        status="succeeded",
        completed_at=started + dt.timedelta(seconds=12),
        items_seen=17,
        items_staged=15,
        absence_candidates=2,
    )

    assert row.status == "succeeded"
    assert row.duration_ms == 12_000
    assert row.items_seen == 17
    assert row.items_staged == 15
    assert row.checkpoint_after["completed_at"] == "2026-10-22T10:00:12+00:00"
    assert row.error_code is None


def test_sync_run_receipt_redacts_failure_details() -> None:
    from app.db.models.integration import IntegrationSyncRun
    from app.services.integration_sync import settle_sync_run

    started = dt.datetime(2026, 10, 22, 10, tzinfo=dt.UTC)
    row = IntegrationSyncRun(
        organization_id=uuid.uuid4(),
        integration_id=uuid.uuid4(),
        run_key="scheduled:failure",
        mode="scheduled",
        status="running",
        started_at=started,
        checkpoint_before={},
    )

    settle_sync_run(
        row,
        status="failed",
        completed_at=started + dt.timedelta(seconds=2),
        error_code="rate_limited",
        error_summary="Provider sync failed; retry scheduled.",
    )

    assert row.status == "failed"
    assert row.error_code == "rate_limited"
    assert row.error_summary == "Provider sync failed; retry scheduled."
    assert row.checkpoint_after == {}


def test_sync_run_history_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/integrations/sync-runs" in {route.path for route in api_router.routes}
