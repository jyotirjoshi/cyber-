from __future__ import annotations

import datetime as dt
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


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

    paths = {route.path for route in api_router.routes}
    assert "/integrations/sync-runs" in paths
    assert "/integrations/{kind}/sync-now" in paths
    assert "/integrations/sync-runs/{run_id}/replay" in paths


def test_manual_sync_receipt_carries_lineage_and_safe_checkpoint() -> None:
    from app.db.models.integration import Integration
    from app.services.integration_sync import new_sync_run

    organization_id = uuid.uuid4()
    integration = Integration(
        id=uuid.uuid4(),
        organization_id=organization_id,
        kind="wiz",
        name="Wiz production",
        sync_failure_count=3,
    )
    started = dt.datetime(2026, 10, 22, 11, tzinfo=dt.UTC)
    replay_of = uuid.uuid4()

    row = new_sync_run(
        integration,
        mode="manual",
        started_at=started,
        replay_of_id=replay_of,
    )

    assert row.organization_id == organization_id
    assert row.integration_id == integration.id
    assert row.mode == "manual"
    assert row.status == "running"
    assert row.run_key.startswith(f"manual:{integration.id}:")
    assert row.checkpoint_before == {
        "last_completed_at": None,
        "failure_count": 3,
        "replay_of_id": str(replay_of),
    }


class _Savepoint:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, exc_type, exc, traceback) -> bool:
        return False


@pytest.mark.asyncio
async def test_manual_sync_success_settles_durable_receipt(monkeypatch) -> None:
    from app.db.enums import IntegrationKind
    from app.db.models.integration import Integration
    from app.services import integration_sync
    from app.services.context import Principal

    organization_id = uuid.uuid4()
    integration = Integration(
        id=uuid.uuid4(), organization_id=organization_id, kind="wiz", name="Wiz"
    )
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=integration),
        add=Mock(),
        flush=AsyncMock(),
        begin_nested=lambda: _Savepoint(),
    )
    handler = AsyncMock(
        return_value=SimpleNamespace(total=8, absence_candidates=2, missing_source_records=1)
    )
    monkeypatch.setitem(integration_sync._SYNC_HANDLERS, IntegrationKind.WIZ, handler)

    result = await integration_sync.run_manual_integration_sync(
        session,
        Principal.for_system(organization_id=organization_id),
        IntegrationKind.WIZ,
        settings=SimpleNamespace(),
        redis=None,
    )

    receipt = session.add.call_args.args[0]
    assert result.total == 8
    assert receipt.status == "succeeded"
    assert receipt.items_staged == 8
    assert receipt.absence_candidates == 2
    assert receipt.checkpoint_after["completed_at"]


@pytest.mark.asyncio
async def test_manual_sync_failure_keeps_redacted_replayable_receipt(monkeypatch) -> None:
    from app.core.errors import IntegrationTimeoutError
    from app.db.enums import IntegrationKind
    from app.db.models.integration import Integration
    from app.services import integration_sync
    from app.services.context import Principal

    organization_id = uuid.uuid4()
    integration = Integration(
        id=uuid.uuid4(), organization_id=organization_id, kind="wiz", name="Wiz"
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[integration, integration]),
        add=Mock(),
        flush=AsyncMock(),
        begin_nested=lambda: _Savepoint(),
    )
    handler = AsyncMock(side_effect=IntegrationTimeoutError("secret body", provider="wiz"))
    monkeypatch.setitem(integration_sync._SYNC_HANDLERS, IntegrationKind.WIZ, handler)
    monkeypatch.setattr(integration_sync.audit_service, "record", AsyncMock())

    with pytest.raises(IntegrationTimeoutError):
        await integration_sync.run_manual_integration_sync(
            session,
            Principal.for_system(organization_id=organization_id),
            IntegrationKind.WIZ,
            settings=SimpleNamespace(),
            redis=None,
        )

    receipt = session.add.call_args.args[0]
    assert receipt.status == "failed"
    assert receipt.error_code == "integration_timeout"
    assert receipt.error_summary == "Provider sync failed; the failed attempt can be replayed."
    assert "secret body" not in receipt.error_summary
    assert integration.sync_failure_count == 1
