"""Run-scoped replay for reconnecting multi-agent DAG clients."""

from __future__ import annotations

import uuid

import pytest

from app.core.config import Settings
from app.services.events import EventBus
from tests.unit.test_events import FakeRedis, _event


@pytest.mark.asyncio
async def test_reconnect_replays_only_run_events_after_cursor(settings: Settings) -> None:
    redis = FakeRedis()
    events = EventBus(redis, settings)  # type: ignore[arg-type]
    session_id, run_id, other_run = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    for seq in range(1, 5):
        await events.publish(_event(session_id, seq, run_id=run_id))
    await events.publish(_event(session_id, 5, run_id=other_run))

    replayed = await events.replay_run(run_id, after_seq=2)

    assert [event.seq for event in replayed] == [3, 4]
    assert all(event.run_id == run_id for event in replayed)
