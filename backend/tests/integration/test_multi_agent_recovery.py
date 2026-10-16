"""Production acceptance contracts for staged multi-agent rollout and recovery."""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.worker.protocol import RunAction, RunRequest


def test_multi_agent_rollout_is_off_by_default_and_canary_scoped() -> None:
    organization_id = uuid.uuid4()
    disabled = Settings().features
    assert disabled.multi_agent is False
    assert disabled.multi_agent_enabled_for(organization_id) is False

    enabled = disabled.model_copy(
        update={
            "multi_agent": True,
            "multi_agent_canary_org_ids": [str(organization_id)],
        }
    )
    assert enabled.multi_agent_enabled_for(organization_id) is True
    assert enabled.multi_agent_enabled_for(uuid.uuid4()) is False


def test_supervisor_dispatch_survives_stream_round_trip() -> None:
    run_id = uuid.uuid4()
    request = RunRequest.new(
        run_id,
        RunAction.SUPERVISE,
        principal={
            "user_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "role": "admin",
            "actor_type": "human",
        },
    )
    restored = RunRequest.from_fields(request.to_fields())
    assert restored == request


def test_multi_agent_runtime_ceilings_are_bounded() -> None:
    agent = Settings().agent
    assert 1 <= agent.multi_agent_max_tasks <= 100
    assert 1 <= agent.multi_agent_max_depth <= 10
    assert 1 <= agent.multi_agent_max_parallel_tasks <= 30
    assert 60 <= agent.multi_agent_default_runtime_seconds <= 28_800
    assert 1 <= agent.task_reservation_ttl_seconds <= 86_400
    assert 15 <= agent.task_lease_seconds <= 3_600


@pytest.mark.asyncio
async def test_provider_parallelism_is_enforced_at_the_handler_boundary(monkeypatch) -> None:
    from app.services.multi_agent_runtime import MultiAgentTaskHandler

    settings = Settings(agent={"provider_max_parallel_tasks": {"openai": 1}})
    handler = object.__new__(MultiAgentTaskHandler)
    handler._settings = settings
    handler._deps = object()
    handler._session_factory = object()
    handler._provider_slots = {"openai": asyncio.Semaphore(1)}
    active = 0
    maximum = 0

    async def execute(self, claim):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0)
        active -= 1
        return claim.provider

    monkeypatch.setattr(MultiAgentTaskHandler, "_execute", execute)
    claims = [SimpleNamespace(provider="openai"), SimpleNamespace(provider="openai")]
    assert await asyncio.gather(*(handler(claim) for claim in claims)) == ["openai", "openai"]
    assert maximum == 1
