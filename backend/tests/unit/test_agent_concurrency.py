"""Atomic multi-dimensional admission for parallel agent tasks."""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict

import pytest

from app.services.agent_concurrency import (
    ConcurrencyAdmission,
    ConcurrencyLimits,
    ConcurrencyRequest,
)


class FakeAdmissionRedis:
    def __init__(self) -> None:
        self.now_ms = 1_000_000
        self.members: dict[str, dict[str, int]] = defaultdict(dict)
        self.lock = asyncio.Lock()

    async def eval(self, script, key_count, *values):
        del key_count
        keys = list(values[:5])
        args = list(values[5:])
        async with self.lock:
            if "ZADD" in script:
                token = str(args[0])
                ttl_ms = int(args[1])
                now_ms = int(args[2])
                limits = [int(value) for value in args[3:7]]
                conflict_enabled = int(args[7])
                for key in keys:
                    self.members[key] = {
                        member: expiry
                        for member, expiry in self.members[key].items()
                        if expiry > now_ms
                    }
                for key, limit in zip(keys[:4], limits, strict=True):
                    if limit >= 0 and len(self.members[key]) >= limit:
                        return [0, 0]
                if conflict_enabled and self.members[keys[4]]:
                    return [0, 0]
                expiry = now_ms + ttl_ms
                for index, key in enumerate(keys):
                    if index < 4 and limits[index] < 0:
                        continue
                    if index == 4 and not conflict_enabled:
                        continue
                    self.members[key][token] = expiry
                return [1, expiry]
            token = str(args[0])
            removed = 0
            for key in keys:
                removed += int(self.members[key].pop(token, None) is not None)
            return removed


ORG_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")
RUN_ID = uuid.UUID("20000000-0000-0000-0000-000000000001")


def _request(*, target: str, provider: str | None = "openai") -> ConcurrencyRequest:
    return ConcurrencyRequest(
        organization_id=ORG_ID,
        run_id=RUN_ID,
        provider=provider,
        conflict_key=target,
        ttl_seconds=30,
    )


@pytest.mark.asyncio
async def test_same_conflict_key_serializes_but_other_targets_run() -> None:
    redis = FakeAdmissionRedis()
    admission = ConcurrencyAdmission(
        redis,
        limits=ConcurrencyLimits(global_tasks=10, tenant_tasks=5, run_tasks=3, provider_tasks=2),
        clock_ms=lambda: redis.now_ms,
    )

    first = await admission.acquire(_request(target="asset:1"))
    assert first is not None
    assert await admission.try_acquire(_request(target="asset:1")) is False
    other = await admission.acquire(_request(target="asset:2"))
    assert other is not None
    await first.release()
    replacement = await admission.acquire(_request(target="asset:1"))
    assert replacement is not None


@pytest.mark.asyncio
async def test_all_callers_observe_atomic_run_ceiling() -> None:
    redis = FakeAdmissionRedis()
    admission = ConcurrencyAdmission(
        redis,
        limits=ConcurrencyLimits(global_tasks=10, tenant_tasks=10, run_tasks=2, provider_tasks=10),
        clock_ms=lambda: redis.now_ms,
    )

    leases = await asyncio.gather(
        *(admission.acquire(_request(target=f"asset:{index}")) for index in range(8))
    )

    assert sum(lease is not None for lease in leases) == 2


@pytest.mark.asyncio
async def test_expired_lease_recovers_every_dimension() -> None:
    redis = FakeAdmissionRedis()
    admission = ConcurrencyAdmission(
        redis,
        limits=ConcurrencyLimits(global_tasks=1, tenant_tasks=1, run_tasks=1, provider_tasks=1),
        clock_ms=lambda: redis.now_ms,
    )
    first = await admission.acquire(_request(target="asset:1"))
    assert first is not None
    assert await admission.try_acquire(_request(target="asset:2")) is False

    redis.now_ms += 30_001

    assert await admission.try_acquire(_request(target="asset:2")) is True


@pytest.mark.asyncio
async def test_release_token_cannot_release_another_lease() -> None:
    redis = FakeAdmissionRedis()
    admission = ConcurrencyAdmission(
        redis,
        limits=ConcurrencyLimits(global_tasks=2, tenant_tasks=2, run_tasks=2, provider_tasks=2),
        clock_ms=lambda: redis.now_ms,
    )
    first = await admission.acquire(_request(target="asset:1"))
    second = await admission.acquire(_request(target="asset:2"))
    assert first is not None and second is not None
    first.token = "not-the-issued-token"  # type: ignore[misc]

    assert await first.release() is False
    assert await admission.try_acquire(_request(target="asset:2")) is False


@pytest.mark.asyncio
async def test_providerless_tasks_do_not_consume_provider_ceiling() -> None:
    redis = FakeAdmissionRedis()
    admission = ConcurrencyAdmission(
        redis,
        limits=ConcurrencyLimits(global_tasks=5, tenant_tasks=5, run_tasks=5, provider_tasks=1),
        clock_ms=lambda: redis.now_ms,
    )

    assert await admission.try_acquire(_request(target="asset:1", provider=None)) is True
    assert await admission.try_acquire(_request(target="asset:2", provider=None)) is True
