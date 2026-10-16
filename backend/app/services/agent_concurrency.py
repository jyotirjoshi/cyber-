"""Atomic global, tenant, run, provider, and target concurrency admission."""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from redis.asyncio.client import Redis

from app.core.redis_client import (
    AGENT_CONCURRENCY_ACQUIRE_LUA,
    AGENT_CONCURRENCY_RELEASE_LUA,
)


@dataclass(frozen=True, slots=True)
class ConcurrencyLimits:
    global_tasks: int
    tenant_tasks: int
    run_tasks: int
    provider_tasks: int

    def __post_init__(self) -> None:
        if any(
            value < 0
            for value in (
                self.global_tasks,
                self.tenant_tasks,
                self.run_tasks,
                self.provider_tasks,
            )
        ):
            raise ValueError("concurrency limits cannot be negative")


@dataclass(frozen=True, slots=True)
class ConcurrencyRequest:
    organization_id: uuid.UUID
    run_id: uuid.UUID
    provider: str | None
    conflict_key: str | None
    ttl_seconds: int

    def __post_init__(self) -> None:
        if not 1 <= self.ttl_seconds <= 3600:
            raise ValueError("concurrency leases must be between 1 and 3600 seconds")
        if self.provider is not None and not 1 <= len(self.provider) <= 80:
            raise ValueError("provider names must contain 1 to 80 characters")
        if self.conflict_key is not None and not 1 <= len(self.conflict_key) <= 500:
            raise ValueError("conflict keys must contain 1 to 500 characters")


@dataclass(slots=True)
class ConcurrencyLease:
    redis: Redis
    token: str
    keys: tuple[str, str, str, str, str]
    expires_at_ms: int
    _released: bool = False

    async def release(self) -> bool:
        if self._released:
            return False
        removed = await self.redis.eval(
            AGENT_CONCURRENCY_RELEASE_LUA,
            len(self.keys),
            *self.keys,
            self.token,
        )
        released = int(cast(int, removed)) > 0
        if released:
            self._released = True
        return released


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


class ConcurrencyAdmission:
    """Acquire every concurrency dimension in one Redis Lua transaction."""

    def __init__(
        self,
        redis: Redis,
        *,
        limits: ConcurrencyLimits,
        prefix: str = "cynux:agent:concurrency",
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self._redis = redis
        self._limits = limits
        self._prefix = prefix.rstrip(":")
        self._clock_ms = clock_ms or (lambda: int(time.time() * 1000))

    def _keys(self, request: ConcurrencyRequest) -> tuple[str, str, str, str, str]:
        provider = _digest(request.provider) if request.provider is not None else "none"
        conflict = _digest(request.conflict_key) if request.conflict_key is not None else "none"
        return (
            f"{self._prefix}:global",
            f"{self._prefix}:tenant:{request.organization_id}",
            f"{self._prefix}:run:{request.run_id}",
            f"{self._prefix}:provider:{provider}",
            f"{self._prefix}:conflict:{conflict}",
        )

    async def acquire(self, request: ConcurrencyRequest) -> ConcurrencyLease | None:
        token = secrets.token_urlsafe(32)
        keys = self._keys(request)
        provider_limit = self._limits.provider_tasks if request.provider is not None else -1
        conflict_enabled = int(request.conflict_key is not None)
        raw = await self._redis.eval(
            AGENT_CONCURRENCY_ACQUIRE_LUA,
            len(keys),
            *keys,
            token,
            request.ttl_seconds * 1000,
            self._clock_ms(),
            self._limits.global_tasks,
            self._limits.tenant_tasks,
            self._limits.run_tasks,
            provider_limit,
            conflict_enabled,
        )
        accepted, expires_at = cast(list[Any] | tuple[Any, ...], raw)
        if int(accepted) != 1:
            return None
        return ConcurrencyLease(
            redis=self._redis,
            token=token,
            keys=keys,
            expires_at_ms=int(expires_at),
        )

    async def try_acquire(self, request: ConcurrencyRequest) -> bool:
        return await self.acquire(request) is not None


async def admit_task(
    redis: Redis,
    request: ConcurrencyRequest,
    limits: ConcurrencyLimits,
) -> ConcurrencyLease | None:
    return await ConcurrencyAdmission(redis, limits=limits).acquire(request)


async def release_task(lease: ConcurrencyLease) -> bool:
    return await lease.release()


__all__ = [
    "ConcurrencyAdmission",
    "ConcurrencyLease",
    "ConcurrencyLimits",
    "ConcurrencyRequest",
    "admit_task",
    "release_task",
]
