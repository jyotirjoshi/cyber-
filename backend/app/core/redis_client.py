"""Redis connections plus the small primitives built directly on them.

One connection pool is shared by the API process and by each worker.  Three
distinct concerns live here because they are all thin wrappers over the same pool:

* **Token revocation** -- a deny list so sign-out and password changes take effect
  immediately instead of at token expiry.
* **Rate limiting** -- a fixed-window counter for API callers and a token bucket for
  outbound calls to rate-limited third parties (FR-020).
* **Response cache** -- used by the intelligence clients so a 24h-stale CVE lookup
  does not cost an NVD request (FR-020).
"""

from __future__ import annotations

import json
import time
from typing import Any

import redis.asyncio as aioredis
from redis.asyncio.client import Redis

from app.core.config import Settings

_pool: aioredis.ConnectionPool | None = None


def get_redis(settings: Settings) -> Redis:
    """Return a client backed by the process-wide pool."""
    global _pool
    if _pool is None:
        _pool = aioredis.ConnectionPool.from_url(
            settings.redis.url,
            decode_responses=True,
            max_connections=64,
            health_check_interval=30,
        )
    return aioredis.Redis(connection_pool=_pool)


async def close_redis() -> None:
    global _pool
    if _pool is not None:
        await _pool.disconnect()
        _pool = None


# ---------------------------------------------------------------------------
# Token revocation
# ---------------------------------------------------------------------------


class TokenDenyList:
    def __init__(self, redis: Redis) -> None:
        self._r = redis

    @staticmethod
    def _jti_key(jti: str) -> str:
        return f"cynux:revoked:jti:{jti}"

    @staticmethod
    def _user_key(user_id: str) -> str:
        return f"cynux:revoked:user:{user_id}"

    async def revoke_token(self, jti: str, ttl_seconds: int) -> None:
        await self._r.setex(self._jti_key(jti), max(ttl_seconds, 1), "1")

    async def revoke_all_for_user(self, user_id: str, ttl_seconds: int) -> None:
        """Invalidate every token issued before now for this user.

        Used on password change. Cheaper and more reliable than enumerating jtis.
        """
        await self._r.setex(self._user_key(user_id), max(ttl_seconds, 1), str(int(time.time())))

    async def is_revoked(self, jti: str, user_id: str, issued_at: int) -> bool:
        pipe = self._r.pipeline()
        pipe.get(self._jti_key(jti))
        pipe.get(self._user_key(user_id))
        jti_hit, cutoff = await pipe.execute()
        if jti_hit:
            return True
        return bool(cutoff and issued_at < int(cutoff))


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class FixedWindowLimiter:
    """Per-principal request throttle for the HTTP API."""

    def __init__(self, redis: Redis, *, limit: int, window_seconds: int = 60) -> None:
        self._r = redis
        self.limit = limit
        self.window = window_seconds

    async def hit(self, key: str) -> tuple[bool, int, int]:
        """Return ``(allowed, remaining, reset_after_seconds)``."""
        bucket = int(time.time()) // self.window
        redis_key = f"cynux:rl:{key}:{bucket}"
        pipe = self._r.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, self.window + 1)
        count, _ = await pipe.execute()
        remaining = max(self.limit - int(count), 0)
        reset = self.window - (int(time.time()) % self.window)
        return int(count) <= self.limit, remaining, reset


#: Distributed token bucket. Refills lazily so it costs one round-trip per call.
_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

local elapsed = math.max(0, now - ts)
tokens = math.min(capacity, tokens + elapsed * refill_per_sec)

local allowed = 0
local wait = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  wait = (cost - tokens) / refill_per_sec
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, math.ceil(capacity / refill_per_sec) + 60)
return {allowed, tostring(wait)}
"""  # noqa: S105 - Lua source, not a credential; S105 fires on "TOKEN" in the name.


class TokenBucket:
    """Rate limiter for *outbound* calls, shared across API and worker processes.

    NVD allows 5 requests / 30s without a key. A per-process limiter would still
    breach that once two workers run, so the state has to live in Redis.
    """

    def __init__(self, redis: Redis, *, name: str, capacity: int, refill_per_second: float):
        self._r = redis
        self.name = name
        self.capacity = capacity
        self.refill = refill_per_second
        self._script = redis.register_script(_TOKEN_BUCKET_LUA)

    async def acquire(self, cost: int = 1) -> tuple[bool, float]:
        """Return ``(allowed, seconds_until_available)``."""
        allowed, wait = await self._script(
            keys=[f"cynux:tb:{self.name}"],
            args=[self.capacity, self.refill, time.time(), cost],
        )
        return bool(int(allowed)), float(wait)


# ---------------------------------------------------------------------------
# Response cache
# ---------------------------------------------------------------------------


class ResponseCache:
    def __init__(self, redis: Redis, settings: Settings) -> None:
        self._r = redis
        self._prefix = settings.redis.cache_prefix

    def _key(self, namespace: str, key: str) -> str:
        return f"{self._prefix}:{namespace}:{key}"

    async def get(self, namespace: str, key: str) -> Any | None:
        raw = await self._r.get(self._key(namespace, key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # A corrupt entry must never be returned as intelligence data.
            await self._r.delete(self._key(namespace, key))
            return None

    async def set(self, namespace: str, key: str, value: Any, ttl_seconds: int) -> None:
        await self._r.setex(
            self._key(namespace, key), max(ttl_seconds, 1), json.dumps(value, default=str)
        )

    async def invalidate(self, namespace: str, key: str) -> None:
        await self._r.delete(self._key(namespace, key))


__all__ = [
    "FixedWindowLimiter",
    "ResponseCache",
    "TokenBucket",
    "TokenDenyList",
    "close_redis",
    "get_redis",
]
