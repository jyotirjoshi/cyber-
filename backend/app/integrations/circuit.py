"""Redis-backed circuit breaker (FR-020).

The state lives in Redis, not in process memory, and that is the whole point.  Cynux runs an
API replica and one or more workers; a per-process breaker means each of them independently
hammers a dead provider until it independently notices, which is exactly the thundering herd
the breaker exists to prevent.  Shared state also means the API can *tell the operator* that
calls are being short-circuited -- see ``IntegrationHealthOut.circuit_open``.

The state machine is the standard three-state one:

*   **closed** -- calls pass. Consecutive failures are counted; a success resets the count.
*   **open** -- calls are refused immediately with :class:`~app.core.errors.CircuitOpenError`
    for ``cooldown_seconds``. Nothing leaves the process.
*   **half-open** -- after the cooldown, exactly one probe is admitted. Success closes the
    circuit; failure re-opens it for another cooldown.

Only *consecutive* failures count. A provider that fails one call in fifty is flaky, not down,
and tripping on a cumulative count would eventually open the circuit on every long-lived
integration.

The probe admission uses ``SET NX`` so that when N workers reach half-open simultaneously
exactly one gets through. Without that, "one probe" becomes "one probe per process" and a
recovering provider is hit by a burst at the worst moment.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

import structlog

from app.core.errors import CircuitOpenError

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class BreakerConfig:
    #: Consecutive failures before the circuit opens.
    failure_threshold: int = 5
    #: How long the circuit stays open before a probe is admitted.
    cooldown_seconds: int = 60
    #: Successes required in half-open before closing. One is enough for an HTTP provider:
    #: demanding more keeps the circuit open while real traffic is already succeeding.
    success_threshold: int = 1
    #: Ceiling on the failure counter's TTL, so a provider that fails once a week never
    #: accumulates its way to an open circuit.
    failure_window_seconds: int = 300


@dataclass(frozen=True, slots=True)
class BreakerStatus:
    provider: str
    state: CircuitState
    failure_count: int
    opened_at: float | None = None
    reopens_in: float | None = None

    @property
    def is_open(self) -> bool:
        return self.state is CircuitState.OPEN


class CircuitBreaker:
    def __init__(
        self,
        redis: Redis,
        *,
        provider: str,
        config: BreakerConfig | None = None,
    ) -> None:
        self._r = redis
        self.provider = provider
        self.config = config or BreakerConfig()
        self._fail_key = f"cynux:cb:{provider}:failures"
        self._open_key = f"cynux:cb:{provider}:open"
        self._probe_key = f"cynux:cb:{provider}:probe"

    # -- inspection ---------------------------------------------------------

    async def status(self) -> BreakerStatus:
        """Current state. Never raises: a Redis outage reports ``closed``.

        Failing closed is deliberate. The breaker is an optimization for a failing
        dependency; if the breaker's own store is unavailable, refusing all outbound calls
        would convert a Redis problem into a total outage of every integration.
        """
        try:
            opened_at_raw = await self._r.get(self._open_key)
            failures_raw = await self._r.get(self._fail_key)
        except Exception:
            logger.warning("circuit.state_unavailable", provider=self.provider)
            return BreakerStatus(self.provider, CircuitState.CLOSED, 0)

        failures = int(failures_raw or 0)
        if opened_at_raw is None:
            return BreakerStatus(self.provider, CircuitState.CLOSED, failures)

        opened_at = float(opened_at_raw)
        elapsed = time.time() - opened_at
        if elapsed >= self.config.cooldown_seconds:
            return BreakerStatus(
                self.provider, CircuitState.HALF_OPEN, failures, opened_at=opened_at
            )
        return BreakerStatus(
            self.provider,
            CircuitState.OPEN,
            failures,
            opened_at=opened_at,
            reopens_in=self.config.cooldown_seconds - elapsed,
        )

    # -- gate ---------------------------------------------------------------

    async def check(self) -> None:
        """Raise :class:`CircuitOpenError` if the call must not proceed."""
        status = await self.status()
        if status.state is CircuitState.CLOSED:
            return
        if status.state is CircuitState.OPEN:
            raise CircuitOpenError(self.provider, reopens_in=status.reopens_in)

        #: Half-open: admit exactly one probe process-wide.
        try:
            won = await self._r.set(
                self._probe_key, "1", nx=True, ex=max(self.config.cooldown_seconds, 5)
            )
        except Exception:
            return  # See status(): a Redis failure must not block traffic.
        if not won:
            raise CircuitOpenError(self.provider, reopens_in=status.reopens_in or 1.0)
        logger.info("circuit.probe_admitted", provider=self.provider)

    # -- outcome reporting --------------------------------------------------

    async def record_success(self) -> None:
        try:
            await self._r.delete(self._fail_key, self._open_key, self._probe_key)
        except Exception:  # pragma: no cover - best effort
            logger.warning("circuit.success_not_recorded", provider=self.provider)

    async def record_failure(self, *, reason: str | None = None) -> None:
        try:
            failures = int(await self._r.incr(self._fail_key))
            await self._r.expire(self._fail_key, self.config.failure_window_seconds)
            if failures >= self.config.failure_threshold:
                await self._r.set(
                    self._open_key,
                    str(time.time()),
                    #: TTL slightly beyond the cooldown so a crashed process cannot leave
                    #: a circuit open forever.
                    ex=self.config.cooldown_seconds * 4,
                )
                await self._r.delete(self._probe_key)
                logger.warning(
                    "circuit.opened",
                    provider=self.provider,
                    failures=failures,
                    threshold=self.config.failure_threshold,
                    cooldown_seconds=self.config.cooldown_seconds,
                    reason=reason,
                )
        except Exception:  # pragma: no cover - best effort
            logger.warning("circuit.failure_not_recorded", provider=self.provider)

    async def reset(self) -> None:
        """Force closed. Used by the integration-test endpoint so an operator who has just
        fixed a credential does not have to wait out the cooldown."""
        await self.record_success()


__all__ = ["BreakerConfig", "BreakerStatus", "CircuitBreaker", "CircuitState"]
