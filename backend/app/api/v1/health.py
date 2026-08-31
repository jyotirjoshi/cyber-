"""Liveness, readiness and a human-readable health snapshot (PRD section 58).

WHY three endpoints rather than one: a liveness probe must fail only when the *process*
is wedged, or Kubernetes kills the pod every time Redis blips; a readiness probe must
fail when a hard dependency is down, so traffic drains instead of erroring; and operators
want one URL that shows the whole picture. ``/healthz`` is liveness (always 200 if the
process can answer), ``/readyz`` is readiness (503 when a hard dependency is unreachable),
and ``/health`` is the snapshot (always 200, for dashboards).

The distinction between ``degraded`` and ``unhealthy`` is deliberate and matches FR-020:
the platform keeps running when an enrichment provider is down, so Redis being
unreachable (auth revocation and rate limiting impaired) is *degraded*, while the primary
database being unreachable is *unhealthy*. These paths are unauthenticated, unversioned,
and excluded from tracing (see :func:`app.core.telemetry.instrument_app`) because probes
poll them constantly.
"""

from __future__ import annotations

import time
from typing import Literal

import structlog
from fastapi import APIRouter, Response
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import API_VERSION
from app.api.deps import DbSession, RedisDep, SettingsDep, redis_ping
from app.schemas.common import DependencyHealth, HealthOut, OkOut

log = structlog.get_logger(__name__)

router = APIRouter(tags=["health"])


def _elapsed_ms(start: float) -> int:
    return int(round((time.perf_counter() - start) * 1000))


async def _probe_db(session: AsyncSession) -> DependencyHealth:
    start = time.perf_counter()
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:  # a probe must degrade gracefully, never raise
        log.warning("health.db_unreachable", error=type(exc).__name__)
        return DependencyHealth(name="database", healthy=False, detail="unreachable")
    return DependencyHealth(name="database", healthy=True, latency_ms=_elapsed_ms(start))


async def _probe_redis(redis: Redis) -> DependencyHealth:
    start = time.perf_counter()
    try:
        await redis_ping(redis)
    except Exception as exc:
        log.warning("health.redis_unreachable", error=type(exc).__name__)
        return DependencyHealth(name="redis", healthy=False, detail="unreachable")
    return DependencyHealth(name="redis", healthy=True, latency_ms=_elapsed_ms(start))


def _overall(
    deps: list[DependencyHealth],
) -> tuple[Literal["ok", "degraded", "unhealthy"], list[str]]:
    by_name = {d.name: d for d in deps}
    if not by_name["database"].healthy:
        return "unhealthy", ["database unreachable"]
    if not by_name["redis"].healthy:
        return "degraded", ["redis unreachable: auth revocation and rate limiting impaired"]
    return "ok", []


async def _snapshot(session: AsyncSession, redis: Redis, environment: str) -> HealthOut:
    deps = [await _probe_db(session), await _probe_redis(redis)]
    status, warnings = _overall(deps)
    return HealthOut(
        status=status,
        version=API_VERSION,
        environment=environment,
        dependencies=deps,
        warnings=warnings,
    )


@router.get("/healthz", response_model=OkOut, summary="Liveness probe")
async def healthz() -> OkOut:
    return OkOut()


@router.get("/health", response_model=HealthOut, summary="Health snapshot")
async def health(session: DbSession, redis: RedisDep, settings: SettingsDep) -> HealthOut:
    return await _snapshot(session, redis, settings.environment)


@router.get("/readyz", response_model=HealthOut, summary="Readiness probe")
async def readyz(
    session: DbSession, redis: RedisDep, settings: SettingsDep, response: Response
) -> HealthOut:
    snapshot = await _snapshot(session, redis, settings.environment)
    if snapshot.status == "unhealthy":
        response.status_code = 503
    return snapshot


__all__ = ["router"]
