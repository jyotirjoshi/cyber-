"""Fail-closed checks for dependencies required by the assessment worker."""

from __future__ import annotations

import asyncio
import time

import structlog

from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.integrations.defectdojo import DefectDojoClient
from app.integrations.storage import ObjectStorage
from app.schemas.common import DependencyHealth

log = structlog.get_logger(__name__)


def _elapsed_ms(start: float) -> int:
    return int(round((time.perf_counter() - start) * 1000))


async def _check_storage(settings: Settings) -> None:
    storage = ObjectStorage(settings)
    if not storage.configured:
        raise ConfigurationError(
            "Object storage is not configured.", setting="CYNUX_STORAGE__ACCESS_KEY_ID"
        )
    await asyncio.to_thread(storage._client().head_bucket, Bucket=storage.bucket)


async def _check_defectdojo(settings: Settings) -> None:
    client = DefectDojoClient(settings)
    if not client.configured:
        raise ConfigurationError(
            "DefectDojo is not configured.", setting="CYNUX_DEFECTDOJO__BASE_URL"
        )
    try:
        await client._require().get_json("/api/v2/system_settings/")
    finally:
        await client.aclose()


async def _probe(name: str, check) -> DependencyHealth:
    start = time.perf_counter()
    try:
        await check()
    except Exception as exc:
        log.warning("worker_dependency_unreachable", dependency=name, error=type(exc).__name__)
        return DependencyHealth(name=name, healthy=False, detail="unreachable")
    return DependencyHealth(name=name, healthy=True, latency_ms=_elapsed_ms(start))


async def probe_worker_dependencies(settings: Settings) -> list[DependencyHealth]:
    """Probe external worker dependencies without exposing provider error bodies."""
    return [
        await _probe("storage", lambda: _check_storage(settings)),
        await _probe("defectdojo", lambda: _check_defectdojo(settings)),
    ]


async def assert_worker_dependencies(settings: Settings) -> None:
    """Refuse worker startup before it can consume work it cannot retain or publish."""
    unhealthy = [item.name for item in await probe_worker_dependencies(settings) if not item.healthy]
    if unhealthy:
        raise ConfigurationError(
            f"Worker dependencies are unavailable: {', '.join(unhealthy)}.",
            setting="CYNUX_STORAGE__ENDPOINT_URL",
        )


__all__ = ["assert_worker_dependencies", "probe_worker_dependencies"]
