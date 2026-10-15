"""Splunk HTTP Event Collector export for tenant security events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.db.enums import NotificationEvent, Severity
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Splunk HEC"


@dataclass(frozen=True, slots=True)
class SplunkHecResult:
    accepted: bool


class SplunkHecClient:
    """Send structured, idempotent Cynux events to Splunk HEC."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._settings = settings
        self._cfg = settings.splunk
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return bool(self._cfg.configured)

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Configure the organization's Splunk HEC URL and token.",
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=str(self._cfg.base_url).rstrip("/"),
                settings=self._settings,
                redis=self._redis,
                headers={"Authorization": f"Splunk {reveal(self._cfg.hec_token)}"},
                timeout=20.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    async def ping(self) -> bool:
        result = await self._require().get_json("/services/collector/health")
        return isinstance(result, dict) and result.get("code") in {0, 17}

    async def emit(
        self,
        *,
        event: NotificationEvent,
        subject: str,
        body: str,
        severity: Severity | None,
        dedupe_key: str,
        organization_id: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        link: str | None = None,
    ) -> SplunkHecResult:
        key = dedupe_key.strip()
        if not key or len(key) > 300:
            raise IntegrationError("Invalid Splunk event identity", provider=PROVIDER)
        event_body: dict[str, Any] = {
            "schema_version": 1,
            "event_type": event.value,
            "organization_id": organization_id,
            "subject": subject[:500],
            "body": body[:50_000],
            "severity": severity.value if severity else None,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "link": link,
            "dedupe_key": key,
        }
        envelope: dict[str, Any] = {
            "host": self._cfg.host,
            "source": self._cfg.source,
            "sourcetype": self._cfg.sourcetype,
            "event": event_body,
        }
        if self._cfg.index:
            envelope["index"] = self._cfg.index
        result = await self._require().post_json(
            "/services/collector/event",
            json=envelope,
            idempotency_key=key,
        )
        if not isinstance(result, dict) or result.get("code") != 0:
            raise IntegrationError("Splunk HEC rejected the event", provider=PROVIDER)
        return SplunkHecResult(accepted=True)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["PROVIDER", "SplunkHecClient", "SplunkHecResult"]
