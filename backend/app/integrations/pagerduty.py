"""PagerDuty Events API v2 notifications with durable provider deduplication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.db.enums import Severity
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "PagerDuty"
_SEVERITIES = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "info",
}


@dataclass(frozen=True, slots=True)
class PagerDutyEvent:
    dedup_key: str
    status: str


class PagerDutyClient:
    """Trigger one PagerDuty incident while preserving the outbox dedupe identity."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._settings = settings
        self._cfg = settings.pagerduty
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_PAGERDUTY__ROUTING_KEY for this organization."
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url.rstrip("/"),
                settings=self._settings,
                redis=self._redis,
                timeout=20.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    async def trigger(
        self,
        *,
        summary: str,
        body: str,
        severity: Severity | None,
        dedup_key: str,
        link: str | None = None,
    ) -> PagerDutyEvent:
        key = str(dedup_key).strip()
        if not key or len(key) > 255:
            raise IntegrationError("Invalid PagerDuty deduplication key", provider=PROVIDER)
        details: dict[str, str] = {"body": body[:10_000]}
        if link:
            details["link"] = link[:2_048]
        payload: dict[str, Any] = {
            "routing_key": reveal(self._cfg.routing_key),
            "event_action": "trigger",
            "dedup_key": key,
            "payload": {
                "summary": summary.strip()[:1_024] or "Cynux security notification",
                "source": str(self._cfg.source).strip()[:1_024] or "Cynux",
                "severity": _SEVERITIES.get(severity or Severity.INFO, "info"),
                "custom_details": details,
            },
        }
        result = await self._require().post_json("/v2/enqueue", json=payload, idempotency_key=key)
        if not isinstance(result, dict) or result.get("status") != "success":
            raise IntegrationError("PagerDuty rejected the event", provider=PROVIDER)
        response_key = result.get("dedup_key")
        return PagerDutyEvent(
            dedup_key=response_key if isinstance(response_key, str) and response_key else key,
            status="triggered",
        )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["PROVIDER", "PagerDutyClient", "PagerDutyEvent"]
