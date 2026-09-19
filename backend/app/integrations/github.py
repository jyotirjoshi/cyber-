"""Read-only GitHub organization security-alert ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "GitHub"
_API_VERSION = "2022-11-28"
_SECURITY_FEEDS = ("dependabot", "code_scanning", "secret_scanning")


@dataclass(frozen=True, slots=True)
class GitHubAlertFeed:
    kind: str
    alerts: list[dict[str, Any]]


class GitHubClient:
    """Retrieve organization security alerts without write permissions."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.github
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_GITHUB__API_TOKEN."
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url.rstrip("/"),
                settings=self.settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {reveal(self._cfg.api_token)}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
        }

    def _organization(self) -> str:
        organization = (self._cfg.organization or "").strip()
        if not organization:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_GITHUB__ORGANIZATION to ingest organization alerts."
            )
        return organization

    async def ping(self) -> bool:
        await self._require().get_json("/user", headers=self._headers())
        return True

    async def list_security_alerts(self) -> list[GitHubAlertFeed]:
        """Return Dependabot, code-scanning, and secret-scanning alerts separately.

        A missing feed is not converted to an empty list: provider errors remain typed
        so a partial source outage cannot masquerade as a clean organization.
        """
        organization = self._organization()
        client = self._require()
        headers = self._headers()
        feeds: list[GitHubAlertFeed] = []
        for kind in _SECURITY_FEEDS:
            payload = await client.get_json(
                f"/orgs/{organization}/{kind.replace('_', '-')}/alerts", headers=headers
            )
            if not isinstance(payload, list):
                payload = []
            feeds.append(
                GitHubAlertFeed(
                    kind=kind,
                    alerts=[item for item in payload if isinstance(item, dict)],
                )
            )
        return feeds


__all__ = ["GitHubAlertFeed", "GitHubClient", "PROVIDER"]
