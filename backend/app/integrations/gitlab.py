"""Read-only GitLab project security-finding ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "GitLab"
_PAGE_SIZE = 100
_MAX_PAGES = 100


@dataclass(frozen=True, slots=True)
class GitLabAlertFeed:
    project: str
    alerts: list[dict[str, Any]]


class GitLabClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._cfg = settings.gitlab
        self._settings = settings
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Set CYNUX_GITLAB__API_TOKEN.")
        if self._client is None:
            self._client = build_client(provider=PROVIDER, base_url=self._cfg.base_url.rstrip("/"), settings=self._settings, redis=self._redis, timeout=30.0, retry=RetryPolicy(max_attempts=2, backoff_base=1.0), breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180))
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": reveal(self._cfg.api_token)}

    async def ping(self) -> bool:
        await self._require().get_json("/user", headers=self._headers())
        return True

    async def list_security_alerts(self) -> list[GitLabAlertFeed]:
        if not self._cfg.project_ids:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Configure at least one GitLab project ID or path.")
        client = self._require()
        headers = self._headers()
        feeds = []
        for project in self._cfg.project_ids:
            path = f"/projects/{quote(project, safe='')}/vulnerability_findings"
            alerts: list[dict[str, Any]] = []
            for page in range(1, _MAX_PAGES + 1):
                payload = await client.get_json(
                    path, headers=headers,
                    params={"scope": "all", "per_page": _PAGE_SIZE, "page": page},
                )
                if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
                    raise IntegrationError("GitLab returned an invalid finding page", provider=PROVIDER)
                alerts.extend(payload)
                if len(payload) < _PAGE_SIZE:
                    break
            else:
                raise IntegrationError("GitLab finding page limit exceeded", provider=PROVIDER)
            feeds.append(GitLabAlertFeed(project=project, alerts=alerts))
        return feeds


__all__ = ["GitLabAlertFeed", "GitLabClient", "PROVIDER"]
