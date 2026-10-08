"""Read-only SonarQube Server vulnerability connector."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "SonarQube"
_PAGE_SIZE = 100
_MAX_RESULTS_PER_PROJECT = 10_000


class SonarQubeClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.sonarqube
        self._redis = redis
        self._client: ResilientClient | None = None

    def _require(self) -> ResilientClient:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set the SonarQube base URL and user API token."
            )
        base_url = self._cfg.base_url
        if not base_url:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Set the SonarQube base URL.")
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=base_url.rstrip("/"),
                settings=self.settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {reveal(self._cfg.api_token)}",
            "Accept": "application/json",
        }

    async def ping(self) -> bool:
        response = await self._require().get_json(
            "/api/authentication/validate", headers=self._headers()
        )
        return isinstance(response, dict) and response.get("valid") is True

    async def list_vulnerabilities(self) -> list[dict[str, Any]]:
        """Page through configured projects; never treat a partial page as a clean result."""
        client = self._require()
        projects = [str(key).strip() for key in self._cfg.project_keys if str(key).strip()]
        if not projects:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Configure at least one project key."
            )
        collected: list[dict[str, Any]] = []
        for project in dict.fromkeys(projects):
            page = 1
            seen = 0
            issue_keys: set[str] = set()
            while True:
                payload = await client.get_json(
                    "/api/issues/search",
                    params={
                        "componentKeys": project,
                        "impactSoftwareQualities": "SECURITY",
                        "p": page,
                        "ps": _PAGE_SIZE,
                    },
                    headers=self._headers(),
                )
                if not isinstance(payload, dict) or not isinstance(payload.get("issues"), list):
                    raise IntegrationError(
                        "SonarQube returned an invalid issues page", provider=PROVIDER
                    )
                paging = payload.get("paging")
                if not isinstance(paging, dict) or not isinstance(paging.get("total"), int):
                    raise IntegrationError(
                        "SonarQube returned no valid page total", provider=PROVIDER
                    )
                total = paging["total"]
                if total < 0 or total > _MAX_RESULTS_PER_PROJECT:
                    raise IntegrationError(
                        "SonarQube search window exceeded",
                        provider=PROVIDER,
                        user_message="This SonarQube project exceeds the supported search window; its sync was not saved.",
                    )
                issues = payload["issues"]
                if any(not isinstance(issue, dict) or not issue.get("key") for issue in issues):
                    raise IntegrationError(
                        "SonarQube returned an issue without a stable key", provider=PROVIDER
                    )
                if seen < total and not issues:
                    raise IntegrationError(
                        "SonarQube returned an incomplete issues page", provider=PROVIDER
                    )
                for issue in issues:
                    if str(issue.get("project") or "").strip() != project:
                        raise IntegrationError(
                            "SonarQube returned an issue outside the requested project",
                            provider=PROVIDER,
                        )
                    key = str(issue["key"])
                    if key in issue_keys:
                        raise IntegrationError(
                            "SonarQube returned a repeated issue", provider=PROVIDER
                        )
                    issue_keys.add(key)
                    impacts = issue.get("impacts")
                    is_security = (
                        isinstance(impacts, list)
                        and any(
                            isinstance(impact, dict) and impact.get("softwareQuality") == "SECURITY"
                            for impact in impacts
                        )
                    ) or issue.get("type") == "VULNERABILITY"
                    if is_security:
                        collected.append(issue)
                seen += len(issues)
                if seen >= total:
                    break
                page += 1
        return collected

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["SonarQubeClient", "PROVIDER"]
