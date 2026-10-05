"""Read-only Snyk REST issues client with bounded, same-origin pagination."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Snyk"
_VERSION = "2024-10-15"
_MAX_PAGES = 100
_MAX_ISSUES = 10_000
_HOSTS = frozenset({"api.snyk.io", "api.us.snyk.io", "api.eu.snyk.io", "api.au.snyk.io"})


class SnykClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.snyk
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> tuple[str, str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set a Snyk organization ID and API token."
            )
        parsed = urlsplit(self._cfg.base_url)
        if parsed.scheme != "https" or parsed.hostname not in _HOSTS or parsed.path not in {"", "/"} or parsed.username or parsed.password or parsed.port:
            raise IntegrationError("Unsupported Snyk API host", provider=PROVIDER)
        try:
            organization_id = str(uuid.UUID(self._cfg.organization_id or ""))
        except ValueError as exc:
            raise IntegrationError("Invalid Snyk organization ID", provider=PROVIDER) from exc
        return parsed.hostname or "", organization_id

    def _require(self) -> ResilientClient:
        host, _ = self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=f"https://{host}",
                settings=self.settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {reveal(self._cfg.api_token)}",
            "Accept": "application/vnd.api+json",
        }

    async def ping(self) -> bool:
        _, organization_id = self._scope()
        result = await self._require().get_json(
            f"/rest/orgs/{organization_id}/issues",
            params={"version": _VERSION, "limit": 1},
            headers=self._headers(),
        )
        return isinstance(result, dict) and isinstance(result.get("data"), list)

    async def list_issues(self) -> list[dict[str, Any]]:
        """Read a complete bounded issue window; never save a partial provider response."""
        host, organization_id = self._scope()
        path = f"/rest/orgs/{organization_id}/issues"
        client = self._require()
        params: dict[str, Any] | None = {"version": _VERSION, "limit": 100}
        seen_paths: set[str] = set()
        seen_ids: set[str] = set()
        issues: list[dict[str, Any]] = []
        for _ in range(_MAX_PAGES):
            if path in seen_paths:
                raise IntegrationError("Repeated Snyk issue cursor", provider=PROVIDER)
            seen_paths.add(path)
            payload = await client.get_json(path, params=params, headers=self._headers())
            if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                raise IntegrationError("Invalid Snyk issues page", provider=PROVIDER)
            page = payload["data"]
            if any(not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("attributes"), dict) for item in page):
                raise IntegrationError("Snyk issue lacks stable identity or attributes", provider=PROVIDER)
            for item in page:
                issue_id = str(item["id"])
                if issue_id in seen_ids:
                    raise IntegrationError("Repeated Snyk issue", provider=PROVIDER)
                seen_ids.add(issue_id)
                issues.append(item)
            if len(issues) > _MAX_ISSUES:
                raise IntegrationError("Snyk issue window exceeded", provider=PROVIDER)
            links = payload.get("links")
            if not isinstance(links, dict):
                raise IntegrationError("Snyk omitted pagination links", provider=PROVIDER)
            next_link = links.get("next")
            if next_link is None:
                return issues
            if not isinstance(next_link, str) or not next_link:
                raise IntegrationError("Invalid Snyk issue cursor", provider=PROVIDER)
            next_url = urlsplit(next_link)
            if (next_url.scheme or next_url.netloc) and (
                next_url.scheme != "https" or next_url.hostname != host or next_url.port
            ):
                raise IntegrationError("Foreign Snyk issue cursor", provider=PROVIDER)
            if next_url.path != f"/rest/orgs/{organization_id}/issues" or not next_url.query:
                raise IntegrationError("Out-of-scope Snyk issue cursor", provider=PROVIDER)
            path = f"{next_url.path}?{next_url.query}"
            params = None
        raise IntegrationError("Snyk issue page limit exceeded", provider=PROVIDER)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["SnykClient", "PROVIDER"]
