"""Read-only CrowdStrike Falcon Spotlight vulnerability connector."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError, IntegrationTimeoutError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "CrowdStrike Falcon Spotlight"
_ALLOWED_HOSTS = frozenset(
    {
        "api.crowdstrike.com",
        "api.us-2.crowdstrike.com",
        "api.eu-1.crowdstrike.com",
        "api.laggar.gcw.crowdstrike.com",
        "api.us-gov-1.crowdstrike.mil",
    }
)
_PAGE_SIZE = 1000
_MAX_PAGES = 100
_MAX_RECORDS = 50_000
_MAX_SYNC_SECONDS = 300


class CrowdStrikeClient:
    """Fetch complete open Spotlight snapshots using Vulnerabilities: READ only."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.crowdstrike
        self._redis = redis
        self._client: ResilientClient | None = None
        self._token: str | None = None

    def _base_url(self) -> str:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set client_id and client_secret with Vulnerabilities: READ."
            )
        parsed = urlsplit(self._cfg.base_url.rstrip("/"))
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_HOSTS
            or parsed.port is not None
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise IntegrationError("Unsupported CrowdStrike cloud URL", provider=PROVIDER)
        return self._cfg.base_url.rstrip("/")

    def _require(self) -> ResilientClient:
        base_url = self._base_url()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=base_url,
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    async def _access_token(self) -> str:
        if self._token is not None:
            return self._token
        response = await self._require().request(
            "POST",
            "/oauth2/token",
            data={
                "client_id": reveal(self._cfg.client_id),
                "client_secret": reveal(self._cfg.client_secret),
            },
            headers={"Accept": "application/json"},
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IntegrationError("CrowdStrike token response is malformed", provider=PROVIDER) from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 8192
            or any(character.isspace() or ord(character) < 32 for character in token)
        ):
            raise IntegrationError("CrowdStrike did not return a usable access token", provider=PROVIDER)
        self._token = token
        return token

    async def _page(self, after: str | None, limit: int) -> tuple[list[dict[str, Any]], str | None]:
        params: dict[str, Any] = {
            "filter": "status:'open'",
            "limit": limit,
            "sort": "updated_timestamp|desc",
            "facet": ["host_info", "remediation", "cve"],
        }
        if after is not None:
            params["after"] = after
        payload = await self._require().get_json(
            "/spotlight/combined/vulnerabilities/v1",
            params=params,
            headers={"Authorization": f"Bearer {await self._access_token()}"},
        )
        resources = payload.get("resources") if isinstance(payload, dict) else None
        meta = payload.get("meta") if isinstance(payload, dict) else None
        pagination = meta.get("pagination") if isinstance(meta, dict) else None
        if (
            not isinstance(resources, list)
            or len(resources) > limit
            or any(not isinstance(item, dict) for item in resources)
            or not isinstance(pagination, dict)
        ):
            raise IntegrationError("CrowdStrike returned an incomplete vulnerability page", provider=PROVIDER)
        next_after = pagination.get("after")
        if next_after in (None, ""):
            return resources, None
        if not isinstance(next_after, str) or len(next_after) > 4096:
            raise IntegrationError("CrowdStrike returned an invalid pagination token", provider=PROVIDER)
        return resources, next_after

    async def _list_vulnerabilities(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        after: str | None = None
        seen_after: set[str] = set()
        seen_ids: set[str] = set()
        for _ in range(_MAX_PAGES):
            page, next_after = await self._page(after, _PAGE_SIZE)
            for item in page:
                item_id = item.get("id")
                if not isinstance(item_id, str) or not item_id or item_id in seen_ids:
                    raise IntegrationError("CrowdStrike returned an invalid or repeated vulnerability ID", provider=PROVIDER)
                seen_ids.add(item_id)
                records.append(item)
                if len(records) > _MAX_RECORDS:
                    raise IntegrationError("CrowdStrike vulnerability limit exceeded", provider=PROVIDER)
            if next_after is None:
                return records
            if not page or next_after in seen_after:
                raise IntegrationError("CrowdStrike pagination did not advance", provider=PROVIDER)
            seen_after.add(next_after)
            after = next_after
        raise IntegrationError("CrowdStrike page limit exceeded", provider=PROVIDER)

    async def list_vulnerabilities(self) -> list[dict[str, Any]]:
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await self._list_vulnerabilities()
        except TimeoutError as exc:
            raise IntegrationTimeoutError("CrowdStrike sync timed out", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await self._page(None, 1)
        return True

    async def aclose(self) -> None:
        self._token = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["CrowdStrikeClient", "PROVIDER"]
