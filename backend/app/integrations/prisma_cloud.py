"""Read-only Prisma Cloud CSPM alert ingestion."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError, IntegrationTimeoutError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Prisma Cloud"
_PAGE_SIZE = 100
_MAX_PAGES = 500
_MAX_ALERTS = 50_000
_MAX_SYNC_SECONDS = 300


class PrismaCloudClient:
    """Fetch complete open-alert snapshots from explicitly selected cloud accounts."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.prisma_cloud
        self._redis = redis
        self._client: ResilientClient | None = None
        self._token: str | None = None

    def _scope(self) -> set[str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set base_url, access_key_id, secret_key, and cloud_account_ids."
            )
        parsed = urlsplit(self._cfg.base_url.rstrip("/"))
        hostname = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or not (hostname.endswith(".prismacloud.io") or hostname.endswith(".prismacloud.cn"))
            or parsed.port is not None
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise IntegrationError("Unsupported Prisma Cloud API URL", provider=PROVIDER)
        accounts = list(self._cfg.cloud_account_ids)
        if not 1 <= len(accounts) <= 100 or len(accounts) != len(set(accounts)):
            raise IntegrationError("Invalid Prisma Cloud account scope", provider=PROVIDER)
        return set(accounts)

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url.rstrip("/"),
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    async def _access_token(self) -> str:
        if self._token is not None:
            return self._token
        payload = await self._require().post_json(
            "/login",
            json={
                "username": reveal(self._cfg.access_key_id),
                "password": reveal(self._cfg.secret_key),
            },
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token or len(token) > 8192 or any(c.isspace() for c in token):
            raise IntegrationError("Prisma Cloud did not return a usable JWT", provider=PROVIDER)
        self._token = token
        return token

    async def _page(self, page_token: str | None, limit: int) -> tuple[list[dict[str, Any]], str | None]:
        params: dict[str, Any] = {
            "limit": limit,
            "detailed": "true",
            "alert.status": "open",
            "cloud.accountId": ",".join(sorted(self._scope())),
        }
        if page_token:
            params["pageToken"] = page_token
        payload = await self._require().get_json(
            "/v2/alert",
            params=params,
            headers={"x-redlock-auth": await self._access_token()},
        )
        items = payload.get("items") if isinstance(payload, dict) else None
        next_token = payload.get("nextPageToken") if isinstance(payload, dict) else None
        if not isinstance(items, list) or len(items) > limit or any(not isinstance(x, dict) for x in items):
            raise IntegrationError("Prisma Cloud returned an invalid alert page", provider=PROVIDER)
        if next_token in (None, ""):
            next_token = None
        elif not isinstance(next_token, str) or len(next_token) > 4096:
            raise IntegrationError("Prisma Cloud returned an invalid page token", provider=PROVIDER)
        return items, next_token

    async def _list_alerts(self) -> list[dict[str, Any]]:
        allowed = self._scope()
        records: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        seen_ids: set[str] = set()
        for _ in range(_MAX_PAGES):
            page, next_token = await self._page(token, _PAGE_SIZE)
            for alert in page:
                alert_id = alert.get("id")
                resource = alert.get("resource")
                account_id = resource.get("accountId") if isinstance(resource, dict) else None
                if not isinstance(alert_id, str) or not alert_id or alert_id in seen_ids:
                    raise IntegrationError("Prisma Cloud returned an invalid or repeated alert ID", provider=PROVIDER)
                if not isinstance(account_id, str) or account_id not in allowed:
                    raise IntegrationError("Prisma Cloud returned an alert outside the selected cloud accounts", provider=PROVIDER)
                seen_ids.add(alert_id)
                records.append(alert)
                if len(records) > _MAX_ALERTS:
                    raise IntegrationError("Prisma Cloud alert limit exceeded", provider=PROVIDER)
            if next_token is None:
                return records
            if not page or next_token in seen_tokens:
                raise IntegrationError("Prisma Cloud pagination did not advance", provider=PROVIDER)
            seen_tokens.add(next_token)
            token = next_token
        raise IntegrationError("Prisma Cloud page limit exceeded", provider=PROVIDER)

    async def list_alerts(self) -> list[dict[str, Any]]:
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await self._list_alerts()
        except TimeoutError as exc:
            raise IntegrationTimeoutError("Prisma Cloud sync timed out", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await self._page(None, 1)
        return True

    async def aclose(self) -> None:
        self._token = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["PROVIDER", "PrismaCloudClient"]
