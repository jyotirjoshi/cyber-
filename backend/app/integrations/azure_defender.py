"""Read-only Microsoft Defender for Cloud security-alert connector."""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError, IntegrationTimeoutError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Microsoft Defender for Cloud"
_UUID = re.compile(r"\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z", re.I)
_MAX_PAGES = 500
_MAX_ALERTS = 50_000
_MAX_SYNC_SECONDS = 300


class AzureDefenderClient:
    """Read a bounded subscription alert snapshot without provider-side writes."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.azure_defender
        self._redis = redis
        self._auth: ResilientClient | None = None
        self._api: ResilientClient | None = None
        self._token: str | None = None
        self._expires_at = 0.0

    def _scope(self) -> tuple[str, str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set tenant ID, client ID, client secret, and subscription ID.",
            )
        tenant = self._cfg.tenant_id.get_secret_value() if self._cfg.tenant_id else ""
        subscription = str(self._cfg.subscription_id or "")
        if _UUID.fullmatch(tenant) is None or _UUID.fullmatch(subscription) is None:
            raise IntegrationError("Invalid Azure tenant or subscription scope.", provider=PROVIDER)
        return tenant.lower(), subscription.lower()

    def _auth_client(self) -> ResilientClient:
        tenant, _ = self._scope()
        if self._auth is None:
            self._auth = build_client(
                provider=PROVIDER,
                base_url=f"https://login.microsoftonline.com/{tenant}",
                settings=self.settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
            )
        return self._auth

    def _api_client(self) -> ResilientClient:
        self._scope()
        if self._api is None:
            self._api = build_client(
                provider=PROVIDER,
                base_url="https://management.azure.com",
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._api

    async def _access_token(self) -> str:
        if self._token and time.monotonic() < self._expires_at:
            return self._token
        response = await self._auth_client().request(
            "POST",
            "/oauth2/v2.0/token",
            data={
                "client_id": reveal(self._cfg.client_id),
                "client_secret": reveal(self._cfg.client_secret),
                "scope": "https://management.azure.com/.default",
                "grant_type": "client_credentials",
            },
            headers={"Accept": "application/json"},
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IntegrationError("Azure returned a malformed token response.", provider=PROVIDER) from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        expires = payload.get("expires_in", 300) if isinstance(payload, dict) else 300
        if not isinstance(token, str) or not token or len(token) > 8192:
            raise IntegrationError("Azure did not return a usable access token.", provider=PROVIDER)
        if isinstance(expires, bool) or not isinstance(expires, int | float) or not 0 < expires <= 86400:
            raise IntegrationError("Azure returned an invalid token expiry.", provider=PROVIDER)
        self._token = token
        self._expires_at = time.monotonic() + max(0, float(expires) - 30)
        return token

    def _next_path(self, next_link: str) -> str:
        _, subscription = self._scope()
        parsed = urlsplit(next_link)
        prefix = f"/subscriptions/{subscription}/"
        if (
            parsed.scheme != "https"
            or parsed.hostname != "management.azure.com"
            or parsed.port is not None
            or parsed.username
            or parsed.password
            or not parsed.path.lower().startswith(prefix)
            or parsed.fragment
        ):
            raise IntegrationError("Azure returned an unsafe pagination link.", provider=PROVIDER)
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")

    async def _page(self, path: str) -> tuple[list[dict[str, Any]], str | None]:
        payload = await self._api_client().get_json(
            path, headers={"Authorization": f"Bearer {await self._access_token()}"}
        )
        alerts = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(alerts, list) or any(not isinstance(item, dict) for item in alerts):
            raise IntegrationError("Azure returned an incomplete alerts page.", provider=PROVIDER)
        next_link = payload.get("nextLink")
        if next_link in (None, ""):
            return alerts, None
        if not isinstance(next_link, str) or len(next_link) > 8192:
            raise IntegrationError("Azure returned an invalid pagination link.", provider=PROVIDER)
        return alerts, self._next_path(next_link)

    async def _list_alerts(self) -> list[dict[str, Any]]:
        _, subscription = self._scope()
        path = (
            f"/subscriptions/{subscription}/providers/Microsoft.Security/alerts"
            "?api-version=2022-01-01"
        )
        records: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        seen_ids: set[str] = set()
        for _ in range(_MAX_PAGES):
            page, next_path = await self._page(path)
            for item in page:
                identifier = item.get("name") or item.get("id")
                if not isinstance(identifier, str) or not identifier or identifier in seen_ids:
                    raise IntegrationError("Azure returned an invalid or repeated alert ID.", provider=PROVIDER)
                seen_ids.add(identifier)
                records.append(item)
                if len(records) > _MAX_ALERTS:
                    raise IntegrationError("Azure Defender alert limit exceeded.", provider=PROVIDER)
            if next_path is None:
                return records
            if not page or next_path in seen_paths:
                raise IntegrationError("Azure pagination did not advance.", provider=PROVIDER)
            seen_paths.add(next_path)
            path = next_path
        raise IntegrationError("Azure Defender page limit exceeded.", provider=PROVIDER)

    async def list_alerts(self) -> list[dict[str, Any]]:
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await self._list_alerts()
        except TimeoutError as exc:
            raise IntegrationTimeoutError("Azure Defender sync timed out.", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        _, subscription = self._scope()
        await self._page(
            f"/subscriptions/{subscription}/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        )
        return True

    async def aclose(self) -> None:
        self._token = None
        self._expires_at = 0.0
        if self._auth is not None:
            await self._auth.aclose()
            self._auth = None
        if self._api is not None:
            await self._api.aclose()
            self._api = None


__all__ = ["AzureDefenderClient", "PROVIDER"]
