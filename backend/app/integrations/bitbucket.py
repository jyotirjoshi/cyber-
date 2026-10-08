"""Tenant-scoped Bitbucket Cloud repository connectivity."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Bitbucket"
_API_BASE_URL = "https://api.bitbucket.org/2.0"


class BitbucketClient:
    """Validate access to the one tenant-configured Bitbucket repository."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._settings = settings
        self._cfg = settings.bitbucket
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint=(
                    "Configure a Bitbucket API token, account email, workspace, and repository."
                ),
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=_API_BASE_URL,
                settings=self._settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        raw = f"{self._cfg.account_email}:{reveal(self._cfg.api_token)}".encode()
        encoded = base64.b64encode(raw).decode("ascii")
        return {"Authorization": f"Basic {encoded}", "Accept": "application/json"}

    async def ping(self) -> bool:
        workspace = self._cfg.workspace or ""
        repository = self._cfg.repository or ""
        payload = await self._require().get_json(
            f"/repositories/{workspace}/{repository}", headers=self._headers()
        )
        if (
            not isinstance(payload, dict)
            or str(payload.get("full_name", "")).casefold()
            != f"{workspace}/{repository}".casefold()
            or payload.get("scm") != "git"
        ):
            raise IntegrationError("Bitbucket did not confirm the configured repository.", provider=PROVIDER)
        return True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["BitbucketClient", "PROVIDER"]
