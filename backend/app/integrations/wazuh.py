"""Wazuh manager connectivity using short-lived JWT authentication.

The Wazuh manager API authenticates with HTTP Basic credentials only at
``/security/user/authenticate``.  All subsequent requests carry the returned
JWT, so a long-lived password is neither replayed nor retained in a request
header after login.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Wazuh"


class WazuhClient:
    """A read-only Wazuh manager API client suitable for tenant health checks."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.wazuh
        self._redis = redis
        self._client: ResilientClient | None = None
        self._jwt: str | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint=(
                    "Set CYNUX_WAZUH__BASE_URL, CYNUX_WAZUH__API_USERNAME and "
                    "CYNUX_WAZUH__API_PASSWORD."
                ),
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url or "",
                settings=self.settings,
                redis=self._redis,
                timeout=float(self._cfg.timeout_seconds),
                verify=self._cfg.verify_tls,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._jwt = None

    def _basic_auth_header(self) -> str:
        username = self._cfg.api_username or ""
        password = reveal(self._cfg.api_password)
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    @staticmethod
    def _token(payload: Any) -> str:
        if isinstance(payload, str) and payload.strip():
            return payload.strip()
        if isinstance(payload, dict):
            token = (payload.get("data") or {}).get("token")
            if isinstance(token, str) and token.strip():
                return token.strip()
        raise IntegrationError(
            "Wazuh authentication returned no token.", provider=PROVIDER
        )

    async def _authenticate(self) -> str:
        if self._jwt:
            return self._jwt
        payload = await self._require().post_json(
            "/security/user/authenticate",
            params={"raw": "true"},
            headers={"Authorization": self._basic_auth_header()},
        )
        self._jwt = self._token(payload)
        return self._jwt

    async def ping(self) -> bool:
        """Verify authentication and read the manager metadata without changing it."""
        token = await self._authenticate()
        await self._require().get_json(
            "/manager/info", headers={"Authorization": f"Bearer {token}"}
        )
        return True


__all__ = ["PROVIDER", "WazuhClient"]
