"""Read-only Qualys VM host-detection connector for one scoped IP address."""

from __future__ import annotations

import base64
import ipaddress
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Qualys VM"
_HOSTS = frozenset(
    {
        "qualysapi.qualys.com",
        "qualysapi.qg2.apps.qualys.com",
        "qualysapi.qg3.apps.qualys.com",
        "qualysapi.qg4.apps.qualys.com",
        "qualysapi.qualys.eu",
    }
)
_MAX_REPORT_BYTES = 10 * 1024 * 1024


class QualysClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.qualys
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> tuple[str, str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set Qualys username, password, and one approved asset_ip."
            )
        parsed = urlsplit(self._cfg.base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _HOSTS
            or parsed.path not in {"", "/"}
            or parsed.username
            or parsed.password
            or parsed.port
        ):
            raise IntegrationError("Unsupported Qualys API host", provider=PROVIDER)
        try:
            asset_ip = str(ipaddress.ip_address(self._cfg.asset_ip or ""))
        except ValueError as exc:
            raise IntegrationError("Invalid Qualys asset IP", provider=PROVIDER) from exc
        return parsed.hostname or "", asset_ip

    def _require(self) -> ResilientClient:
        host, _ = self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=f"https://{host}",
                settings=self.settings,
                redis=self._redis,
                timeout=60.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        username = reveal(self._cfg.username)
        password = reveal(self._cfg.password)
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {
            "Authorization": f"Basic {encoded}",
            "Accept": "application/xml",
            "X-Requested-With": "Cynux",
        }

    async def host_detections_xml(self, *, details: str) -> bytes:
        _, asset_ip = self._scope()
        response = await self._require().request(
            "GET",
            "/api/2.0/fo/asset/host/vm/detection/",
            params={"action": "list", "details": details, "ips": asset_ip, "truncation_limit": "10000"},
            headers=self._headers(),
        )
        if len(response.content) > _MAX_REPORT_BYTES:
            raise IntegrationError("Qualys response exceeds the supported import limit", provider=PROVIDER)
        if not response.content:
            raise IntegrationError("Qualys returned an empty host-detection response", provider=PROVIDER)
        return bytes(response.content)

    async def ping(self) -> bool:
        # The same read-only endpoint validates credentials and configured scope.
        await self.host_detections_xml(details="Basic")
        return True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["QualysClient", "PROVIDER"]
