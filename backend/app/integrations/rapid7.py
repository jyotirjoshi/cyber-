"""Read-only Rapid7 InsightVM Console API connector.

The connector never creates scans, assets, or exceptions.  Every request is
bounded to the tenant's configured Console asset IDs and uses the Console's
documented API v3 service-vulnerabilities endpoint.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Rapid7 InsightVM"
_MAX_ASSETS = 20
_MAX_VULNERABILITIES = 100_000
_PAGE_SIZE = 500


class Rapid7Client:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.rapid7
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> list[str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set an HTTPS Console URL, username, password, and selected asset_ids."
            )
        parsed = urlsplit(self._cfg.base_url or "")
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise IntegrationError("Rapid7 Console URL must be an HTTPS origin", provider=PROVIDER)
        asset_ids = list(self._cfg.asset_ids)
        if (
            not 1 <= len(asset_ids) <= _MAX_ASSETS
            or len(set(asset_ids)) != len(asset_ids)
            or any(not item.isdecimal() or int(item) <= 0 for item in asset_ids)
        ):
            raise IntegrationError("Invalid Rapid7 asset scope", provider=PROVIDER)
        return asset_ids

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=(self._cfg.base_url or "").rstrip("/"),
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        encoded = base64.b64encode(
            f"{reveal(self._cfg.username)}:{reveal(self._cfg.password)}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {encoded}", "Accept": "application/json"}

    async def ping(self) -> bool:
        asset_id = self._scope()[0]
        payload = await self._require().get_json(f"/api/3/assets/{asset_id}", headers=self._headers())
        return isinstance(payload, dict) and payload.get("id") is not None

    async def list_vulnerabilities(self) -> list[dict[str, Any]]:
        """Fetch a complete, bounded service-vulnerability view for selected assets."""
        records: list[dict[str, Any]] = []
        client = self._require()
        for asset_id in self._scope():
            asset = await client.get_json(f"/api/3/assets/{asset_id}", headers=self._headers())
            if not isinstance(asset, dict):
                raise IntegrationError("Malformed Rapid7 asset response", provider=PROVIDER)
            resource = _asset_resource(asset)
            if not resource:
                raise IntegrationError(
                    "Rapid7 asset has no usable IP address or hostname", provider=PROVIDER
                )
            services = asset.get("services")
            if not isinstance(services, list):
                raise IntegrationError(
                    "Rapid7 asset response omitted services; select an assessed asset.",
                    provider=PROVIDER,
                )
            for service in services:
                if not isinstance(service, dict):
                    raise IntegrationError("Malformed Rapid7 service response", provider=PROVIDER)
                protocol = str(service.get("protocol") or "").lower()
                port = service.get("port")
                if protocol not in {"tcp", "udp"} or not isinstance(port, int) or not 0 <= port <= 65535:
                    continue
                page = 0
                while True:
                    response = await client.get_json(
                        f"/api/3/assets/{asset_id}/services/{protocol}/{port}/vulnerabilities",
                        headers=self._headers(),
                        params={"page": page, "size": _PAGE_SIZE},
                    )
                    if not isinstance(response, dict) or not isinstance(response.get("resources"), list):
                        raise IntegrationError("Malformed Rapid7 vulnerability page", provider=PROVIDER)
                    items = response["resources"]
                    for item in items:
                        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                            raise IntegrationError(
                                "Rapid7 vulnerability has no stable identity", provider=PROVIDER
                            )
                        records.append(
                            {
                                **item,
                                "asset_id": asset_id,
                                "asset_resource": resource,
                                "protocol": protocol,
                                "port": port,
                            }
                        )
                        if len(records) > _MAX_VULNERABILITIES:
                            raise IntegrationError(
                                "Rapid7 vulnerability limit exceeded", provider=PROVIDER
                            )
                    if len(items) < _PAGE_SIZE:
                        break
                    page += 1
        return records

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _asset_resource(asset: dict[str, Any]) -> str:
    addresses = asset.get("addresses")
    if isinstance(addresses, list):
        for address in addresses:
            if isinstance(address, str) and address:
                return address[:1000]
            if isinstance(address, dict):
                value = address.get("value") or address.get("ip")
                if isinstance(value, str) and value:
                    return value[:1000]
    for key in ("hostName", "hostname", "ip"):
        value = asset.get(key)
        if isinstance(value, str) and value:
            return value[:1000]
    return ""


__all__ = ["Rapid7Client", "PROVIDER"]
