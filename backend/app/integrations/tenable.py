"""Tenable Vulnerability Management scan control and results client."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Tenable VM"
_MAX_HOSTS = 10_000
_MAX_VULNS = 100_000


class TenableClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.tenable
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> list[str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Set access_key, secret_key, and scan_ids.")
        if self._cfg.base_url.rstrip("/") != "https://cloud.tenable.com":
            raise IntegrationError("Unsupported Tenable VM host", provider=PROVIDER)
        try:
            scans = [str(uuid.UUID(scan)) for scan in self._cfg.scan_ids]
        except ValueError as exc:
            raise IntegrationError("Invalid Tenable scan UUID", provider=PROVIDER) from exc
        if not 1 <= len(scans) <= 20 or len(set(scans)) != len(scans):
            raise IntegrationError("Invalid Tenable scan list", provider=PROVIDER)
        return scans

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER, base_url="https://cloud.tenable.com",
                settings=self.settings, redis=self._redis, timeout=30.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"X-ApiKeys": f"accessKey={reveal(self._cfg.access_key)}; secretKey={reveal(self._cfg.secret_key)}",
                "Accept": "application/json"}

    async def ping(self) -> bool:
        scan = self._scope()[0]
        payload = await self._require().get_json(f"/scans/{scan}", headers=self._headers())
        return isinstance(payload, dict) and isinstance(payload.get("info"), dict)

    def _configured_scan(self, scan_id: str) -> str:
        try:
            normalized = str(uuid.UUID(scan_id))
        except (ValueError, TypeError) as exc:
            raise IntegrationError("Invalid Tenable scan UUID", provider=PROVIDER) from exc
        if normalized not in self._scope():
            raise IntegrationError("Tenable scan is not configured for this organization", provider=PROVIDER)
        return normalized

    async def latest_scan_status(self, scan_id: str) -> str:
        """Return Tenable's current status for an explicitly configured scan."""
        scan = self._configured_scan(scan_id)
        payload = await self._require().get_json(
            f"/scans/{scan}/latest-status", headers=self._headers()
        )
        status = payload.get("status") if isinstance(payload, dict) else None
        if not isinstance(status, str) or not status:
            raise IntegrationError("Malformed Tenable scan status", provider=PROVIDER)
        return status

    async def launch_scan(self, scan_id: str) -> str | None:
        """Launch only a saved scan with its existing targets, never arbitrary targets."""
        scan = self._configured_scan(scan_id)
        status = await self.latest_scan_status(scan)
        if status not in {"completed", "aborted", "canceled", "empty"}:
            user_message = (
                "Tenable scan is running. Wait for it to finish before launching again."
                if status in {"running", "initializing", "pending", "resuming"}
                else "Tenable scan cannot be launched in its current state."
            )
            raise IntegrationError(
                f"Tenable scan cannot be launched while status is {status}",
                provider=PROVIDER, user_message=user_message, retryable=False,
            )
        # POST is intentionally not supplied an idempotency key: Tenable does not
        # document one, so the shared transport must not retry an ambiguous launch.
        payload = await self._require().post_json(
            f"/scans/{scan}/launch", headers=self._headers()
        )
        launched_uuid = payload.get("scan_uuid") if isinstance(payload, dict) else None
        return launched_uuid if isinstance(launched_uuid, str) and launched_uuid else None

    async def list_vulnerabilities(self) -> list[dict[str, Any]]:
        """Fetch complete latest scans before any database staging; reject partial results."""
        scans = self._scope()
        client = self._require()
        records: list[dict[str, Any]] = []
        total_hosts = 0
        for scan in scans:
            detail = await client.get_json(f"/scans/{scan}", headers=self._headers())
            if not isinstance(detail, dict) or not isinstance(detail.get("info"), dict):
                raise IntegrationError("Malformed Tenable scan response", provider=PROVIDER)
            info = detail["info"]
            if info.get("is_archived") is True or info.get("status") != "completed":
                raise IntegrationError("Tenable scan is archived or not complete", provider=PROVIDER)
            if info.get("reporting_mode") == "differential":
                raise IntegrationError("Differential Tenable scan cannot be fully imported", provider=PROVIDER)
            hosts = detail.get("hosts")
            if not isinstance(hosts, list):
                raise IntegrationError("Tenable scan omitted hosts", provider=PROVIDER)
            total_hosts += len(hosts)
            if total_hosts > _MAX_HOSTS:
                raise IntegrationError("Tenable scan host limit exceeded", provider=PROVIDER)
            for host in hosts:
                if not isinstance(host, dict) or not isinstance(host.get("host_id"), int):
                    raise IntegrationError("Tenable scan host has no ID", provider=PROVIDER)
                host_id = host["host_id"]
                host_uuid = host.get("uuid") or host.get("asset_id")
                if not host_uuid:
                    raise IntegrationError("Tenable scan host has no stable identity", provider=PROVIDER)
                payload = await client.get_json(f"/scans/{scan}/hosts/{host_id}", headers=self._headers())
                if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                    raise IntegrationError("Tenable host omitted vulnerabilities", provider=PROVIDER)
                for vuln in payload["vulnerabilities"]:
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("plugin_id"), int):
                        raise IntegrationError("Tenable vulnerability has no plugin ID", provider=PROVIDER)
                    records.append({**vuln, "scan_id": scan, "host_uuid": str(host_uuid),
                                    "hostname": str(host.get("hostname") or host_uuid)})
                    if len(records) > _MAX_VULNS:
                        raise IntegrationError("Tenable vulnerability limit exceeded", provider=PROVIDER)
        return records

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
