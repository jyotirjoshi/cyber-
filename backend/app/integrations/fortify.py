"""Bounded read-only Fortify Software Security Center issue connector."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Fortify SSC"
_PAGE_SIZE = 200
_MAX_ISSUES = 100_000
_VERSION_ID = re.compile(r"[1-9]\d{0,18}")


class FortifySscClient:
    """Read complete issue snapshots from configured SSC application versions."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.fortify
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> dict[str, str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set an HTTPS SSC URL, AutomationToken, and application-version mappings.",
            )
        parsed = urlsplit(self._cfg.base_url or "")
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not parsed.path.rstrip("/").endswith("/ssc")
        ):
            raise IntegrationError("Fortify SSC URL must be an HTTPS /ssc origin", provider=PROVIDER)
        versions = dict(self._cfg.application_versions)
        if not (
            1 <= len(versions) <= 100
            and all(
                isinstance(version_id, str)
                and _VERSION_ID.fullmatch(version_id)
                and isinstance(asset, str)
                and 3 <= len(asset) <= 500
                for version_id, asset in versions.items()
            )
        ):
            raise IntegrationError("Invalid Fortify application-version scope", provider=PROVIDER)
        return versions

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
        return {
            "Authorization": f"FortifyToken {reveal(self._cfg.automation_token)}",
            "Accept": "application/json",
        }

    async def ping(self) -> bool:
        version_id = next(iter(self._scope()))
        payload = await self._require().get_json(
            f"/api/v1/projectVersions/{version_id}", headers=self._headers()
        )
        data = payload.get("data") if isinstance(payload, dict) else None
        return isinstance(data, dict) and str(data.get("id")) == version_id

    async def list_issues(self) -> list[dict[str, Any]]:
        client = self._require()
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for version_id, asset in self._scope().items():
            version = await client.get_json(
                f"/api/v1/projectVersions/{version_id}", headers=self._headers()
            )
            data = version.get("data") if isinstance(version, dict) else None
            if not isinstance(data, dict) or str(data.get("id")) != version_id:
                raise IntegrationError("Fortify returned an out-of-scope application version", provider=PROVIDER)
            start = 0
            while True:
                payload = await client.get_json(
                    f"/api/v1/projectVersions/{version_id}/issues",
                    params={"start": start, "limit": _PAGE_SIZE},
                    headers=self._headers(),
                )
                issues = payload.get("data") if isinstance(payload, dict) else None
                total = payload.get("totalCount") if isinstance(payload, dict) else None
                if not isinstance(issues, list) or not isinstance(total, int) or total < 0:
                    raise IntegrationError("Fortify returned an invalid issues page", provider=PROVIDER)
                if start < total and not issues:
                    raise IntegrationError("Fortify pagination stopped before total count", provider=PROVIDER)
                for issue in issues:
                    issue_id = str(issue.get("issueInstanceId") or "") if isinstance(issue, dict) else ""
                    scoped_id = f"{version_id}:{issue_id}"
                    if not issue_id or scoped_id in seen:
                        raise IntegrationError("Fortify issue lacks unique scoped identity", provider=PROVIDER)
                    seen.add(scoped_id)
                    rows.append(
                        {
                            "issue": issue,
                            "application_version_id": version_id,
                            "asset": asset,
                        }
                    )
                    if len(rows) > _MAX_ISSUES:
                        raise IntegrationError("Fortify issue limit exceeded", provider=PROVIDER)
                start += len(issues)
                if start >= total:
                    break
        return rows

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["FortifySscClient", "PROVIDER"]
