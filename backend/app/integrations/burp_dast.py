"""Read-only Burp Suite DAST GraphQL connector."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError, IntegrationTimeoutError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Burp Suite DAST"
_PAGE_SIZE = 500
_MAX_ISSUES_PER_SCAN = 10_000
_MAX_SYNC_SECONDS = 300

_LATEST_SCAN_QUERY = """
query CynuxLatestScan($siteId: ID!) {
  scans(site_id: $siteId, limit: 1, sort_column: start, sort_order: desc) {
    id status site_name
  }
}
"""

_SCAN_ISSUES_QUERY = """
query CynuxScanIssues($scanId: ID!, $start: Int!, $count: Int!) {
  scan(id: $scanId) {
    issues(start: $start, count: $count) {
      serial_number severity confidence path origin description_html remediation_html
      issue_type { type_index name }
    }
  }
}
"""


class BurpDastClient:
    """Read the latest complete issue snapshot for explicitly configured sites."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.burp_dast
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> list[str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set the Burp DAST URL, API key, and explicit site IDs."
            )
        site_ids = [str(value) for value in self._cfg.site_ids]
        if not site_ids or len(site_ids) > 100 or any(re.fullmatch(r"[1-9]\d{0,18}", value) is None for value in site_ids):
            raise IntegrationError("Invalid Burp DAST site scope.", provider=PROVIDER)
        return site_ids

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=str(self._cfg.base_url).rstrip("/"),
                settings=self.settings,
                redis=self._redis,
                headers={"Authorization": reveal(self._cfg.api_key)},
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    async def _graphql(
        self, query: str, variables: dict[str, Any], *, operation: str
    ) -> dict[str, Any]:
        payload = await self._require().post_json(
            "/graphql/v1",
            json={"query": query, "operationName": operation, "variables": variables},
            idempotency_key=f"burp-query:{operation}:{variables}",
        )
        if not isinstance(payload, dict) or payload.get("errors"):
            raise IntegrationError("Burp DAST rejected the GraphQL query.", provider=PROVIDER)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise IntegrationError("Burp DAST returned an incomplete response.", provider=PROVIDER)
        return data

    async def _latest_scan(self, site_id: str) -> dict[str, Any] | None:
        data = await self._graphql(
            _LATEST_SCAN_QUERY, {"siteId": site_id}, operation="CynuxLatestScan"
        )
        scans = data.get("scans")
        if not isinstance(scans, list) or any(not isinstance(scan, dict) for scan in scans):
            raise IntegrationError("Burp DAST returned invalid scan data.", provider=PROVIDER)
        if not scans:
            return None
        scan = scans[0]
        if str(scan.get("status") or "").lower() != "succeeded":
            raise IntegrationError(
                f"Latest Burp DAST scan for site {site_id} is not complete.", provider=PROVIDER
            )
        if not str(scan.get("id") or ""):
            raise IntegrationError("Burp DAST scan has no stable ID.", provider=PROVIDER)
        return scan

    async def _issues(self, scan_id: str) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for start in range(0, _MAX_ISSUES_PER_SCAN, _PAGE_SIZE):
            data = await self._graphql(
                _SCAN_ISSUES_QUERY,
                {"scanId": scan_id, "start": start, "count": _PAGE_SIZE},
                operation="CynuxScanIssues",
            )
            scan = data.get("scan")
            page = scan.get("issues") if isinstance(scan, dict) else None
            if not isinstance(page, list) or any(not isinstance(issue, dict) for issue in page):
                raise IntegrationError("Burp DAST returned invalid issue data.", provider=PROVIDER)
            issues.extend(page)
            if len(page) < _PAGE_SIZE:
                return issues
        raise IntegrationError("Burp DAST issue limit exceeded.", provider=PROVIDER)

    async def list_findings(self) -> list[dict[str, Any]]:
        async def collect() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for site_id in self._scope():
                scan = await self._latest_scan(site_id)
                if scan is None:
                    continue
                for issue in await self._issues(str(scan["id"])):
                    rows.append({"site_id": site_id, "scan": scan, "issue": issue})
            return rows

        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await collect()
        except TimeoutError as exc:
            raise IntegrationTimeoutError("Burp DAST sync timed out.", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await self._latest_scan(self._scope()[0])
        return True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["BurpDastClient", "PROVIDER"]
