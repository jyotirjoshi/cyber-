"""Read-only Google Security Command Center v2 findings connector."""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError, IntegrationTimeoutError
from app.integrations.http import ResilientClient, RetryPolicy, build_client
from app.services.gcp_credentials import mint_gcp_access_token

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Google Security Command Center"
_PROJECT = re.compile(r"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_LOCATION = re.compile(r"\A(?:global|[a-z][a-z0-9-]{1,30})\Z")
_PAGE_SIZE = 1000
_MAX_PAGES = 100
_MAX_FINDINGS = 50_000
_MAX_SYNC_SECONDS = 300


class GcpSccClient:
    """Fetch a complete bounded project snapshot across all SCC sources."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.gcp_scc
        self._redis = redis
        self._client: ResilientClient | None = None
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _scope(self) -> tuple[str, str, str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set project ID, SCC location, and service-account JSON."
            )
        project = str(self._cfg.project_id or "")
        location = str(self._cfg.location or "")
        key = self._cfg.service_account_json.get_secret_value()
        if _PROJECT.fullmatch(project) is None or _LOCATION.fullmatch(location) is None:
            raise IntegrationError("Invalid GCP project or SCC location.", provider=PROVIDER)
        return project, location, key

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url="https://securitycenter.googleapis.com",
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    async def _access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token
        project, _, key = self._scope()
        try:
            token = await asyncio.to_thread(mint_gcp_access_token, key, project)
        except Exception as exc:
            raise IntegrationError("GCP service-account authentication failed.", provider=PROVIDER) from exc
        self._token = token
        self._token_expires_at = time.monotonic() + 2400
        return token

    async def _page(self, page_token: str | None) -> tuple[list[dict[str, Any]], str | None]:
        project, location, _ = self._scope()
        params: dict[str, Any] = {
            "pageSize": _PAGE_SIZE,
            "orderBy": "eventTime desc",
        }
        if page_token is not None:
            params["pageToken"] = page_token
        payload = await self._require().get_json(
            f"/v2/projects/{project}/sources/-/locations/{location}/findings",
            params=params,
            headers={"Authorization": f"Bearer {await self._access_token()}"},
        )
        results = payload.get("listFindingsResults") if isinstance(payload, dict) else None
        if results is None:
            results = []
        if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
            raise IntegrationError("GCP SCC returned an incomplete findings page.", provider=PROVIDER)
        token = payload.get("nextPageToken")
        if token in (None, ""):
            return results, None
        if not isinstance(token, str) or len(token) > 4096:
            raise IntegrationError("GCP SCC returned an invalid pagination token.", provider=PROVIDER)
        return results, token

    async def _list_findings(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        seen_names: set[str] = set()
        for _ in range(_MAX_PAGES):
            page, next_token = await self._page(token)
            for result in page:
                finding = result.get("finding")
                name = finding.get("name") if isinstance(finding, dict) else None
                if not isinstance(name, str) or not name or name in seen_names:
                    raise IntegrationError("GCP SCC returned an invalid or repeated finding.", provider=PROVIDER)
                seen_names.add(name)
                records.append(result)
                if len(records) > _MAX_FINDINGS:
                    raise IntegrationError("GCP SCC finding limit exceeded.", provider=PROVIDER)
            if next_token is None:
                return records
            if not page or next_token in seen_tokens:
                raise IntegrationError("GCP SCC pagination did not advance.", provider=PROVIDER)
            seen_tokens.add(next_token)
            token = next_token
        raise IntegrationError("GCP SCC page limit exceeded.", provider=PROVIDER)

    async def list_findings(self) -> list[dict[str, Any]]:
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await self._list_findings()
        except TimeoutError as exc:
            raise IntegrationTimeoutError("GCP SCC sync timed out.", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await self._page(None)
        return True

    async def aclose(self) -> None:
        self._token = None
        self._token_expires_at = 0.0
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["GcpSccClient", "PROVIDER"]
