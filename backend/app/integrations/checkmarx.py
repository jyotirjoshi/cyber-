"""Read-only Checkmarx One results connector."""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Checkmarx One"
_API_HOSTS = frozenset({"ast.checkmarx.net", "us.ast.checkmarx.net", "eu.ast.checkmarx.net", "eu-2.ast.checkmarx.net", "deu.ast.checkmarx.net", "anz.ast.checkmarx.net", "ind.ast.checkmarx.net", "ind-2.ast.checkmarx.net", "sng.ast.checkmarx.net", "mea.ast.checkmarx.net", "gov-il.ast.checkmarx.net"})
_AUTH_HOSTS = frozenset(
    {
        "iam.checkmarx.net",
        "us.iam.checkmarx.net",
        "eu.iam.checkmarx.net",
        "eu-2.iam.checkmarx.net",
        "deu.iam.checkmarx.net",
        "anz.iam.checkmarx.net",
        "ind.iam.checkmarx.net",
        "ind-2.iam.checkmarx.net",
        "sng.iam.checkmarx.net",
        "mea.iam.checkmarx.net",
        "gov-il.iam.checkmarx.net",
    }
)
_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_MAX_RESULTS = 50_000


class CheckmarxClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings, self._cfg, self._redis = settings, settings.checkmarx, redis
        self._auth: ResilientClient | None = None
        self._api: ResilientClient | None = None

    def _scope(self) -> dict[str, str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Set OAuth credentials, tenant, and project-to-repository mappings.")
        api, auth = urlsplit(self._cfg.base_url), urlsplit(self._cfg.auth_url)
        if api.scheme != "https" or api.hostname not in _API_HOSTS or api.path not in {"", "/"} or api.port or api.username or api.password:
            raise IntegrationError("Unsupported Checkmarx API host", provider=PROVIDER)
        if auth.scheme != "https" or auth.hostname not in _AUTH_HOSTS or auth.path not in {"", "/"} or auth.port or auth.username or auth.password:
            raise IntegrationError("Unsupported Checkmarx identity host", provider=PROVIDER)
        if _TENANT.fullmatch(self._cfg.tenant or "") is None:
            raise IntegrationError("Invalid Checkmarx tenant", provider=PROVIDER)
        projects = dict(self._cfg.projects)
        try:
            valid = 1 <= len(projects) <= 100 and all(str(uuid.UUID(key)) == key.lower() and isinstance(value, str) and "/" in value and len(value) <= 500 for key, value in projects.items())
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise IntegrationError("Invalid Checkmarx project scope", provider=PROVIDER)
        return projects

    def _clients(self) -> tuple[ResilientClient, ResilientClient]:
        self._scope()
        if self._auth is None:
            self._auth = build_client(provider=PROVIDER, base_url=self._cfg.auth_url, settings=self.settings, redis=self._redis, timeout=30.0, retry=RetryPolicy(max_attempts=3))
        if self._api is None:
            self._api = build_client(provider=PROVIDER, base_url=self._cfg.base_url, settings=self.settings, redis=self._redis, timeout=45.0, retry=RetryPolicy(max_attempts=3))
        return self._auth, self._api

    async def _token(self) -> str:
        auth, _ = self._clients()
        response = await auth.request("POST", f"/auth/realms/{self._cfg.tenant}/protocol/openid-connect/token", data={"grant_type": "client_credentials", "client_id": reveal(self._cfg.client_id), "client_secret": reveal(self._cfg.client_secret)}, idempotency_key="checkmarx-oauth-client-credentials")
        try:
            payload = response.json()
        except ValueError as exc:
            raise IntegrationError("Checkmarx returned invalid authentication data", provider=PROVIDER) from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise IntegrationError("Checkmarx authentication returned no access token", provider=PROVIDER)
        return token

    async def list_results(self) -> list[dict[str, Any]]:
        projects, token = self._scope(), await self._token()
        _, api = self._clients()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for project_id, asset in projects.items():
            scans = await api.get_json("/api/scans", params={"project-id": project_id, "statuses": "Completed", "sort": "-created-at", "limit": 1, "offset": 0}, headers=headers)
            page = scans.get("scans") if isinstance(scans, dict) else None
            if not isinstance(page, list):
                raise IntegrationError("Checkmarx returned an invalid scan page", provider=PROVIDER)
            if not page:
                continue
            scan = page[0]
            if not isinstance(scan, dict) or scan.get("projectId") != project_id or scan.get("status") != "Completed" or not scan.get("id"):
                raise IntegrationError("Checkmarx returned an incomplete or out-of-scope scan", provider=PROVIDER)
            scan_id, offset = str(scan["id"]), 0
            while True:
                payload = await api.get_json("/api/results", params={"scan-id": scan_id, "limit": 100, "offset": offset}, headers=headers)
                results = payload.get("results") if isinstance(payload, dict) else None
                total = payload.get("totalCount") if isinstance(payload, dict) else None
                if not isinstance(results, list) or not isinstance(total, int):
                    raise IntegrationError("Checkmarx returned an invalid results page", provider=PROVIDER)
                for result in results:
                    result_id = str(result.get("id") or "") if isinstance(result, dict) else ""
                    if not result_id or result_id in seen or str(result.get("scanId") or scan_id) != scan_id:
                        raise IntegrationError("Checkmarx result lacks unique scoped identity", provider=PROVIDER)
                    seen.add(result_id)
                    rows.append({"result": result, "project_id": project_id, "asset": asset})
                if len(rows) > _MAX_RESULTS:
                    raise IntegrationError("Checkmarx result limit exceeded", provider=PROVIDER)
                offset += len(results)
                if offset >= total:
                    break
                if not results:
                    raise IntegrationError("Checkmarx pagination stopped before total count", provider=PROVIDER)
        return rows

    async def ping(self) -> bool:
        await self._token()
        return True

    async def aclose(self) -> None:
        for client in (self._auth, self._api):
            if client is not None:
                await client.aclose()
        self._auth = self._api = None


__all__ = ["CheckmarxClient", "PROVIDER"]
