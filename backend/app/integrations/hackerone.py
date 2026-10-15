"""Read-only HackerOne customer report connector with bounded pagination."""

from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "HackerOne"
_HOST = "api.hackerone.com"
_MAX_PAGES = 500
_MAX_REPORTS = 50_000
_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}")


class HackerOneClient:
    """Read complete report snapshots for an explicit program allowlist."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.hackerone
        self._redis = redis
        self._client: ResilientClient | None = None

    def _scope(self) -> tuple[str, ...]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set an API username, API token, and one or more program handles.",
            )
        parsed = urlsplit(self._cfg.base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != _HOST
            or parsed.path not in {"", "/"}
            or parsed.username
            or parsed.password
            or parsed.port
        ):
            raise IntegrationError("Unsupported HackerOne API host", provider=PROVIDER)
        handles = tuple(str(value) for value in self._cfg.program_handles)
        if (
            not 1 <= len(handles) <= 100
            or any(_HANDLE.fullmatch(handle) is None for handle in handles)
            or len(set(handles)) != len(handles)
        ):
            raise IntegrationError("Invalid HackerOne program scope", provider=PROVIDER)
        return handles

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=f"https://{_HOST}",
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        username = reveal(self._cfg.api_username)
        token = reveal(self._cfg.api_token)
        encoded = base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
        return {"Authorization": f"Basic {encoded}", "Accept": "application/json"}

    @staticmethod
    def _program_handle(report: dict[str, Any]) -> str:
        relationships = report.get("relationships")
        program = relationships.get("program") if isinstance(relationships, dict) else None
        data = program.get("data") if isinstance(program, dict) else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        return str(attributes.get("handle") or "") if isinstance(attributes, dict) else ""

    async def list_reports(self) -> list[dict[str, Any]]:
        handles = self._scope()
        client = self._require()
        path = "/v1/reports"
        params: list[tuple[str, str]] | None = [
            *(("filter[program][]", handle) for handle in handles),
            ("page[size]", "100"),
            ("page[number]", "1"),
        ]
        reports: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_cursors: set[str] = set()
        for _ in range(_MAX_PAGES):
            cursor = path if params is None else f"{path}?{params!r}"
            if cursor in seen_cursors:
                raise IntegrationError("Repeated HackerOne report cursor", provider=PROVIDER)
            seen_cursors.add(cursor)
            payload = await client.get_json(path, params=params, headers=self._headers())
            data = payload.get("data") if isinstance(payload, dict) else None
            links = payload.get("links") if isinstance(payload, dict) else None
            if not isinstance(data, list) or not isinstance(links, dict):
                raise IntegrationError("Invalid HackerOne reports page", provider=PROVIDER)
            for report in data:
                if not isinstance(report, dict) or report.get("type") != "report":
                    raise IntegrationError("Invalid HackerOne report", provider=PROVIDER)
                report_id = str(report.get("id") or "")
                if not report_id or report_id in seen_ids:
                    raise IntegrationError("Repeated or unidentified HackerOne report", provider=PROVIDER)
                if self._program_handle(report) not in handles:
                    raise IntegrationError(
                        "HackerOne returned a report outside the selected programs",
                        provider=PROVIDER,
                    )
                seen_ids.add(report_id)
                reports.append(report)
                if len(reports) > _MAX_REPORTS:
                    raise IntegrationError("HackerOne report limit exceeded", provider=PROVIDER)
            next_link = links.get("next")
            if next_link is None:
                return reports
            if not isinstance(next_link, str) or not next_link:
                raise IntegrationError("Invalid HackerOne report cursor", provider=PROVIDER)
            parsed = urlsplit(next_link)
            if parsed.scheme != "https" or parsed.hostname != _HOST or parsed.port:
                raise IntegrationError("Foreign HackerOne report cursor", provider=PROVIDER)
            if parsed.path != "/v1/reports" or not parsed.query:
                raise IntegrationError("Out-of-scope HackerOne report cursor", provider=PROVIDER)
            query = parse_qsl(parsed.query, keep_blank_values=True)
            if any(key == "filter[program][]" and value not in handles for key, value in query):
                raise IntegrationError("Out-of-scope HackerOne report cursor", provider=PROVIDER)
            path = f"{parsed.path}?{parsed.query}"
            params = None
        raise IntegrationError("HackerOne report page limit exceeded", provider=PROVIDER)

    async def ping(self) -> bool:
        handles = self._scope()
        payload = await self._require().get_json(
            "/v1/reports",
            params=[("filter[program][]", handles[0]), ("page[size]", "1")],
            headers=self._headers(),
        )
        return isinstance(payload, dict) and isinstance(payload.get("data"), list)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["HackerOneClient", "PROVIDER"]
