"""Read-only Wiz Issues connector using its service-account GraphQL API."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import (
    IntegrationAuthError,
    IntegrationError,
    IntegrationNotConfiguredError,
    IntegrationTimeoutError,
)
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Wiz"
_REGION = re.compile(r"\A[a-z][a-z0-9-]{1,23}\Z")
_MAX_PROJECTS = 100
_PAGE_SIZE = 100
_MAX_ISSUES = 10_000
_MAX_PAGES = 1000
_MAX_SYNC_SECONDS = 300

_ISSUES_QUERY = """
query CynuxIssues($after: String, $first: Int!, $filterBy: IssueFilters) {
  issues: issuesV2(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      severity
      status
      entitySnapshot { externalId }
      sourceRule {
        ... on Control { id name }
        ... on CloudEventRule { id name }
        ... on CloudConfigurationRule { id name }
      }
      projects { id }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class WizClient:
    """Fetch bounded issue pages; never changes a Wiz project, issue, or policy."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.wiz
        self._redis = redis
        self._auth: ResilientClient | None = None
        self._api: ResilientClient | None = None
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _require_scope(self) -> list[str]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set Wiz region, client_id, client_secret, and selected project_ids.",
            )
        region = self._cfg.region or ""
        project_ids = list(self._cfg.project_ids)
        if (
            _REGION.fullmatch(region) is None
            or not 1 <= len(project_ids) <= _MAX_PROJECTS
            or any(
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item)
                for item in project_ids
            )
            or len(set(project_ids)) != len(project_ids)
        ):
            raise IntegrationError("Invalid Wiz region or project scope.", provider=PROVIDER)
        return project_ids

    def _auth_client(self) -> ResilientClient:
        self._require_scope()
        if self._auth is None:
            self._auth = build_client(
                provider=PROVIDER,
                base_url="https://auth.app.wiz.io",
                settings=self.settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
            )
        return self._auth

    def _api_client(self) -> ResilientClient:
        region = self._cfg.region or ""
        self._require_scope()
        if self._api is None:
            self._api = build_client(
                provider=PROVIDER,
                base_url=f"https://api.{region}.app.wiz.io",
                settings=self.settings,
                redis=self._redis,
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
            )
        return self._api

    async def _access_token(self) -> str:
        if self._token is not None and time.monotonic() < self._token_expires_at:
            return self._token
        payload = await self._auth_client().post_json(
            "/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": reveal(self._cfg.client_id),
                "client_secret": reveal(self._cfg.client_secret),
                "audience": "wiz-api",
            },
        )
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 8192
            or any(character.isspace() or ord(character) < 32 for character in token)
        ):
            raise IntegrationError("Wiz did not return a usable access token.", provider=PROVIDER)
        expires_in = payload.get("expires_in", 300)
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, int | float)
            or not 0 < expires_in <= 86400
        ):
            raise IntegrationError("Wiz returned an invalid token expiry.", provider=PROVIDER)
        self._token = token
        self._token_expires_at = time.monotonic() + max(0, expires_in - 30)
        return token

    async def _page(self, after: str | None, first: int) -> tuple[list[dict[str, Any]], str | None]:
        project_ids = self._require_scope()
        payload: Any = None
        for attempt in range(2):
            token = await self._access_token()
            try:
                payload = await self._api_client().post_json(
                    "/graphql",
                    json={
                        "query": _ISSUES_QUERY,
                        "variables": {
                            "after": after,
                            "first": first,
                            "filterBy": {
                                "project": project_ids,
                                "status": ["OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"],
                            },
                        },
                    },
                    headers={"Authorization": f"Bearer {token}"},
                    # Queries are repeatable; authorize transport retries for this POST.
                    idempotency_key=str(uuid.uuid4()),
                )
                break
            except IntegrationAuthError as exc:
                if attempt or exc.context.get("status") != 401:
                    raise
                self._token = None
        if not isinstance(payload, dict) or payload.get("errors"):
            raise IntegrationError("Wiz rejected the Issues query.", provider=PROVIDER)
        data = payload.get("data")
        issues = data.get("issues") if isinstance(data, dict) else None
        nodes = issues.get("nodes") if isinstance(issues, dict) else None
        page_info = issues.get("pageInfo") if isinstance(issues, dict) else None
        if (
            not isinstance(nodes, list)
            or len(nodes) > first
            or any(not isinstance(item, dict) for item in nodes)
            or not isinstance(page_info, dict)
            or not isinstance(page_info.get("hasNextPage"), bool)
        ):
            raise IntegrationError("Wiz returned an incomplete Issues page.", provider=PROVIDER)
        cursor = page_info.get("endCursor") if page_info["hasNextPage"] else None
        if page_info["hasNextPage"] and (
            not nodes or not isinstance(cursor, str) or not cursor or len(cursor) > 4096
        ):
            raise IntegrationError("Wiz pagination cursor is invalid.", provider=PROVIDER)
        return nodes, cursor

    async def _list_issues(self) -> list[dict[str, Any]]:
        allowed_projects = set(self._require_scope())
        records: list[dict[str, Any]] = []
        after: str | None = None
        seen_cursors: set[str] = set()
        seen_ids: set[str] = set()
        for _ in range(_MAX_PAGES):
            nodes, next_cursor = await self._page(after, _PAGE_SIZE)
            for issue in nodes:
                issue_id = issue.get("id")
                if not isinstance(issue_id, str) or not issue_id or issue_id in seen_ids:
                    raise IntegrationError("Wiz returned an invalid or repeated issue ID.", provider=PROVIDER)
                seen_ids.add(issue_id)
                projects = issue.get("projects")
                if not isinstance(projects, list) or any(
                    not isinstance(item, dict) or not isinstance(item.get("id"), str)
                    for item in projects
                ):
                    raise IntegrationError("Wiz omitted issue project membership.", provider=PROVIDER)
                matched = sorted({item["id"] for item in projects} & allowed_projects)
                if not matched:
                    raise IntegrationError("Wiz returned an issue outside the selected projects.", provider=PROVIDER)
                records.append({**issue, "_cynux_project_id": matched[0], "_cynux_project_ids": matched})
                if len(records) > _MAX_ISSUES:
                    raise IntegrationError("Wiz issue limit exceeded for selected projects.", provider=PROVIDER)
            if next_cursor is None:
                return records
            if next_cursor in seen_cursors:
                raise IntegrationError("Wiz returned a repeated pagination cursor.", provider=PROVIDER)
            seen_cursors.add(next_cursor)
            after = next_cursor
        raise IntegrationError("Wiz page limit exceeded; narrow the project scope.", provider=PROVIDER)

    async def list_issues(self) -> list[dict[str, Any]]:
        """Return a complete bounded pull; incomplete pulls never reach persistence."""
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await self._list_issues()
        except TimeoutError as exc:
            raise IntegrationTimeoutError("Wiz sync timed out; narrow the project scope.", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await self._page(None, 1)
        return True

    async def aclose(self) -> None:
        self._token = None
        self._token_expires_at = 0.0
        if self._auth is not None:
            await self._auth.aclose()
            self._auth = None
        if self._api is not None:
            await self._api.aclose()
            self._api = None


__all__ = ["WizClient", "PROVIDER"]
