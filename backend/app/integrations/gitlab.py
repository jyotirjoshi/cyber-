"""Read-only GitLab project security-finding ingestion."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "GitLab"
_PAGE_SIZE = 100
_MAX_PAGES = 100
_PROJECT_RE = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?\Z")


@dataclass(frozen=True, slots=True)
class GitLabAlertFeed:
    project: str
    alerts: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class GitLabIssue:
    key: str
    id: str
    url: str
    status: str
    summary: str = ""


class GitLabClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._cfg = settings.gitlab
        self._settings = settings
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Set CYNUX_GITLAB__API_TOKEN.")
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url.rstrip("/"),
                settings=self._settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": reveal(self._cfg.api_token)}

    def _issue_project(self) -> str:
        project = str(getattr(self._cfg, "issue_project", "") or "").strip()
        if not _PROJECT_RE.fullmatch(project):
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set CYNUX_GITLAB__ISSUE_PROJECT to a safe project path or ID for issue filing.",
            )
        return project

    @staticmethod
    def _finding_label(finding_id: str) -> str:
        return f"cynux-finding-{re.sub(r'[^A-Za-z0-9_.-]', '-', str(finding_id))[:80]}"

    @staticmethod
    def _issue_from_payload(payload: dict[str, Any]) -> GitLabIssue:
        iid = payload.get("iid")
        if not isinstance(iid, int) or iid <= 0:
            raise IntegrationError("GitLab returned an invalid issue IID", provider=PROVIDER)
        return GitLabIssue(
            key=f"#{iid}",
            id=str(payload.get("id") or iid),
            url=str(payload.get("web_url") or ""),
            status=str(payload.get("state") or ""),
            summary=str(payload.get("title") or ""),
        )

    async def find_issue_for_finding(self, finding_id: str) -> GitLabIssue | None:
        project = self._issue_project()
        payload = await self._require().get_json(
            f"/projects/{quote(project, safe='')}/issues",
            headers=self._headers(),
            params={"scope": "all", "state": "all", "labels": self._finding_label(finding_id), "per_page": 1},
        )
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise IntegrationError("GitLab returned an invalid issue search response", provider=PROVIDER)
        return self._issue_from_payload(payload[0]) if payload else None

    async def create_issue(
        self,
        *,
        summary: str,
        description: str,
        finding_id: str,
        labels: list[str] | None = None,
    ) -> GitLabIssue:
        """Create one labeled GitLab issue, safely returning an existing match on retry."""
        project = self._issue_project()
        existing = await self.find_issue_for_finding(finding_id)
        if existing is not None:
            return existing
        issue_labels = sorted({"cynux", self._finding_label(finding_id), *(labels or [])})
        payload = await self._require().post_json(
            f"/projects/{quote(project, safe='')}/issues",
            headers=self._headers(),
            json={
                "title": summary.strip()[:255],
                "description": description[:1_000_000],
                "labels": ",".join(issue_labels),
            },
        )
        if not isinstance(payload, dict):
            raise IntegrationError("GitLab returned an invalid issue response", provider=PROVIDER)
        return self._issue_from_payload(payload)

    async def get_issue(self, key: str) -> GitLabIssue:
        project = self._issue_project()
        iid = key.lstrip("#")
        if not iid.isdigit() or int(iid) <= 0:
            raise IntegrationError("Invalid GitLab issue key", provider=PROVIDER)
        payload = await self._require().get_json(
            f"/projects/{quote(project, safe='')}/issues/{int(iid)}", headers=self._headers()
        )
        if not isinstance(payload, dict):
            raise IntegrationError("GitLab returned an invalid issue response", provider=PROVIDER)
        return self._issue_from_payload(payload)

    async def add_comment(self, key: str, text: str) -> None:
        """Append a bounded Cynux remediation update to a GitLab issue."""
        project = self._issue_project()
        iid = key.lstrip("#")
        if not iid.isdigit() or int(iid) <= 0:
            raise IntegrationError("Invalid GitLab issue key", provider=PROVIDER)
        await self._require().post_json(
            f"/projects/{quote(project, safe='')}/issues/{int(iid)}/notes",
            headers=self._headers(),
            json={"body": text[:1_000_000]},
        )

    async def ping(self) -> bool:
        await self._require().get_json("/user", headers=self._headers())
        return True

    async def list_security_alerts(self) -> list[GitLabAlertFeed]:
        if not self._cfg.project_ids:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Configure at least one GitLab project ID or path."
            )
        client = self._require()
        headers = self._headers()
        feeds = []
        for project in self._cfg.project_ids:
            path = f"/projects/{quote(project, safe='')}/vulnerability_findings"
            alerts: list[dict[str, Any]] = []
            for page in range(1, _MAX_PAGES + 1):
                payload = await client.get_json(
                    path,
                    headers=headers,
                    params={"scope": "all", "per_page": _PAGE_SIZE, "page": page},
                )
                if not isinstance(payload, list) or any(
                    not isinstance(item, dict) for item in payload
                ):
                    raise IntegrationError(
                        "GitLab returned an invalid finding page", provider=PROVIDER
                    )
                alerts.extend(payload)
                if len(payload) < _PAGE_SIZE:
                    break
            else:
                raise IntegrationError("GitLab finding page limit exceeded", provider=PROVIDER)
            feeds.append(GitLabAlertFeed(project=project, alerts=alerts))
        return feeds


__all__ = ["GitLabAlertFeed", "GitLabClient", "GitLabIssue", "PROVIDER"]
