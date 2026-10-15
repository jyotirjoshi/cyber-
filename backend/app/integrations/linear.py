"""Linear GraphQL issue connector."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Linear"


@dataclass(frozen=True, slots=True)
class LinearIssue:
    key: str
    id: str
    url: str
    status: str
    summary: str = ""


class LinearClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._settings, self._cfg, self._redis, self._client = (
            settings,
            settings.linear,
            redis,
            None,
        )

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_LINEAR__API_TOKEN and CYNUX_LINEAR__TEAM_ID."
            )
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

    def _team(self) -> str:
        value = str(getattr(self._cfg, "team_id", "") or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", value):
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_LINEAR__TEAM_ID to a team UUID."
            )
        return value

    def _headers(self) -> dict[str, str]:
        return {"Authorization": reveal(self._cfg.api_token), "Content-Type": "application/json"}

    @staticmethod
    def _marker(finding_id: str) -> str:
        clean = re.sub(r"[^A-Za-z0-9_.-]", "-", str(finding_id)).strip("-")[:80]
        if not clean:
            raise IntegrationError("Invalid canonical finding identity", provider=PROVIDER)
        return f"<!-- cynux-finding-{clean} -->"

    @staticmethod
    def _issue(payload: Any) -> LinearIssue:
        if not isinstance(payload, dict):
            raise IntegrationError("Linear returned an invalid issue", provider=PROVIDER)
        identifier, issue_id = payload.get("identifier"), payload.get("id")
        if not isinstance(identifier, str) or not isinstance(issue_id, str):
            raise IntegrationError("Linear returned an invalid issue", provider=PROVIDER)
        state = payload.get("state") or {}
        return LinearIssue(
            identifier,
            issue_id,
            str(payload.get("url") or ""),
            str(state.get("name") or "unknown").lower(),
            str(payload.get("title") or ""),
        )

    async def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        payload = await self._require().post_json(
            "", headers=self._headers(), json={"query": query, "variables": variables}
        )
        if (
            not isinstance(payload, dict)
            or payload.get("errors")
            or not isinstance(payload.get("data"), dict)
        ):
            raise IntegrationError("Linear GraphQL request failed", provider=PROVIDER)
        return payload["data"]

    async def find_issue_for_finding(self, finding_id: str) -> LinearIssue | None:
        data = await self._graphql(
            "query FindCynuxIssue($teamId: String!, $marker: String!) { issues(filter: { team: { id: { eq: $teamId } }, description: { contains: $marker } }, first: 1) { nodes { id identifier url title state { name } } } }",
            {"teamId": self._team(), "marker": self._marker(finding_id)},
        )
        nodes = data.get("issues", {}).get("nodes", [])
        return self._issue(nodes[0]) if nodes else None

    async def create_issue(
        self, *, summary: str, description: str, finding_id: str, labels: list[str] | None = None
    ) -> LinearIssue:
        del labels
        existing = await self.find_issue_for_finding(finding_id)
        if existing:
            return existing
        data = await self._graphql(
            "mutation CreateCynuxIssue($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url title state { name } } } }",
            {
                "input": {
                    "teamId": self._team(),
                    "title": summary.strip()[:255],
                    "description": f"{description[:60000]}\n\n{self._marker(finding_id)}",
                }
            },
        )
        result = data.get("issueCreate") or {}
        if result.get("success") is not True:
            raise IntegrationError("Linear did not create the issue", provider=PROVIDER)
        return self._issue(result.get("issue"))

    async def get_issue(self, key: str) -> LinearIssue:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}-[1-9][0-9]*", key):
            raise IntegrationError("Invalid Linear issue identifier", provider=PROVIDER)
        data = await self._graphql(
            "query CynuxIssue($query: String!) { issueSearch(query: $query, first: 10) { nodes { id identifier url title state { name } } } }",
            {"query": key},
        )
        nodes = data.get("issueSearch", {}).get("nodes", [])
        if not isinstance(nodes, list):
            raise IntegrationError("Linear returned an invalid issue search", provider=PROVIDER)
        for node in nodes:
            issue = self._issue(node)
            if issue.key == key:
                return issue
        raise IntegrationError("Linear issue was not found", provider=PROVIDER, retryable=False)

    async def add_comment(self, key: str, text: str) -> None:
        """Append a remediation update to the issue identified by its stable key."""
        issue = await self.get_issue(key)
        data = await self._graphql(
            "mutation CreateCynuxComment($input: CommentCreateInput!) { commentCreate(input: $input) { success } }",
            {"input": {"issueId": issue.id, "body": text[:60_000]}},
        )
        result = data.get("commentCreate") or {}
        if result.get("success") is not True:
            raise IntegrationError("Linear did not create the comment", provider=PROVIDER)

    async def ping(self) -> bool:
        await self._graphql("query CynuxViewer { viewer { id } }", {})
        return True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["LinearClient", "LinearIssue", "PROVIDER"]
