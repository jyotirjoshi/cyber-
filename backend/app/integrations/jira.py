"""Jira Cloud issue creation (FR-027).

One finding becomes at most one Jira issue, and keeping that true is the whole difficulty.
Three mechanisms stack up, because none alone is sufficient:

1.  An ``Idempotency-Key`` derived from the finding id, so the HTTP spine is permitted to
    retry the ``POST``.  Jira Cloud does not honour the header, so this is what makes the
    retry *allowed*, not what makes it *safe*.
2.  A JQL pre-check for an existing issue carrying the finding's Cynux label.  This catches
    the case where the first attempt actually succeeded and the response was lost.
3.  The unique constraint on ``ticket_links``, which is the only guarantee that survives two
    workers racing.  The service layer relies on it; this client just makes the first two
    cheap enough that the constraint rarely fires.

The Cynux label -- :func:`finding_label` -- is what ties the three together.  It is written
onto every issue Cynux files so the JQL check has something exact to match on; matching on
summary text would break the moment someone edits the title.

Jira Cloud v3 takes descriptions as Atlassian Document Format rather than text, so
:func:`to_adf` converts plain text with a deliberately small subset of structure. Building a
full Markdown-to-ADF converter would be a project of its own and the PRD scopes ticket bodies
as summaries with links back to Cynux.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.db.enums import Priority, Severity
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "Jira"

#: Label prefix Cynux stamps on every issue it files. Also the JQL search key.
LABEL_PREFIX = "cynux-finding"

#: Jira rejects labels containing whitespace and silently mangles some punctuation, so the
#: label is restricted to a conservative character set.
_LABEL_SAFE_RE = re.compile(r"[^A-Za-z0-9_.\-]")

#: Cynux priority to a Jira priority name. Jira instances rename these freely, so a failure
#: to set priority is tolerated (see :meth:`JiraClient.create_issue`) rather than fatal --
#: refusing to file a ticket because a priority scheme was customized would be absurd.
PRIORITY_NAMES: dict[Priority, str] = {
    Priority.P1: "Highest",
    Priority.P2: "High",
    Priority.P3: "Medium",
    Priority.P4: "Low",
    Priority.P5: "Lowest",
}

SEVERITY_PRIORITY: dict[Severity, Priority] = {
    Severity.CRITICAL: Priority.P1,
    Severity.HIGH: Priority.P2,
    Severity.MEDIUM: Priority.P3,
    Severity.LOW: Priority.P4,
    Severity.INFO: Priority.P5,
}


def finding_label(finding_id: str) -> str:
    """The label identifying the Cynux finding an issue was filed for."""
    safe = _LABEL_SAFE_RE.sub("-", str(finding_id))[:80]
    return f"{LABEL_PREFIX}-{safe}"


@dataclass(frozen=True, slots=True)
class JiraIssue:
    key: str
    id: str
    url: str
    summary: str = ""
    status: str = ""
    assignee: str | None = None
    priority: str | None = None
    labels: list[str] = field(default_factory=list)


def to_adf(text: str) -> dict[str, Any]:
    """Convert plain text to Atlassian Document Format.

    Blank-line-separated blocks become paragraphs; lines starting with ``- `` or ``* ``
    become bullet list items. Nothing else is interpreted -- in particular no inline
    formatting -- because a partial Markdown parser produces subtly wrong documents and the
    reader cannot tell whether the odd rendering is Cynux's fault or the finding's content.
    """
    content: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n", (text or "").strip()):
        block = block.strip()
        if not block:
            continue
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if lines and all(line.startswith(("- ", "* ")) for line in lines):
            content.append(
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": line[2:].strip()}],
                                }
                            ],
                        }
                        for line in lines
                    ],
                }
            )
        else:
            content.append(
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": " ".join(lines)}],
                }
            )
    if not content:
        #: ADF rejects an empty document, and Jira's error for it is opaque.
        content = [{"type": "paragraph", "content": [{"type": "text", "text": "(no detail)"}]}]
    return {"type": "doc", "version": 1, "content": content}


def _parse_issue(payload: dict[str, Any], *, base_url: str) -> JiraIssue:
    fields = payload.get("fields") or {}
    assignee = fields.get("assignee") or {}
    priority = fields.get("priority") or {}
    status = fields.get("status") or {}
    key = str(payload.get("key") or "")
    return JiraIssue(
        key=key,
        id=str(payload.get("id") or ""),
        #: The browse URL, not the REST ``self`` link. This is what goes in a Slack message
        #: and on the findings screen, and a human clicking a REST URL gets raw JSON.
        url=f"{base_url.rstrip('/')}/browse/{key}" if key else "",
        summary=str(fields.get("summary") or ""),
        status=str(status.get("name") or ""),
        assignee=(assignee.get("displayName") or assignee.get("emailAddress")),
        priority=priority.get("name"),
        labels=[str(label) for label in fields.get("labels") or []],
    )


class JiraClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.jira
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return bool(self._cfg.configured)

    @property
    def project_key(self) -> str:
        return self._cfg.project_key or ""

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint=(
                    "Set CYNUX_JIRA__BASE_URL, CYNUX_JIRA__USER_EMAIL, "
                    "CYNUX_JIRA__API_TOKEN and CYNUX_JIRA__PROJECT_KEY."
                ),
            )
        if self._client is None:
            #: Jira Cloud uses HTTP Basic with the account email as the username and an API
            #: token as the password. Not Bearer -- Bearer is for OAuth apps.
            raw = f"{self._cfg.user_email}:{reveal(self._cfg.api_token)}".encode()
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url or "",
                settings=self.settings,
                redis=self._redis,
                headers={
                    "Authorization": f"Basic {base64.b64encode(raw).decode()}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=float(self._cfg.timeout_seconds),
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=5, cooldown_seconds=120),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- search --------------------------------------------------------------

    async def search(self, jql: str, *, max_results: int = 20) -> list[JiraIssue]:
        payload = await self._require().post_json(
            "/rest/api/3/search",
            json={
                "jql": jql,
                "maxResults": max(1, min(max_results, 100)),
                "fields": ["summary", "status", "assignee", "priority", "labels"],
            },
        )
        base = self._cfg.base_url or ""
        return [_parse_issue(issue, base_url=base) for issue in (payload or {}).get("issues") or []]

    async def find_for_finding(self, finding_id: str) -> JiraIssue | None:
        """Look for an issue Cynux already filed for this finding.

        Deliberately swallows failures: this is a duplicate-avoidance optimization, and a
        Jira search outage must not block filing the ticket. Worst case we file a second
        issue, which the ``ticket_links`` unique constraint then prevents from being
        recorded twice.
        """
        label = finding_label(finding_id)
        try:
            issues = await self.search(
                f'project = "{self.project_key}" AND labels = "{label}" ORDER BY created DESC',
                max_results=1,
            )
        except IntegrationError as exc:
            logger.warning("jira.duplicate_check_failed", error=exc.code)
            return None
        return issues[0] if issues else None

    # -- create --------------------------------------------------------------

    async def create_issue(
        self,
        *,
        summary: str,
        description: str,
        finding_id: str | None = None,
        priority: Priority | None = None,
        labels: list[str] | None = None,
        issue_type: str | None = None,
        assignee_account_id: str | None = None,
        components: list[str] | None = None,
    ) -> JiraIssue:
        """File an issue.

        When ``finding_id`` is supplied the client checks for an existing issue first and
        returns it rather than filing a duplicate, and stamps the finding label so the next
        check will find it.
        """
        client = self._require()

        if finding_id:
            existing = await self.find_for_finding(finding_id)
            if existing is not None:
                logger.info("jira.issue_exists", finding_id=finding_id, issue_key=existing.key)
                return existing

        all_labels = ["cynux", *(labels or [])]
        if finding_id:
            all_labels.append(finding_label(finding_id))

        fields: dict[str, Any] = {
            "project": {"key": self.project_key},
            #: Jira truncates summaries over 255 characters server-side, which produces a
            #: mid-word cut. Trimming here keeps the ellipsis intentional.
            "summary": (summary[:252] + "...") if len(summary) > 255 else summary,
            "description": to_adf(description),
            "issuetype": {"name": issue_type or self._cfg.issue_type},
            "labels": sorted(set(all_labels)),
        }
        if priority is not None:
            fields["priority"] = {"name": PRIORITY_NAMES[priority]}
        if assignee_account_id:
            fields["assignee"] = {"accountId": assignee_account_id}
        if components:
            fields["components"] = [{"name": name} for name in components]

        try:
            payload = await client.post_json(
                "/rest/api/3/issue",
                json={"fields": fields},
                #: Makes the POST retryable in the spine. See the module docstring: this is
                #: necessary but not sufficient, which is why the JQL pre-check exists.
                idempotency_key=f"cynux-finding-{finding_id}" if finding_id else None,
            )
        except IntegrationError:
            if "priority" not in fields and "components" not in fields:
                raise
            #: Priority schemes and component lists are per-project configuration Cynux
            #: cannot know. Rather than fail the whole ticket, retry without the fields a
            #: customized project is likely to reject, and record that we did.
            logger.warning(
                "jira.retrying_without_optional_fields",
                finding_id=finding_id,
                dropped=sorted({"priority", "components"} & set(fields)),
            )
            fields.pop("priority", None)
            fields.pop("components", None)
            payload = await client.post_json(
                "/rest/api/3/issue",
                json={"fields": fields},
                idempotency_key=f"cynux-finding-{finding_id}-retry" if finding_id else None,
            )

        if not payload or not payload.get("key"):
            raise IntegrationError(
                "Jira accepted the request but returned no issue key.",
                provider=PROVIDER,
                context={"finding_id": finding_id},
            )
        issue = _parse_issue(
            {"key": payload["key"], "id": payload.get("id"), "fields": fields},
            base_url=self._cfg.base_url or "",
        )
        logger.info("jira.issue_created", issue_key=issue.key, finding_id=finding_id)
        return issue

    # -- read / update -------------------------------------------------------

    async def get_issue(self, key: str) -> JiraIssue:
        payload = await self._require().get_json(
            f"/rest/api/3/issue/{key}",
            params={"fields": "summary,status,assignee,priority,labels"},
        )
        if not payload:
            raise IntegrationError(
                f"Jira returned no body for issue {key}.",
                provider=PROVIDER,
                context={"issue_key": key},
            )
        return _parse_issue(payload, base_url=self._cfg.base_url or "")

    async def add_comment(self, key: str, text: str) -> None:
        await self._require().post_json(
            f"/rest/api/3/issue/{key}/comment", json={"body": to_adf(text)}
        )

    async def ping(self) -> bool:
        """Verify credentials and that the configured project exists.

        Checking the project too, not just ``/myself``: a valid token against a project key
        that does not exist fails only at the first real ticket, which is the worst moment
        to discover it.
        """
        await self._require().get_json("/rest/api/3/myself")
        await self._require().get_json(f"/rest/api/3/project/{self.project_key}")
        return True


__all__ = [
    "LABEL_PREFIX",
    "PRIORITY_NAMES",
    "PROVIDER",
    "SEVERITY_PRIORITY",
    "JiraClient",
    "JiraIssue",
    "finding_label",
    "to_adf",
]
