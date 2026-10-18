"""Azure DevOps Work Item ticketing with project-scoped idempotency."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis


PROVIDER = "Azure DevOps"
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}\Z")
_WORK_ITEM_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,79}\Z")


@dataclass(frozen=True, slots=True)
class AzureDevOpsIssue:
    key: str
    id: str
    url: str
    status: str
    summary: str = ""


class AzureDevOpsClient:
    """Create Azure DevOps work items only in the configured organization/project."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._settings = settings
        self._cfg = settings.azure_devops
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set CYNUX_AZURE_DEVOPS__BASE_URL and CYNUX_AZURE_DEVOPS__API_TOKEN.",
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

    def _coordinates(self) -> tuple[str, str, str]:
        organization = str(getattr(self._cfg, "organization", "") or "").strip()
        project = str(getattr(self._cfg, "project", "") or "").strip()
        work_item_type = str(getattr(self._cfg, "work_item_type", "") or "").strip()
        if not _SEGMENT.fullmatch(organization) or not _SEGMENT.fullmatch(project):
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set safe CYNUX_AZURE_DEVOPS__ORGANIZATION and CYNUX_AZURE_DEVOPS__PROJECT values.",
            )
        if not _WORK_ITEM_TYPE.fullmatch(work_item_type):
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_AZURE_DEVOPS__WORK_ITEM_TYPE to a valid work item type."
            )
        return organization, project, work_item_type

    def _headers(self, *, patch: bool = False) -> dict[str, str]:
        token = base64.b64encode(f":{reveal(self._cfg.api_token)}".encode()).decode()
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        if patch:
            headers.update({"Content-Type": "application/json-patch+json", "X-HTTP-Method-Override": "PATCH"})
        return headers

    @staticmethod
    def _tag(finding_id: str) -> str:
        clean = re.sub(r"[^A-Za-z0-9_.-]", "-", str(finding_id)).strip("-")[:80]
        if not clean:
            raise IntegrationError("Invalid canonical finding identity", provider=PROVIDER)
        return f"cynux-finding-{clean}"

    def _path(self, suffix: str, *, api_version: str = "7.1") -> str:
        organization, project, _ = self._coordinates()
        return f"/{organization}/{project}/_apis/wit/{suffix}?api-version={api_version}"

    @staticmethod
    def _issue(payload: dict[str, Any]) -> AzureDevOpsIssue:
        identifier = payload.get("id")
        fields = payload.get("fields")
        if not isinstance(identifier, int) or identifier <= 0 or not isinstance(fields, dict):
            raise IntegrationError("Azure DevOps returned an invalid work item", provider=PROVIDER)
        return AzureDevOpsIssue(
            key=f"#{identifier}", id=str(identifier), url=str(payload.get("url") or ""),
            status=str(fields.get("System.State") or "unknown").strip().lower(),
            summary=str(fields.get("System.Title") or ""),
        )

    async def find_issue_for_finding(self, finding_id: str) -> AzureDevOpsIssue | None:
        tag = self._tag(finding_id)
        # ``tag`` is derived by _tag's strict allowlist, so it cannot terminate the
        # WIQL literal or add a predicate.
        query = "SELECT [System.Id] FROM WorkItems WHERE [System.Tags] CONTAINS '" + tag + "'"  # noqa: S608 - WIQL has no bind parameters; _tag restricts the literal alphabet.
        result = await self._require().post_json(
            self._path("wiql"), headers=self._headers(),
            json={"query": query},
        )
        work_items = result.get("workItems") if isinstance(result, dict) else None
        if not isinstance(work_items, list):
            raise IntegrationError("Azure DevOps returned an invalid WIQL response", provider=PROVIDER)
        if not work_items:
            return None
        work_id = work_items[0].get("id") if isinstance(work_items[0], dict) else None
        if not isinstance(work_id, int) or work_id <= 0:
            raise IntegrationError("Azure DevOps returned an invalid work item ID", provider=PROVIDER)
        return await self.get_issue(f"#{work_id}")

    async def create_issue(self, *, summary: str, description: str, finding_id: str, labels: list[str] | None = None) -> AzureDevOpsIssue:
        del labels
        existing = await self.find_issue_for_finding(finding_id)
        if existing is not None:
            return existing
        _, _, work_item_type = self._coordinates()
        tag = self._tag(finding_id)
        payload = await self._require().post_json(
            self._path(f"workitems/${work_item_type}"), headers=self._headers(patch=True),
            json=[
                {"op": "add", "path": "/fields/System.Title", "value": summary.strip()[:255]},
                {"op": "add", "path": "/fields/System.Description", "value": description[:60_000]},
                {"op": "add", "path": "/fields/System.Tags", "value": f"cynux;{tag}"},
            ],
            idempotency_key=tag,
        )
        if not isinstance(payload, dict):
            raise IntegrationError("Azure DevOps returned an invalid work item", provider=PROVIDER)
        return self._issue(payload)

    async def get_issue(self, key: str) -> AzureDevOpsIssue:
        raw_id = key.lstrip("#")
        if not raw_id.isdigit() or int(raw_id) <= 0:
            raise IntegrationError("Invalid Azure DevOps work item key", provider=PROVIDER)
        payload = await self._require().get_json(self._path(f"workitems/{int(raw_id)}"), headers=self._headers())
        if not isinstance(payload, dict):
            raise IntegrationError("Azure DevOps returned an invalid work item", provider=PROVIDER)
        return self._issue(payload)

    async def add_comment(self, key: str, text: str) -> None:
        """Append a remediation update using the work-item comments API."""
        raw_id = key.lstrip("#")
        if not raw_id.isdigit() or int(raw_id) <= 0:
            raise IntegrationError("Invalid Azure DevOps work item key", provider=PROVIDER)
        digest = hashlib.sha256(text[:60_000].encode("utf-8")).hexdigest()[:24]
        await self._require().post_json(
            self._path(f"workitems/{int(raw_id)}/comments", api_version="7.1-preview.4"),
            headers=self._headers(),
            json={"text": text[:60_000]},
            idempotency_key=f"cynux-comment-{raw_id}-{digest}",
        )

    async def set_issue_state(self, key: str, *, closed: bool) -> AzureDevOpsIssue:
        """Set the conventional work-item state with an auditable JSON Patch."""
        raw_id = key.lstrip("#")
        if not raw_id.isdigit() or int(raw_id) <= 0:
            raise IntegrationError("Invalid Azure DevOps work item key", provider=PROVIDER)
        payload = await self._require().patch_json(
            self._path(f"workitems/{int(raw_id)}"),
            headers=self._headers(patch=True),
            json=[
                {
                    "op": "add",
                    "path": "/fields/System.State",
                    "value": "Closed" if closed else "Active",
                }
            ],
        )
        if not isinstance(payload, dict):
            raise IntegrationError("Azure DevOps returned an invalid work item", provider=PROVIDER)
        return self._issue(payload)

    async def ping(self) -> bool:
        await self._require().get_json(self._path("workitemtypes"), headers=self._headers())
        return True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["AzureDevOpsClient", "AzureDevOpsIssue", "PROVIDER"]
