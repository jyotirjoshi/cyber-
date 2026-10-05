"""GitHub organization security-alert ingestion and explicit source actions."""

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


PROVIDER = "GitHub"
_API_VERSION = "2022-11-28"
_SECURITY_FEEDS = ("dependabot", "code_scanning", "secret_scanning")
_PAGE_SIZE = 100
_MAX_PAGES = 100
_REPOSITORY_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
_DISMISS_REASONS = {
    "dependabot": frozenset({"fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk"}),
    "code_scanning": frozenset({"false positive", "won't fix", "used in tests", "mitigated"}),
    "secret_scanning": frozenset({"false_positive", "wont_fix", "revoked", "used_in_tests"}),
}


@dataclass(frozen=True, slots=True)
class GitHubAlertFeed:
    kind: str
    alerts: list[dict[str, Any]]


class GitHubClient:
    """Retrieve and explicitly update organization security alerts."""

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.github
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_GITHUB__API_TOKEN."
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url.rstrip("/"),
                settings=self.settings,
                redis=self._redis,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {reveal(self._cfg.api_token)}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
        }

    def _organization(self) -> str:
        organization = (self._cfg.organization or "").strip()
        if not organization:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_GITHUB__ORGANIZATION to ingest organization alerts."
            )
        return organization

    async def ping(self) -> bool:
        await self._require().get_json("/user", headers=self._headers())
        return True

    async def list_security_alerts(self) -> list[GitHubAlertFeed]:
        """Return Dependabot, code-scanning, and secret-scanning alerts separately.

        A missing feed is not converted to an empty list: provider errors remain typed
        so a partial source outage cannot masquerade as a clean organization.
        """
        organization = self._organization()
        client = self._require()
        headers = self._headers()
        feeds: list[GitHubAlertFeed] = []
        for kind in _SECURITY_FEEDS:
            path = f"/orgs/{organization}/{kind.replace('_', '-')}/alerts"
            alerts: list[dict[str, Any]] = []
            for page in range(1, _MAX_PAGES + 1):
                payload = await client.get_json(
                    path,
                    headers=headers,
                    params={"per_page": _PAGE_SIZE, "page": page},
                )
                if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
                    raise IntegrationError("GitHub returned an invalid alert page", provider=PROVIDER)
                alerts.extend(payload)
                if len(payload) < _PAGE_SIZE:
                    break
            else:
                raise IntegrationError("GitHub alert page limit exceeded", provider=PROVIDER)
            feeds.append(GitHubAlertFeed(kind=kind, alerts=alerts))
        return feeds

    async def set_alert_state(
        self, category: str, repository: str, number: int, *,
        decision: str, reason: str | None = None, comment: str | None = None,
    ) -> str:
        """Update one alert using the feed-specific GitHub state and reason contract."""
        organization = self._organization()
        parts = repository.split("/")
        if (len(parts) != 2 or parts[0].lower() != organization.lower()
                or any(part in {".", ".."} or not _REPOSITORY_SEGMENT.fullmatch(part) for part in parts)
                or not isinstance(number, int) or isinstance(number, bool) or number <= 0):
            raise IntegrationError("Invalid or foreign GitHub alert identity", provider=PROVIDER)
        if category not in _DISMISS_REASONS or decision not in {"dismiss", "reopen"}:
            raise IntegrationError("Unsupported GitHub alert action", provider=PROVIDER)
        if decision == "reopen":
            if reason is not None or comment is not None:
                raise IntegrationError("Reopening does not accept a dismissal reason", provider=PROVIDER)
            expected_state = "open"
            body = {"state": expected_state}
        else:
            if reason not in _DISMISS_REASONS[category] or not isinstance(comment, str) or not 1 <= len(comment.strip()) <= 2000:
                raise IntegrationError("Invalid GitHub alert dismissal reason or comment", provider=PROVIDER)
            expected_state = "resolved" if category == "secret_scanning" else "dismissed"
            reason_key = "resolution" if category == "secret_scanning" else "dismissed_reason"
            comment_key = "resolution_comment" if category == "secret_scanning" else "dismissed_comment"
            body = {"state": expected_state, reason_key: reason, comment_key: comment.strip()}
        path = f"/repos/{parts[0]}/{parts[1]}/{category.replace('_', '-')}/alerts/{number}"
        payload = await self._require().patch_json(path, json=body, headers=self._headers())
        if not isinstance(payload, dict) or payload.get("number") != number or payload.get("state") != expected_state:
            raise IntegrationError("GitHub did not confirm alert status", provider=PROVIDER)
        return expected_state

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["GitHubAlertFeed", "GitHubClient", "PROVIDER"]
