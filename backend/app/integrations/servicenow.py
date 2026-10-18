"""ServiceNow incident ticketing with correlation-safe idempotency."""

from __future__ import annotations

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


PROVIDER = "ServiceNow"
_TABLES = frozenset({"incident", "sn_si_incident"})
_SAFE_CORRELATION = re.compile(r"[^A-Za-z0-9_.-]")
_OPEN_STATES = frozenset({"-5", "-4", "-3", "-2", "-1", "0", "1", "2", "3"})
_CLOSED_STATES = frozenset({"6", "7"})


@dataclass(frozen=True, slots=True)
class ServiceNowIssue:
    key: str
    id: str
    url: str
    status: str
    summary: str = ""


class ServiceNowClient:
    """Create and refresh only incidents in the explicitly configured table.

    ``correlation_id`` is the durable provider-side idempotency key.  A retry first
    searches it, avoiding duplicate incidents even if the original HTTP response was
    lost after ServiceNow accepted the write.
    """

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self._settings = settings
        self._cfg = settings.servicenow
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_SERVICENOW__BASE_URL and CYNUX_SERVICENOW__API_TOKEN."
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

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {reveal(self._cfg.api_token)}", "Accept": "application/json"}

    def _table(self) -> str:
        table = str(getattr(self._cfg, "table", "") or "").strip()
        if table not in _TABLES:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set CYNUX_SERVICENOW__TABLE to incident or sn_si_incident.",
            )
        return table

    @staticmethod
    def _correlation_id(finding_id: str) -> str:
        value = _SAFE_CORRELATION.sub("-", str(finding_id)).strip("-")
        if not value:
            raise IntegrationError("Invalid canonical finding identity", provider=PROVIDER)
        return f"cynux-finding-{value[:80]}"

    def _url(self, table: str, payload: dict[str, Any]) -> str:
        remote_url = payload.get("sysparm_link") or payload.get("url")
        if isinstance(remote_url, str) and remote_url.startswith(("https://", "http://")):
            return remote_url
        sys_id = payload.get("sys_id")
        if not isinstance(sys_id, str) or not sys_id:
            return ""
        return f"{self._cfg.base_url.rstrip('/')}/nav_to.do?uri={table}.do?sys_id={sys_id}"

    @staticmethod
    def _status(payload: dict[str, Any]) -> str:
        state = str(payload.get("state") or "").strip()
        if state in _CLOSED_STATES:
            return "closed"
        if state in _OPEN_STATES:
            return "open"
        return state.lower() or "unknown"

    def _issue_from_payload(self, table: str, payload: dict[str, Any]) -> ServiceNowIssue:
        sys_id = payload.get("sys_id")
        number = payload.get("number")
        if not isinstance(sys_id, str) or not sys_id or not isinstance(number, str) or not number:
            raise IntegrationError("ServiceNow returned an invalid incident response", provider=PROVIDER)
        return ServiceNowIssue(
            key=number,
            id=sys_id,
            url=self._url(table, payload),
            status=self._status(payload),
            summary=str(payload.get("short_description") or ""),
        )

    @staticmethod
    def _result_list(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict) or not isinstance(payload.get("result"), list):
            raise IntegrationError("ServiceNow returned an invalid incident search response", provider=PROVIDER)
        result = payload["result"]
        if any(not isinstance(item, dict) for item in result):
            raise IntegrationError("ServiceNow returned an invalid incident search response", provider=PROVIDER)
        return result

    async def find_issue_for_finding(self, finding_id: str) -> ServiceNowIssue | None:
        table = self._table()
        result = self._result_list(
            await self._require().get_json(
                f"/api/now/table/{table}",
                headers=self._headers(),
                params={
                    "sysparm_query": f"correlation_id={self._correlation_id(finding_id)}",
                    "sysparm_limit": 1,
                },
            )
        )
        return self._issue_from_payload(table, result[0]) if result else None

    async def create_issue(
        self,
        *,
        summary: str,
        description: str,
        finding_id: str,
        labels: list[str] | None = None,
    ) -> ServiceNowIssue:
        del labels  # ServiceNow incidents have no portable labels field.
        table = self._table()
        existing = await self.find_issue_for_finding(finding_id)
        if existing is not None:
            return existing
        body: dict[str, str] = {
            "short_description": summary.strip()[:160],
            "description": description[:65_000],
            "correlation_id": self._correlation_id(finding_id),
        }
        assignment_group = str(getattr(self._cfg, "assignment_group", "") or "").strip()
        if assignment_group:
            body["assignment_group"] = assignment_group[:160]
        payload = await self._require().post_json(
            f"/api/now/table/{table}", headers=self._headers(), json=body
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("result"), dict):
            raise IntegrationError("ServiceNow returned an invalid incident response", provider=PROVIDER)
        return self._issue_from_payload(table, payload["result"])

    async def get_issue(self, key: str) -> ServiceNowIssue:
        table = self._table()
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,79}", key):
            raise IntegrationError("Invalid ServiceNow incident key", provider=PROVIDER)
        payload = await self._require().get_json(
            f"/api/now/table/{table}",
            headers=self._headers(),
            params={"sysparm_query": f"number={key}", "sysparm_limit": 1},
        )
        result = self._result_list(payload)
        if not result:
            raise IntegrationError("ServiceNow incident was not found", provider=PROVIDER)
        return self._issue_from_payload(table, result[0])

    async def add_comment(self, key: str, text: str) -> None:
        """Append an operator-visible work note to the linked incident."""
        issue = await self.get_issue(key)
        table = self._table()
        digest = hashlib.sha256(text[:65_000].encode("utf-8")).hexdigest()[:24]
        await self._require().patch_json(
            f"/api/now/table/{table}/{issue.id}",
            headers=self._headers(),
            json={"work_notes": text[:65_000]},
            idempotency_key=f"cynux-comment-{issue.id}-{digest}",
        )

    async def set_issue_state(self, key: str, *, closed: bool) -> ServiceNowIssue:
        """Close or reopen the exact incident previously linked by its number."""
        issue = await self.get_issue(key)
        table = self._table()
        payload = await self._require().patch_json(
            f"/api/now/table/{table}/{issue.id}",
            headers=self._headers(),
            json={"state": "6" if closed else "2"},
        )
        result = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(result, dict):
            raise IntegrationError("ServiceNow returned an invalid incident", provider=PROVIDER)
        return self._issue_from_payload(table, result)

    async def ping(self) -> bool:
        await self._require().get_json("/api/now/table/sys_user", headers=self._headers(), params={"sysparm_limit": 1})
        return True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["PROVIDER", "ServiceNowClient", "ServiceNowIssue"]
