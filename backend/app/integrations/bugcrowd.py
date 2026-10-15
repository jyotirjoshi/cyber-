"""Read-only Bugcrowd submissions connector with bounded engagement pagination."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Bugcrowd"
_HOST = "api.bugcrowd.com"
_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}")
_MAX_PAGES = 500
_MAX_SUBMISSIONS = 50_000


class BugcrowdClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings, self._cfg, self._redis = settings, settings.bugcrowd, redis
        self._client: ResilientClient | None = None

    def _scope(self) -> tuple[str, ...]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(PROVIDER, hint="Set token credentials and engagement codes.")
        parsed = urlsplit(self._cfg.base_url)
        if parsed.scheme != "https" or parsed.hostname != _HOST or parsed.path not in {"", "/"} or parsed.port or parsed.username or parsed.password:
            raise IntegrationError("Unsupported Bugcrowd API host", provider=PROVIDER)
        codes = tuple(str(value) for value in self._cfg.engagement_codes)
        if not 1 <= len(codes) <= 100 or any(_CODE.fullmatch(code) is None for code in codes) or len(set(codes)) != len(codes):
            raise IntegrationError("Invalid Bugcrowd engagement scope", provider=PROVIDER)
        return codes

    def _require(self) -> ResilientClient:
        self._scope()
        if self._client is None:
            self._client = build_client(provider=PROVIDER, base_url=f"https://{_HOST}", settings=self.settings, redis=self._redis, timeout=45.0, retry=RetryPolicy(max_attempts=3, backoff_base=1.0))
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {reveal(self._cfg.token_username)}:{reveal(self._cfg.token_password)}", "Accept": "application/vnd.bugcrowd+json"}

    async def list_submissions(self) -> list[dict[str, Any]]:
        client, rows, seen_ids = self._require(), [], set()
        for code in self._scope():
            path, params = "/submissions", {"filter[engagement]": code, "include": "target", "page[limit]": "100", "page[offset]": "0"}
            seen_pages: set[str] = set()
            for _ in range(_MAX_PAGES):
                cursor = path if params is None else f"{path}?{params!r}"
                if cursor in seen_pages:
                    raise IntegrationError("Repeated Bugcrowd cursor", provider=PROVIDER)
                seen_pages.add(cursor)
                payload = await client.get_json(path, params=params, headers=self._headers())
                data, included, links = payload.get("data"), payload.get("included", []), payload.get("links")
                if not isinstance(data, list) or not isinstance(included, list) or not isinstance(links, dict):
                    raise IntegrationError("Invalid Bugcrowd submissions page", provider=PROVIDER)
                targets = {str(item.get("id")): item for item in included if isinstance(item, dict) and item.get("type") == "target"}
                for submission in data:
                    if not isinstance(submission, dict) or submission.get("type") != "submission":
                        raise IntegrationError("Invalid Bugcrowd submission", provider=PROVIDER)
                    submission_id = str(submission.get("id") or "")
                    if not submission_id or submission_id in seen_ids:
                        raise IntegrationError("Repeated or unidentified Bugcrowd submission", provider=PROVIDER)
                    relationships = submission.get("relationships")
                    target_rel = relationships.get("target") if isinstance(relationships, dict) else None
                    target_ref = target_rel.get("data") if isinstance(target_rel, dict) else None
                    target = targets.get(str(target_ref.get("id"))) if isinstance(target_ref, dict) else None
                    if target is None:
                        raise IntegrationError("Bugcrowd submission omitted its target", provider=PROVIDER)
                    seen_ids.add(submission_id)
                    rows.append({"submission": submission, "target": target, "engagement_code": code})
                    if len(rows) > _MAX_SUBMISSIONS:
                        raise IntegrationError("Bugcrowd submission limit exceeded", provider=PROVIDER)
                next_link = links.get("next")
                if next_link is None:
                    break
                if not isinstance(next_link, str) or not next_link:
                    raise IntegrationError("Invalid Bugcrowd cursor", provider=PROVIDER)
                parsed = urlsplit(next_link)
                if parsed.netloc and (parsed.scheme != "https" or parsed.hostname != _HOST or parsed.port):
                    raise IntegrationError("Foreign Bugcrowd cursor", provider=PROVIDER)
                if parsed.path != "/submissions" or not parsed.query:
                    raise IntegrationError("Out-of-scope Bugcrowd cursor", provider=PROVIDER)
                path, params = f"{parsed.path}?{parsed.query}", None
            else:
                raise IntegrationError("Bugcrowd page limit exceeded", provider=PROVIDER)
        return rows

    async def ping(self) -> bool:
        code = self._scope()[0]
        result = await self._require().get_json("/submissions", params={"filter[engagement]": code, "page[limit]": "1"}, headers=self._headers())
        return isinstance(result, dict) and isinstance(result.get("data"), list)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


__all__ = ["BugcrowdClient", "PROVIDER"]
