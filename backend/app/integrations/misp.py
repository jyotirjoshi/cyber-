"""MISP threat-intelligence lookups (FR-019).

MISP is the one intelligence provider that is genuinely optional: it is a self-hosted
platform an organization either runs or does not, and most Cynux deployments will not have
one.  Unconfigured, every method raises
:class:`~app.core.errors.IntegrationNotConfiguredError` -- it does not return an empty hit
list.  The distinction matters at the top of the stack: an empty list from a configured MISP
means "our threat-intel platform has nothing on this indicator", which is a real negative
signal worth reporting, while an unconfigured MISP means the question was never asked.
Conflating them would put a false negative in a report.

MISP instances are usually internal, frequently behind a self-signed certificate, which is
why ``verify_tls`` is configurable here and defaults to on.  Turning it off is a deliberate,
logged decision -- see :data:`~app.core.config.IntelSettings.misp_verify_tls`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "MISP"

#: Attribute types worth searching on. MISP holds far more, but these are the ones a
#: security assessment produces: hostnames, addresses, URLs and CVE references.
SEARCHABLE_TYPES = (
    "domain",
    "hostname",
    "ip-src",
    "ip-dst",
    "url",
    "vulnerability",
)


@dataclass(frozen=True, slots=True)
class MISPHit:
    attribute_id: str
    attribute_type: str
    value: str
    category: str = ""
    event_id: str = ""
    event_info: str = ""
    #: MISP's own threat level, 1 (high) to 4 (undefined). Inverted relative to every other
    #: scale in this codebase, so it is exposed raw and interpreted by
    #: :attr:`threat_label` rather than silently remapped.
    threat_level_id: str | None = None
    to_ids: bool = False
    comment: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None

    @property
    def threat_label(self) -> str:
        return {
            "1": "high",
            "2": "medium",
            "3": "low",
            "4": "undefined",
        }.get(str(self.threat_level_id or ""), "unknown")

    def evidence(self) -> dict[str, Any]:
        return {
            "indicator": self.value,
            "indicator_type": self.attribute_type,
            "misp_event": self.event_info,
            "misp_event_id": self.event_id,
            "category": self.category,
            "threat_level": self.threat_label,
            #: ``to_ids`` false means the analyst who entered it did not consider it
            #: actionable for detection. Reporting it as a confirmed indicator would
            #: overstate what MISP actually says.
            "actionable_for_detection": self.to_ids,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def _parse_hit(payload: dict[str, Any]) -> MISPHit | None:
    if not isinstance(payload, dict) or not payload.get("value"):
        return None
    event = payload.get("Event") or {}
    tags = [
        str(tag.get("name"))
        for tag in payload.get("Tag") or []
        if isinstance(tag, dict) and tag.get("name")
    ]
    return MISPHit(
        attribute_id=str(payload.get("id") or ""),
        attribute_type=str(payload.get("type") or ""),
        value=str(payload["value"]),
        category=str(payload.get("category") or ""),
        event_id=str(event.get("id") or payload.get("event_id") or ""),
        event_info=str(event.get("info") or ""),
        threat_level_id=(event.get("threat_level_id") if isinstance(event, dict) else None),
        to_ids=bool(payload.get("to_ids", False)),
        comment=str(payload.get("comment") or ""),
        tags=tags,
        first_seen=payload.get("first_seen"),
        last_seen=payload.get("last_seen"),
    )


class MISPClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.intel
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return bool(self._cfg.misp_configured)

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set CYNUX_INTEL__MISP_BASE_URL and CYNUX_INTEL__MISP_API_KEY.",
            )
        if self._client is None:
            if not self._cfg.misp_verify_tls:
                #: Logged every time the client is built, so an operator reviewing logs can
                #: see that certificate verification is off rather than discovering it in a
                #: config file six months later.
                logger.warning("misp.tls_verification_disabled", base_url=self._cfg.misp_base_url)
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.misp_base_url or "",
                settings=self.settings,
                redis=self._redis,
                headers={
                    "Authorization": reveal(self._cfg.misp_api_key),
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
                verify=self._cfg.misp_verify_tls,
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search_attribute(self, value: str, *, limit: int = 25) -> list[MISPHit]:
        """Search MISP attributes for one indicator.

        Uses ``/attributes/restSearch`` with ``returnFormat=json``. The endpoint is a POST
        because MISP's search body is a JSON document, but it is a read: no
        ``idempotency_key`` is supplied because retrying it cannot create anything, and the
        HTTP spine therefore will not retry it. That is the safe default and the cost is one
        lost retry on a transient failure of an optional provider.
        """
        cleaned = value.strip()
        if not cleaned:
            return []

        payload = await self._require().post_json(
            "/attributes/restSearch",
            json={
                "returnFormat": "json",
                "value": cleaned,
                "type": list(SEARCHABLE_TYPES),
                "limit": max(1, min(limit, 100)),
                #: Deleted attributes are excluded: an indicator an analyst retracted is
                #: not evidence.
                "deleted": False,
                "includeEventTags": True,
            },
        )
        response = (payload or {}).get("response") or {}
        raw_attributes = response.get("Attribute") or []
        hits: list[MISPHit] = []
        for entry in raw_attributes:
            hit = _parse_hit(entry)
            if hit is not None:
                hits.append(hit)
        logger.debug("misp.search_complete", indicator_type="value", hits=len(hits))
        return hits

    async def search_cve(self, cve_id: str, *, limit: int = 25) -> list[MISPHit]:
        """Indicators MISP associates with a CVE."""
        return await self.search_attribute(cve_id.strip().upper(), limit=limit)

    async def ping(self) -> bool:
        await self._require().get_json("/servers/getVersion")
        return True


__all__ = ["PROVIDER", "SEARCHABLE_TYPES", "MISPClient", "MISPHit"]
