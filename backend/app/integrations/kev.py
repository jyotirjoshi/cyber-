"""CISA Known Exploited Vulnerabilities catalogue (FR-019).

KEV is the single highest-signal input to prioritization: a CVE in this catalogue is one
CISA has confirmed is being exploited in the wild, which outranks any CVSS score in
:data:`~app.llm.prompts.PRIORITIZATION_SYSTEM`.  It is also cheap -- one JSON document of a
few thousand entries, refreshed a handful of times a day -- so the client fetches the whole
catalogue and caches it rather than querying per CVE.

The important rule in this module is what happens when the fetch fails.  It raises.  It does
not return an empty catalogue, and callers must not translate a failure into ``in_kev =
False``.  ``Finding.in_kev`` is deliberately ``bool | None`` for this reason: ``None`` means
"we could not check", ``False`` means "CISA has this CVE and it is not listed", and
collapsing the two would let a report state that a vulnerability is not being exploited on
the strength of a network timeout (FR-024).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client
from app.llm.guard import normalize_cve

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "CISA KEV"

#: Namespace for the whole-catalogue cache entry.
_CACHE_NAMESPACE = "kev"
_CACHE_KEY = "catalog"


@dataclass(frozen=True, slots=True)
class KEVEntry:
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str | None = None
    short_description: str = ""
    required_action: str = ""
    due_date: str | None = None
    #: CISA's own field, spelled ``knownRansomwareCampaignUse``. Values are "Known" or
    #: "Unknown"; anything else is treated as unknown rather than as a denial.
    known_ransomware_use: bool = False

    def evidence(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "listed_in_cisa_kev": True,
            "date_added": self.date_added,
            "vulnerability_name": self.vulnerability_name,
            "required_action": self.required_action,
            "remediation_due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_use,
            "vendor_project": self.vendor_project,
            "product": self.product,
        }


@dataclass(frozen=True, slots=True)
class KEVCatalog:
    catalog_version: str = ""
    date_released: str | None = None
    entries: dict[str, KEVEntry] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cve_id: str) -> KEVEntry | None:
        return self.entries.get(normalize_cve(cve_id))

    def __contains__(self, cve_id: str) -> bool:
        return normalize_cve(cve_id) in self.entries


def _parse_entry(payload: dict[str, Any]) -> KEVEntry | None:
    cve_id = payload.get("cveID") or payload.get("cveId")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    ransomware = str(payload.get("knownRansomwareCampaignUse") or "").strip().lower()
    return KEVEntry(
        cve_id=normalize_cve(cve_id),
        vendor_project=str(payload.get("vendorProject") or ""),
        product=str(payload.get("product") or ""),
        vulnerability_name=str(payload.get("vulnerabilityName") or ""),
        date_added=payload.get("dateAdded"),
        short_description=str(payload.get("shortDescription") or ""),
        required_action=str(payload.get("requiredAction") or ""),
        due_date=payload.get("dueDate"),
        known_ransomware_use=ransomware == "known",
    )


def parse_catalog(payload: dict[str, Any]) -> KEVCatalog:
    entries: dict[str, KEVEntry] = {}
    for raw in payload.get("vulnerabilities") or []:
        if not isinstance(raw, dict):
            continue
        entry = _parse_entry(raw)
        if entry is not None:
            entries[entry.cve_id] = entry
    return KEVCatalog(
        catalog_version=str(payload.get("catalogVersion") or ""),
        date_released=payload.get("dateReleased"),
        entries=entries,
    )


class KEVClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.intel
        self._redis = redis
        self._client: ResilientClient | None = None
        #: Process-local copy on top of the Redis cache. A single enrichment pass looks up
        #: hundreds of CVEs; deserializing a few thousand entries from Redis for each one
        #: would dominate the pass.
        self._memo: KEVCatalog | None = None

    @property
    def configured(self) -> bool:
        """KEV is a public feed with no credential, so it is always available."""
        return bool(self._cfg.kev_url)

    def _require(self) -> ResilientClient:
        if self._client is None:
            #: The KEV URL is absolute and points at a different host from the other
            #: intelligence providers, so the base URL is the feed itself and every request
            #: uses an empty path.
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.kev_url,
                settings=self.settings,
                redis=self._redis,
                headers={"Accept": "application/json"},
                timeout=45.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=300),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _cache_get(self) -> KEVCatalog | None:
        if self._redis is None:
            return None
        from app.core.redis_client import ResponseCache

        try:
            payload = await ResponseCache(self._redis, self.settings).get(
                _CACHE_NAMESPACE, _CACHE_KEY
            )
        except Exception:  # pragma: no cover - cache is an optimization
            return None
        if not isinstance(payload, dict):
            return None
        return parse_catalog(payload)

    async def _cache_set(self, payload: dict[str, Any]) -> None:
        if self._redis is None:
            return
        from app.core.redis_client import ResponseCache

        try:
            await ResponseCache(self._redis, self.settings).set(
                _CACHE_NAMESPACE, _CACHE_KEY, payload, self._cfg.kev_refresh_seconds
            )
        except Exception:  # pragma: no cover - cache is an optimization
            logger.debug("kev.cache_store_failed")

    async def refresh(self, *, force: bool = False) -> KEVCatalog:
        """Return the catalogue, fetching it if the cached copy has expired.

        Raises on failure. A caller that wants degradation rather than an exception catches
        :class:`~app.core.errors.IntegrationError` and records
        :attr:`~app.db.enums.EnrichmentStatus.UNAVAILABLE`; it must not substitute an empty
        catalogue.
        """
        if not force and self._memo is not None:
            return self._memo
        if not force:
            cached = await self._cache_get()
            if cached is not None and cached.entries:
                self._memo = cached
                return cached

        payload = await self._require().get_json("")
        if not isinstance(payload, dict) or "vulnerabilities" not in payload:
            raise IntegrationError(
                "The CISA KEV feed returned an unexpected document shape.",
                provider=PROVIDER,
            )
        catalog = parse_catalog(payload)
        if not catalog.entries:
            #: An empty catalogue has never been published. Treating one as valid would
            #: cache "nothing is exploited" for six hours.
            raise IntegrationError(
                "The CISA KEV feed returned an empty catalogue.",
                provider=PROVIDER,
                context={"catalog_version": catalog.catalog_version},
            )
        await self._cache_set(payload)
        self._memo = catalog
        logger.info(
            "kev.refreshed",
            entries=len(catalog),
            catalog_version=catalog.catalog_version,
        )
        return catalog

    async def lookup(self, cve_id: str) -> KEVEntry | None:
        """``None`` means CISA has no entry for this CVE -- not that we failed to check."""
        catalog = await self.refresh()
        return catalog.get(cve_id)

    async def lookup_many(self, cve_ids: list[str]) -> dict[str, KEVEntry]:
        catalog = await self.refresh()
        hits: dict[str, KEVEntry] = {}
        for cve_id in cve_ids:
            entry = catalog.get(cve_id)
            if entry is not None:
                hits[entry.cve_id] = entry
        return hits


__all__ = ["PROVIDER", "KEVCatalog", "KEVClient", "KEVEntry", "parse_catalog"]
