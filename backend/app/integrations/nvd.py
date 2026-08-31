"""NVD CVE lookups (FR-019).

Two constraints drive the shape of this module.

**NVD rate-limits hard.**  Five requests per rolling 30 seconds without an API key, fifty
with one.  Those are documented limits, not guidance, and exceeding them earns a 403 rather
than a 429.  The limiter is therefore the Redis token bucket, not a per-process counter: an
API replica enriching a finding on demand and three workers enriching a batch all draw from
the same allowance.  Combined with a 24-hour response cache -- CVE records change on the
scale of days -- a full assessment usually makes a handful of real requests.

**A miss is not a zero.**  :meth:`NVDClient.get_cve` returns ``None`` only when NVD
*answered* and had no such record.  When NVD is unreachable it raises, because the caller
must write :attr:`~app.db.enums.EnrichmentStatus.UNAVAILABLE` rather than record a CVE as
having no CVSS score.  FR-024 draws exactly this line: "we could not reach NVD" and "this
CVE has no severity" are different statements and the report must not confuse them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal
from app.llm.guard import CVE_RE, normalize_cve

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "NVD"

#: Anonymous and keyed request allowances, in requests per 30 seconds, per NVD's published
#: policy. Expressed as a refill rate for the token bucket.
_ANON_PER_30S = 5
_KEYED_PER_30S = 50


@dataclass(frozen=True, slots=True)
class CVSSMetric:
    version: str
    vector: str
    base_score: float
    base_severity: str
    #: NVD returns metrics from several sources (NIST, the vendor CNA). The source matters
    #: for citation: FR-024 requires the evidence id to identify who said it.
    source: str = ""
    primary: bool = False


@dataclass(frozen=True, slots=True)
class NVDRecord:
    cve_id: str
    description: str = ""
    published: str | None = None
    last_modified: str | None = None
    #: ``"Rejected"`` or ``"Deferred"`` records exist and must not be treated as live
    #: vulnerabilities.
    vuln_status: str | None = None
    metrics: list[CVSSMetric] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def primary_metric(self) -> CVSSMetric | None:
        """The metric to quote, preferring CVSS v3.1 from a primary source.

        NVD frequently carries both a v2 and a v3.x score, and a v2 score of 5.0 next to a
        v3.1 score of 9.8 for the same CVE is a routine occurrence. Quoting the wrong one
        understates risk, so the preference order is explicit rather than "first in list".
        """
        if not self.metrics:
            return None
        ordered = sorted(
            self.metrics,
            key=lambda m: (
                0 if m.version.startswith("3.1") else 1 if m.version.startswith("3") else 2,
                0 if m.primary else 1,
            ),
        )
        return ordered[0]

    @property
    def base_score(self) -> float | None:
        metric = self.primary_metric
        return metric.base_score if metric else None

    @property
    def severity(self) -> str | None:
        metric = self.primary_metric
        return metric.base_severity if metric else None

    @property
    def is_rejected(self) -> bool:
        return (self.vuln_status or "").strip().lower() in {"rejected", "deferred"}

    def evidence(self) -> dict[str, Any]:
        """The citable evidence block for this record (FR-024).

        The key format ``nvd:CVE-...`` is what :func:`app.llm.guard.verify_claims` resolves
        source markers against, so a model citing ``[nvd:CVE-2024-3094]`` is checkable.
        """
        metric = self.primary_metric
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_version": metric.version if metric else None,
            "cvss_base_score": metric.base_score if metric else None,
            "cvss_severity": metric.base_severity if metric else None,
            "cvss_vector": metric.vector if metric else None,
            "cvss_source": metric.source if metric else None,
            "cwes": self.cwes,
            "published": self.published,
            "vuln_status": self.vuln_status,
        }


def _parse_metrics(metrics: dict[str, Any]) -> list[CVSSMetric]:
    out: list[CVSSMetric] = []
    #: NVD's key names encode the version: cvssMetricV31, cvssMetricV30, cvssMetricV2.
    for key, entries in (metrics or {}).items():
        if not key.startswith("cvssMetric") or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData") or {}
            raw_score = data.get("baseScore")
            if raw_score is None:
                continue
            try:
                base_score = float(raw_score)
            except (TypeError, ValueError):
                continue
            severity = (
                data.get("baseSeverity")
                #: CVSS v2 carries severity on the wrapper, not on cvssData.
                or entry.get("baseSeverity")
                or ""
            )
            out.append(
                CVSSMetric(
                    version=str(data.get("version") or key.removeprefix("cvssMetricV")),
                    vector=str(data.get("vectorString") or ""),
                    base_score=base_score,
                    base_severity=str(severity),
                    source=str(entry.get("source") or ""),
                    primary=str(entry.get("type") or "").lower() == "primary",
                )
            )
    return out


def parse_cve(payload: dict[str, Any]) -> NVDRecord | None:
    """Turn one NVD 2.0 ``vulnerabilities[]`` entry into a record."""
    cve = payload.get("cve") if "cve" in payload else payload
    if not isinstance(cve, dict) or not cve.get("id"):
        return None

    descriptions = cve.get("descriptions") or []
    english = next(
        (d.get("value") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"),
        "",
    )

    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in (weakness or {}).get("description") or []:
            value = (desc or {}).get("value")
            if isinstance(value, str) and value.upper().startswith("CWE-"):
                cwes.append(value.upper())

    references = [
        str(ref.get("url"))
        for ref in cve.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]

    return NVDRecord(
        cve_id=normalize_cve(str(cve["id"])),
        description=str(english or ""),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        vuln_status=cve.get("vulnStatus"),
        metrics=_parse_metrics(cve.get("metrics") or {}),
        cwes=sorted(set(cwes)),
        references=references[:20],
    )


class NVDClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.intel
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        """NVD needs no credential, so it is always available.

        An API key raises the rate limit tenfold but is not required; treating NVD as
        unconfigured without one would disable enrichment for every default deployment.
        """
        return bool(self._cfg.nvd_base_url)

    def _require(self) -> ResilientClient:
        if self._client is None:
            headers = {"Accept": "application/json"}
            if self._cfg.nvd_api_key:
                headers["apiKey"] = reveal(self._cfg.nvd_api_key)

            limiter = None
            if self._redis is not None:
                from app.core.redis_client import TokenBucket

                per_30s = _KEYED_PER_30S if self._cfg.nvd_api_key else _ANON_PER_30S
                limiter = TokenBucket(
                    self._redis,
                    name="nvd",
                    #: Capacity is deliberately below the published allowance. NVD counts
                    #: over a rolling window and we cannot see their clock; leaving a
                    #: token of headroom is cheaper than being blocked for 30 seconds.
                    capacity=max(per_30s - 1, 1),
                    refill_per_second=per_30s / 30.0,
                )

            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.nvd_base_url,
                settings=self.settings,
                redis=self._redis,
                headers=headers,
                timeout=30.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=2.0, backoff_max=16.0),
                rate_limiter=limiter,
                breaker_config=BreakerConfig(failure_threshold=6, cooldown_seconds=120),
                cacheable=True,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_cve(self, cve_id: str) -> NVDRecord | None:
        """Look up one CVE.

        Returns ``None`` only when NVD answered and had no such record. Unreachability
        raises -- see the module docstring.
        """
        normalized = normalize_cve(cve_id)
        if not CVE_RE.fullmatch(normalized):
            #: Rejecting locally rather than asking NVD: the id comes from scanner output
            #: or model text, and a malformed value is a bug or a hallucination, not a
            #: lookup. Sending it would also spend a rate-limit token on a certain 404.
            logger.debug("nvd.malformed_cve_id", value=cve_id[:64])
            return None

        payload = await self._require().get_json(
            "/cves/2.0",
            params={"cveId": normalized},
            cache_ttl=self._cfg.nvd_cache_ttl_seconds,
        )
        entries = (payload or {}).get("vulnerabilities") or []
        if not entries:
            return None
        record = parse_cve(entries[0])
        if record is None:
            raise IntegrationError(
                "NVD returned a vulnerability entry Cynux could not parse.",
                provider=PROVIDER,
                context={"cve_id": normalized},
            )
        return record

    async def get_many(self, cve_ids: list[str]) -> dict[str, NVDRecord]:
        """Look up several CVEs, one request each.

        NVD's 2.0 API has no batch-by-id endpoint -- ``cveId`` accepts a single value -- so
        this is a loop by necessity, paced by the shared token bucket. Failures are
        collected rather than propagated: enriching 40 of 42 CVEs is a partial result the
        caller records as :attr:`~app.db.enums.EnrichmentStatus.PARTIAL`, whereas raising
        would discard the 40 that worked.
        """
        out: dict[str, NVDRecord] = {}
        for cve_id in dict.fromkeys(normalize_cve(c) for c in cve_ids):
            try:
                record = await self.get_cve(cve_id)
            except IntegrationError as exc:
                logger.warning("nvd.lookup_failed", cve_id=cve_id, error=exc.code)
                continue
            if record is not None:
                out[cve_id] = record
        return out


__all__ = ["PROVIDER", "CVSSMetric", "NVDClient", "NVDRecord", "parse_cve"]
