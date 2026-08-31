"""FIRST EPSS scores (FR-019).

EPSS answers a question CVSS cannot: *how likely is this to be exploited in the next 30
days?*  A CVSS 9.8 with an EPSS probability of 0.0004 and a CVSS 6.5 with an EPSS of 0.87 are
routinely both present in one assessment, and the second is the one to fix first.
:data:`~app.llm.prompts.PRIORITIZATION_SYSTEM` weights it accordingly.

The API takes a comma-separated ``cve`` parameter, so unlike NVD this client genuinely
batches.  Batches are capped at :data:`MAX_BATCH` because the parameter travels in the query
string and a 400-CVE assessment would otherwise build a URL long enough for an intermediate
proxy to reject -- which would present as a confusing 414 rather than as a batching bug.

As everywhere in the intelligence layer, a missing score and an unreachable provider are
different things.  A CVE absent from the response simply has no published EPSS score, which
is normal for recent CVEs; an unreachable API raises.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client
from app.llm.guard import CVE_RE, normalize_cve

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "EPSS"

#: CVEs per request. Keeps the query string comfortably inside every proxy's URL limit.
MAX_BATCH = 100


@dataclass(frozen=True, slots=True)
class EPSSScore:
    cve_id: str
    #: Probability of exploitation in the next 30 days, 0.0-1.0.
    probability: float
    #: Position against all scored CVEs, 0.0-1.0. 0.95 means "more likely to be exploited
    #: than 95% of all scored CVEs" -- the number a human actually reasons about.
    percentile: float
    date: str | None = None

    @property
    def percentile_display(self) -> str:
        return f"{self.percentile * 100:.1f}th percentile"

    def evidence(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss_probability": round(self.probability, 5),
            "epss_percentile": round(self.percentile, 5),
            "epss_model_date": self.date,
            "interpretation": (
                f"{self.probability:.2%} estimated probability of exploitation within 30 "
                f"days ({self.percentile_display})."
            ),
        }


def _parse_score(payload: dict[str, Any]) -> EPSSScore | None:
    cve_id = payload.get("cve")
    if not isinstance(cve_id, str):
        return None
    raw_probability = payload.get("epss")
    raw_percentile = payload.get("percentile")
    #: An absent score is not a zero score (FR-024): rejecting the record leaves the finding
    #: un-enriched, where coercing to 0.0 would assert "no exploitation likelihood" as fact.
    if raw_probability is None or raw_percentile is None:
        return None
    try:
        probability = float(raw_probability)
        percentile = float(raw_percentile)
    except (TypeError, ValueError):
        return None
    return EPSSScore(
        cve_id=normalize_cve(cve_id),
        probability=probability,
        percentile=percentile,
        date=payload.get("date"),
    )


class EPSSClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.intel
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        """Public API, no credential required."""
        return bool(self._cfg.epss_base_url)

    def _require(self) -> ResilientClient:
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.epss_base_url,
                settings=self.settings,
                redis=self._redis,
                headers={"Accept": "application/json"},
                timeout=30.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=5, cooldown_seconds=120),
                cacheable=True,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def scores(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for up to any number of CVEs, batched.

        The returned map only contains CVEs FIRST has a score for. Absence means "no
        published score", which for a CVE published this week is the normal case.
        """
        wanted = [
            normalized
            for normalized in dict.fromkeys(normalize_cve(c) for c in cve_ids)
            if CVE_RE.fullmatch(normalized)
        ]
        if not wanted:
            return {}

        out: dict[str, EPSSScore] = {}
        for start in range(0, len(wanted), MAX_BATCH):
            batch = wanted[start : start + MAX_BATCH]
            payload = await self._require().get_json(
                "",
                params={"cve": ",".join(batch), "pretty": "false"},
                cache_ttl=self._cfg.epss_cache_ttl_seconds,
            )
            if not isinstance(payload, dict):
                raise IntegrationError(
                    "EPSS returned an unexpected document shape.", provider=PROVIDER
                )
            for entry in payload.get("data") or []:
                if not isinstance(entry, dict):
                    continue
                score = _parse_score(entry)
                if score is not None:
                    out[score.cve_id] = score

        logger.debug("epss.scores_fetched", requested=len(wanted), returned=len(out))
        return out

    async def score(self, cve_id: str) -> EPSSScore | None:
        return (await self.scores([cve_id])).get(normalize_cve(cve_id))


__all__ = ["MAX_BATCH", "PROVIDER", "EPSSClient", "EPSSScore"]
