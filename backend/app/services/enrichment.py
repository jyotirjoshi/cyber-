"""Vulnerability intelligence enrichment (FR-019, FR-020).

One rule governs this module, and it is the reason the code is shaped the way it is:

**A provider that could not be reached is never recorded as a negative result.**

Every provider gets its own :class:`~app.db.enums.EnrichmentStatus` column, and every
failure path writes ``UNAVAILABLE`` rather than leaving the value at its default.  ``in_kev``
is ``bool | None`` for the same reason: ``False`` means CISA answered and this CVE is not in
the catalogue; ``None`` means we do not know.  Collapsing those two into ``False`` would
score an actively-exploited vulnerability as ordinary during a CISA outage, which is the
single most consequential way this system could lie to an operator.

Providers are queried concurrently and independently.  ``asyncio.gather`` with
``return_exceptions=True`` is deliberate: NVD being rate-limited must not stop the EPSS
lookup, and the aggregate status is derived from what each one actually returned.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from collections.abc import Sequence
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import CynuxError, IntegrationNotConfiguredError
from app.db.enums import EnrichmentStatus
from app.db.models.finding import Finding, FindingEnrichment
from app.integrations.epss import EPSSClient, EPSSScore
from app.integrations.kev import KEVClient, KEVEntry
from app.integrations.misp import MISPClient, MISPHit
from app.integrations.nvd import NVDClient, NVDRecord

log = structlog.get_logger(__name__)

#: Cap on stored MISP attributes. The full result set can run to hundreds of indicators for a
#: well-documented CVE; the report cites a handful and the prompt budget (SEC-006) would
#: reject the rest anyway.
_MAX_MISP_ATTRIBUTES = 25

#: Cap on stored NVD references. Same reasoning; the advisory links that matter are the first
#: few, and NVD orders them with vendor advisories first.
_MAX_NVD_REFERENCES = 15

#: Findings enriched per gather round. Bounds the concurrent request count against four
#: upstream APIs, two of which rate-limit aggressively.
_BATCH_SIZE = 10


async def enrich_finding(
    session: AsyncSession,
    finding: Finding,
    *,
    nvd: NVDClient | None = None,
    kev: KEVClient | None = None,
    epss: EPSSClient | None = None,
    misp: MISPClient | None = None,
    settings: Settings,
) -> FindingEnrichment:
    """Enrich one finding from every configured provider.

    Creates the enrichment row if absent, updates it if present, and never raises for a
    provider failure -- the failure is the ``UNAVAILABLE`` status and an entry in
    ``provider_errors``.  Does not commit: the caller owns the transaction boundary, because
    the enrich node enriches a batch and one commit per finding would be one round trip per
    finding on a 200-finding assessment.

    A finding with no CVE gets ``NOT_APPLICABLE`` rather than ``UNAVAILABLE``.  The
    distinction matters in the report appendix: "we could not check" is a caveat on the
    result, "there was nothing to check" is not.
    """
    enrichment = await _row_for(session, finding)
    cve_ids = _cves_of(finding)

    if not cve_ids:
        _mark_not_applicable(enrichment)
        log.debug("enrichment.no_cve", finding_id=str(finding.id))
        return enrichment

    primary = cve_ids[0]
    results = await asyncio.gather(
        _fetch_nvd(nvd, primary),
        _fetch_kev(kev, cve_ids),
        _fetch_epss(epss, cve_ids),
        _fetch_misp(misp, primary, settings),
        return_exceptions=True,
    )
    nvd_result, kev_result, epss_result, misp_result = results

    errors: dict[str, Any] = {}
    _apply_nvd(enrichment, nvd_result, errors=errors)
    _apply_kev(enrichment, kev_result, errors=errors)
    _apply_epss(enrichment, epss_result, errors=errors)
    _apply_misp(enrichment, misp_result, errors=errors)

    enrichment.provider_errors = errors
    enrichment.status = _aggregate_status(enrichment).value
    enrichment.enriched_at = _now()

    log.info(
        "enrichment.completed",
        finding_id=str(finding.id),
        cve=primary,
        status=enrichment.status,
        in_kev=enrichment.in_kev,
        epss=enrichment.epss_score,
        degraded=sorted(errors),
    )
    return enrichment


async def enrich_findings(
    session: AsyncSession,
    findings: Sequence[Finding],
    *,
    nvd: NVDClient | None = None,
    kev: KEVClient | None = None,
    epss: EPSSClient | None = None,
    misp: MISPClient | None = None,
    settings: Settings,
) -> list[FindingEnrichment]:
    """Enrich a batch, in bounded-concurrency rounds.

    Rounds rather than one big ``gather``: 200 findings would open 800 upstream requests at
    once and get every one of them rate-limited, turning a slow enrichment into an
    unavailable one.
    """
    rows: list[FindingEnrichment] = []
    for start in range(0, len(findings), _BATCH_SIZE):
        chunk = findings[start : start + _BATCH_SIZE]
        results = await asyncio.gather(
            *(
                enrich_finding(
                    session,
                    finding,
                    nvd=nvd,
                    kev=kev,
                    epss=epss,
                    misp=misp,
                    settings=settings,
                )
                for finding in chunk
            ),
            return_exceptions=True,
        )
        for finding, result in zip(chunk, results, strict=True):
            if isinstance(result, BaseException):
                # enrich_finding is written not to raise; reaching here means a bug or a
                # DB error, and it must not take the rest of the batch with it.
                log.warning(
                    "enrichment.batch_item_failed",
                    finding_id=str(finding.id),
                    error=type(result).__name__,
                )
                continue
            rows.append(result)
    return rows


def enrichment_evidence(
    finding: Finding,
    enrichment: FindingEnrichment | None,
) -> dict[str, dict[str, Any]]:
    """Citable evidence for the analysis prompt, keyed by source id (FR-024).

    Keys are ``provider:CVE-...``, which is the form :func:`app.llm.guard.verify_claims`
    resolves ``[nvd:CVE-2024-3094]`` markers against.  Providers that were unavailable
    contribute nothing: an absent source is precisely what makes the model unable to claim
    anything about them, and the guard then replaces such a sentence with the mandated
    "unable to verify" text rather than letting it through.
    """
    blocks: dict[str, dict[str, Any]] = {}
    cve = finding.primary_cve

    # The finding itself is always citable. Scanner output is a real observation, and without
    # it every sentence about the finding would be unsupported -- the guard would blank an
    # analysis that was entirely accurate about what the scanner reported.
    blocks[f"scanner:{finding.defectdojo_finding_id}"] = {
        "provider": finding.scanner or "scanner",
        "title": finding.title,
        "severity": finding.severity,
        "endpoint": finding.endpoint,
        "component": finding.component,
        "component_version": finding.component_version,
        "cve_ids": list(finding.cve_ids or []),
        "cwe": finding.cwe,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
    }

    if enrichment is None or cve is None:
        return blocks

    if enrichment.nvd_status == EnrichmentStatus.COMPLETE.value and enrichment.nvd_description:
        blocks[f"nvd:{cve}"] = {
            "provider": "nvd",
            "cve_id": cve,
            "description": enrichment.nvd_description,
            "cvss_v3_base_score": enrichment.nvd_cvss_v31_score,
            "cvss_v3_vector": enrichment.nvd_cvss_v31_vector,
            "cwes": list(enrichment.nvd_cwe_ids or []),
            "published": _iso(enrichment.nvd_published_at),
            "references": list(enrichment.nvd_references or [])[:5],
        }

    if enrichment.kev_status == EnrichmentStatus.COMPLETE.value and enrichment.in_kev is not None:
        blocks[f"kev:{cve}"] = {
            "provider": "cisa_kev",
            "cve_id": cve,
            "listed_in_cisa_kev": enrichment.in_kev,
            "date_added": _iso_date(enrichment.kev_date_added),
            "remediation_due_date": _iso_date(enrichment.kev_due_date),
            "known_ransomware_campaign_use": enrichment.kev_ransomware_use,
            "required_action": enrichment.kev_required_action,
        }

    if enrichment.epss_status == EnrichmentStatus.COMPLETE.value and (
        enrichment.epss_score is not None
    ):
        blocks[f"epss:{cve}"] = {
            "provider": "epss",
            "cve_id": cve,
            "epss_probability": enrichment.epss_score,
            "epss_percentile": enrichment.epss_percentile,
        }

    if enrichment.misp_status == EnrichmentStatus.COMPLETE.value and enrichment.misp_attributes:
        blocks[f"misp:{cve}"] = {
            "provider": "misp",
            "cve_id": cve,
            "event_count": enrichment.misp_event_count,
            "indicators": list(enrichment.misp_attributes)[:5],
        }

    return blocks


def unavailable_providers(enrichment: FindingEnrichment | None) -> list[str]:
    """Providers that could not be consulted, for the report appendix (FR-020).

    The report is required to say what it could not check.  A report that silently omits an
    unreachable provider reads as a complete assessment, which is the failure mode FR-020
    exists to prevent.
    """
    if enrichment is None:
        return []
    return [
        name
        for name, status in (
            ("nvd", enrichment.nvd_status),
            ("cisa_kev", enrichment.kev_status),
            ("epss", enrichment.epss_status),
            ("misp", enrichment.misp_status),
        )
        if status == EnrichmentStatus.UNAVAILABLE.value
    ]


# ---------------------------------------------------------------------------
# Provider fetches -- each returns its own result type or raises
# ---------------------------------------------------------------------------


async def _fetch_nvd(client: NVDClient | None, cve_id: str) -> NVDRecord | None | _Skipped:
    if client is None or not client.configured:
        return _SKIPPED
    return await client.get_cve(cve_id)


async def _fetch_kev(
    client: KEVClient | None, cve_ids: Sequence[str]
) -> tuple[KEVEntry | None, bool] | _Skipped:
    """``(entry, checked)``.

    Returns the tuple rather than just the entry so the caller can tell "CISA answered and
    this CVE is absent" from "we never asked" -- the FR-020 distinction, at the one place
    where the information still exists.
    """
    if client is None or not client.configured:
        return _SKIPPED
    hits = await client.lookup_many(list(cve_ids))
    for cve_id in cve_ids:
        entry = hits.get(cve_id)
        if entry is not None:
            return entry, True
    return None, True


async def _fetch_epss(
    client: EPSSClient | None, cve_ids: Sequence[str]
) -> EPSSScore | None | _Skipped:
    if client is None or not client.configured:
        return _SKIPPED
    scores = await client.scores(list(cve_ids))
    for cve_id in cve_ids:
        score = scores.get(cve_id)
        if score is not None:
            return score
    return None


async def _fetch_misp(
    client: MISPClient | None, cve_id: str, settings: Settings
) -> list[MISPHit] | _Skipped:
    """MISP is optional by design -- most deployments have no instance.

    An unconfigured optional provider yields ``NOT_APPLICABLE``, not ``UNAVAILABLE``: there
    is no outage to report, and flagging one in every report appendix would train operators
    to ignore the section that exists to be read.
    """
    if client is None or not client.configured:
        return _SKIPPED
    return await client.search_cve(cve_id, limit=_MAX_MISP_ATTRIBUTES)


# ---------------------------------------------------------------------------
# Result application
# ---------------------------------------------------------------------------


class _Skipped:
    """Sentinel: the provider was not configured, so nothing was attempted."""

    __slots__ = ()


_SKIPPED = _Skipped()


def _apply_nvd(
    enrichment: FindingEnrichment,
    result: Any,
    *,
    errors: dict[str, Any],
) -> None:
    if isinstance(result, _Skipped):
        enrichment.nvd_status = EnrichmentStatus.NOT_APPLICABLE.value
        return
    if isinstance(result, BaseException):
        enrichment.nvd_status = EnrichmentStatus.UNAVAILABLE.value
        errors["nvd"] = _error_note(result)
        return
    if result is None:
        # NVD answered and has no such record. A real answer, so COMPLETE -- the fields stay
        # null, which is what "no CVE record" looks like.
        enrichment.nvd_status = EnrichmentStatus.COMPLETE.value
        return

    record: NVDRecord = result
    metric = record.primary_metric
    enrichment.nvd_status = EnrichmentStatus.COMPLETE.value
    enrichment.nvd_description = record.description or None
    enrichment.nvd_published_at = _parse_dt(record.published)
    enrichment.nvd_last_modified_at = _parse_dt(record.last_modified)
    enrichment.nvd_cwe_ids = list(record.cwes)
    enrichment.nvd_references = [{"url": url} for url in record.references[:_MAX_NVD_REFERENCES]]

    # The columns are named for CVSS v3.1, so only a v3.x metric goes in them. NVD still
    # carries v2-only scores for older CVEs, and a v2 base score of 5.0 stored in a v3.1
    # column would be quoted in a report as a v3.1 score -- understating a vulnerability
    # whose v3.1 equivalent is routinely two or three points higher.
    if metric is not None and metric.version.startswith("3"):
        enrichment.nvd_cvss_v31_score = metric.base_score
        enrichment.nvd_cvss_v31_vector = metric.vector
    else:
        enrichment.nvd_cvss_v31_score = None
        enrichment.nvd_cvss_v31_vector = None
        if metric is not None:
            errors["nvd"] = f"NVD has only a CVSS v{metric.version} score for this CVE."

    if record.is_rejected:
        # Recorded, not hidden: a rejected CVE that a scanner still reports is a probable
        # false positive, and the analysis step needs to be able to say so.
        errors["nvd"] = f"NVD marks this record {record.vuln_status}."


def _apply_kev(
    enrichment: FindingEnrichment,
    result: Any,
    *,
    errors: dict[str, Any],
) -> None:
    if isinstance(result, _Skipped):
        enrichment.kev_status = EnrichmentStatus.NOT_APPLICABLE.value
        enrichment.in_kev = None
        return
    if isinstance(result, BaseException):
        # The load-bearing line of this module: unreachable stays None, never False.
        enrichment.kev_status = EnrichmentStatus.UNAVAILABLE.value
        enrichment.in_kev = None
        errors["cisa_kev"] = _error_note(result)
        return

    entry, checked = result
    enrichment.kev_status = (
        EnrichmentStatus.COMPLETE.value if checked else EnrichmentStatus.UNAVAILABLE.value
    )
    if entry is None:
        enrichment.in_kev = False if checked else None
        enrichment.kev_date_added = None
        enrichment.kev_due_date = None
        enrichment.kev_ransomware_use = None
        enrichment.kev_required_action = None
        return

    enrichment.in_kev = True
    enrichment.kev_date_added = _parse_date(entry.date_added)
    enrichment.kev_due_date = _parse_date(entry.due_date)
    enrichment.kev_ransomware_use = "known" if entry.known_ransomware_use else "unknown"
    enrichment.kev_required_action = entry.required_action or None


def _apply_epss(
    enrichment: FindingEnrichment,
    result: Any,
    *,
    errors: dict[str, Any],
) -> None:
    if isinstance(result, _Skipped):
        enrichment.epss_status = EnrichmentStatus.NOT_APPLICABLE.value
        return
    if isinstance(result, BaseException):
        enrichment.epss_status = EnrichmentStatus.UNAVAILABLE.value
        enrichment.epss_score = None
        enrichment.epss_percentile = None
        errors["epss"] = _error_note(result)
        return

    enrichment.epss_status = EnrichmentStatus.COMPLETE.value
    if result is None:
        # FIRST scores published CVEs only; absence is a real answer, not a failure.
        enrichment.epss_score = None
        enrichment.epss_percentile = None
        return
    score: EPSSScore = result
    enrichment.epss_score = round(score.probability, 6)
    enrichment.epss_percentile = round(score.percentile, 6)


def _apply_misp(
    enrichment: FindingEnrichment,
    result: Any,
    *,
    errors: dict[str, Any],
) -> None:
    if isinstance(result, _Skipped):
        enrichment.misp_status = EnrichmentStatus.NOT_APPLICABLE.value
        return
    if isinstance(result, BaseException):
        enrichment.misp_status = EnrichmentStatus.UNAVAILABLE.value
        errors["misp"] = _error_note(result)
        return

    hits: list[MISPHit] = list(result)
    enrichment.misp_status = EnrichmentStatus.COMPLETE.value
    enrichment.misp_event_count = len({hit.event_id for hit in hits if hit.event_id})
    enrichment.misp_attributes = [hit.evidence() for hit in hits[:_MAX_MISP_ATTRIBUTES]]


def _aggregate_status(enrichment: FindingEnrichment) -> EnrichmentStatus:
    """Roll the four provider statuses into one.

    ``PARTIAL`` when some providers answered and others did not.  A single status would
    force a choice between overstating completeness and understating it; the per-provider
    columns stay authoritative and this is a summary for filtering.
    """
    statuses = [
        enrichment.nvd_status,
        enrichment.kev_status,
        enrichment.epss_status,
        enrichment.misp_status,
    ]
    considered = [s for s in statuses if s != EnrichmentStatus.NOT_APPLICABLE.value]
    if not considered:
        return EnrichmentStatus.NOT_APPLICABLE
    complete = [s for s in considered if s == EnrichmentStatus.COMPLETE.value]
    if len(complete) == len(considered):
        return EnrichmentStatus.COMPLETE
    if not complete:
        return EnrichmentStatus.UNAVAILABLE
    return EnrichmentStatus.PARTIAL


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _row_for(session: AsyncSession, finding: Finding) -> FindingEnrichment:
    """The finding's enrichment row, created if absent.

    Queried rather than read off ``finding.enrichment``: under ``lazy="raise_on_sql"`` the
    relationship raises unless the caller eager-loaded it, and this function is called from
    paths that legitimately did not.
    """
    existing = (
        await session.execute(
            select(FindingEnrichment).where(FindingEnrichment.finding_id == finding.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    row = FindingEnrichment(
        organization_id=finding.organization_id,
        finding_id=finding.id,
        status=EnrichmentStatus.PENDING.value,
        nvd_status=EnrichmentStatus.PENDING.value,
        kev_status=EnrichmentStatus.PENDING.value,
        epss_status=EnrichmentStatus.PENDING.value,
        misp_status=EnrichmentStatus.PENDING.value,
        nvd_cwe_ids=[],
        nvd_references=[],
        misp_attributes=[],
        provider_errors={},
    )
    session.add(row)
    await session.flush()
    return row


def _mark_not_applicable(enrichment: FindingEnrichment) -> None:
    """No CVE, nothing to look up. Not a degradation."""
    for attr in ("status", "nvd_status", "kev_status", "epss_status", "misp_status"):
        setattr(enrichment, attr, EnrichmentStatus.NOT_APPLICABLE.value)
    enrichment.in_kev = None
    enrichment.provider_errors = {}
    enrichment.enriched_at = _now()


def _cves_of(finding: Finding) -> list[str]:
    """Normalized, de-duplicated CVE ids from the finding, order preserved."""
    seen: list[str] = []
    for raw in finding.cve_ids or []:
        cve = str(raw).strip().upper()
        if cve.startswith("CVE-") and cve not in seen:
            seen.append(cve)
    return seen


def _error_note(exc: BaseException) -> str:
    """A user-safe one-liner for ``provider_errors``.

    Uses ``user_message`` for taxonomy errors and the class name otherwise.  ``str(exc)`` is
    avoided: an httpx error stringifies to a URL that can carry an API key (SEC-002), and
    this dict is serialized into the report appendix.
    """
    if isinstance(exc, IntegrationNotConfiguredError):
        return "Not configured."
    if isinstance(exc, CynuxError):
        return exc.user_message
    return f"The provider could not be reached ({type(exc).__name__})."


def _parse_dt(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _parse_date(value: str | None) -> dt.date | None:
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def _iso_date(value: dt.date | None) -> str | None:
    return value.isoformat() if value else None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


async def load_enrichments(
    session: AsyncSession,
    finding_ids: Sequence[uuid.UUID],
) -> dict[uuid.UUID, FindingEnrichment]:
    """Enrichment rows for a set of findings, keyed by finding id.

    One query for the batch. The analysis and report stages both need every finding's
    enrichment, and doing it per finding is the classic N+1 that ``lazy="raise_on_sql"``
    exists to make impossible to write by accident.
    """
    if not finding_ids:
        return {}
    rows = (
        (
            await session.execute(
                select(FindingEnrichment).where(FindingEnrichment.finding_id.in_(list(finding_ids)))
            )
        )
        .scalars()
        .all()
    )
    return {row.finding_id: row for row in rows}


async def findings_with_enrichment(
    session: AsyncSession,
    finding_ids: Sequence[uuid.UUID],
) -> list[Finding]:
    """Findings with ``enrichment`` and ``asset`` eagerly loaded."""
    if not finding_ids:
        return []
    stmt = (
        select(Finding)
        .where(Finding.id.in_(list(finding_ids)))
        .options(selectinload(Finding.enrichment), selectinload(Finding.asset))
        .order_by(Finding.id)
    )
    return list((await session.execute(stmt)).scalars().all())


__all__ = [
    "enrich_finding",
    "enrich_findings",
    "enrichment_evidence",
    "findings_with_enrichment",
    "load_enrichments",
    "unavailable_providers",
]
