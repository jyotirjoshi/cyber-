"""Refresh public CVE signals used by the canonical exposure risk model."""

from __future__ import annotations

import asyncio
import datetime as dt
import math
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import CynuxError, IntegrationNotConfiguredError
from app.db.enums import IntegrationKind, Role
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.identity import Organization
from app.integrations.epss import EPSSClient
from app.integrations.kev import KEVClient
from app.integrations.nvd import NVDClient
from app.llm.guard import CVE_RE, normalize_cve
from app.services.canonical_risk import score_canonical
from app.services.context import ACTOR_WORKER, Principal
from app.services.integration import resolve_settings
from app.services.organization import load_policy


def _bounded(value: Any, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, float | int):
        return None
    result = float(value)
    return result if math.isfinite(result) and 0 <= result <= maximum else None


async def fetch_cve_intelligence(
    cve_id: str, *, nvd: Any, kev: Any, epss: Any
) -> dict[str, Any]:
    """Fetch independent feeds without treating a failed provider as a negative answer."""
    normalized = normalize_cve(cve_id)
    if CVE_RE.fullmatch(normalized) is None:
        raise ValueError("Invalid CVE identifier")
    nvd_result, kev_result, epss_result = await asyncio.gather(
        nvd.get_cve(normalized), kev.lookup(normalized), epss.score(normalized),
        return_exceptions=True,
    )
    if any(isinstance(result, asyncio.CancelledError) for result in (nvd_result, kev_result, epss_result)):
        raise asyncio.CancelledError()
    snapshot: dict[str, Any] = {"cve_id": normalized}
    snapshot["nvd_status"] = "unavailable" if isinstance(nvd_result, BaseException) else "complete"
    snapshot["kev_status"] = "unavailable" if isinstance(kev_result, BaseException) else "complete"
    snapshot["epss_status"] = "unavailable" if isinstance(epss_result, BaseException) else "complete"
    if nvd_result is not None and not isinstance(nvd_result, BaseException) and not nvd_result.is_rejected:
        cvss = _bounded(nvd_result.base_score, 10.0)
        if cvss is not None:
            snapshot["cvss_score"] = cvss
        exploit_references = getattr(nvd_result, "exploit_references", [])
        if exploit_references:
            snapshot["exploit_available"] = True
            snapshot["exploit_reference_count"] = len(exploit_references)
            snapshot["exploit_references"] = exploit_references[:5]
    if not isinstance(kev_result, BaseException):
        snapshot["in_kev"] = kev_result is not None
        if kev_result is not None and kev_result.known_ransomware_use:
            snapshot["ransomware_use"] = True
    if epss_result is not None and not isinstance(epss_result, BaseException):
        probability = _bounded(epss_result.probability, 1.0)
        if probability is not None:
            snapshot["epss_score"] = probability
    return snapshot


def merge_last_known_intelligence(
    current: dict[str, Any], prior: dict[str, Any]
) -> dict[str, Any]:
    """Retain only prior verified positive signals when a feed is unavailable."""
    merged = dict(current)
    stale: list[str] = []
    prior_stale = set(prior.get("stale_providers") or [])
    if current.get("nvd_status") == "unavailable" and (
        prior.get("nvd_status") == "complete" or "nvd" in prior_stale
    ):
        cvss = _bounded(prior.get("cvss_score"), 10.0)
        if cvss is not None:
            merged["cvss_score"] = cvss
            stale.append("nvd")
        if prior.get("exploit_available") is True:
            merged["exploit_available"] = True
            merged["exploit_references"] = list(prior.get("exploit_references") or [])[:5]
            if "nvd" not in stale:
                stale.append("nvd")
    if current.get("kev_status") == "unavailable" and (
        prior.get("kev_status") == "complete" or "kev" in prior_stale
    ) and prior.get("in_kev") is True:
        merged["in_kev"] = True
        if prior.get("ransomware_use") is True:
            merged["ransomware_use"] = True
        stale.append("kev")
    if stale:
        merged["stale_providers"] = stale
    return merged


def verified_intel_evidence(snapshots: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Feed only verified, current values into scoring; unavailable stays unknown."""
    evidence: list[dict[str, Any]] = []
    for snapshot in snapshots.values():
        item: dict[str, Any] = {}
        stale = set(snapshot.get("stale_providers") or [])
        if snapshot.get("nvd_status") == "complete" or "nvd" in stale:
            cvss = _bounded(snapshot.get("cvss_score"), 10.0)
            if cvss is not None:
                item["cvss_score"] = cvss
            if snapshot.get("exploit_available") is True:
                item["exploit_available"] = True
        if snapshot.get("kev_status") == "complete" or "kev" in stale:
            if isinstance(snapshot.get("in_kev"), bool):
                item["in_kev"] = snapshot["in_kev"]
                item["observed_in_the_wild"] = snapshot["in_kev"]
            if snapshot.get("ransomware_use") is True:
                item["ransomware_use"] = True
        if snapshot.get("epss_status") == "complete":
            epss = _bounded(snapshot.get("epss_score"), 1.0)
            if epss is not None:
                item["epss_score"] = epss
        if item:
            evidence.append(item)
    return evidence


def with_stale_intel_provenance(
    factors: dict[str, Any], snapshots: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    stale_sources = {
        cve: snapshot["stale_providers"]
        for cve, snapshot in snapshots.items()
        if snapshot.get("stale_providers")
    }
    return {**factors, "intelligence_stale_providers": stale_sources} if stale_sources else factors


class _UnavailableNVD:
    async def get_cve(self, _cve_id: str) -> None:
        raise IntegrationNotConfiguredError("nvd")

    async def aclose(self) -> None:
        return None


async def refresh_stale_intel_batch(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Any | None = None,
    limit: int = 3,
    now: dt.datetime | None = None,
) -> int:
    """Refresh a locked page of canonical CVE exposures and immediately re-score them."""
    if not 1 <= limit <= 10:
        raise ValueError("intelligence refresh batch size must be between 1 and 10")
    now = now or dt.datetime.now(dt.UTC)
    if now.tzinfo is None:
        raise ValueError("refresh time must be timezone-aware")
    age_seconds = max(3600, int(settings.intel.canonical_refresh_seconds))
    cutoff = now - dt.timedelta(seconds=age_seconds)
    rows = (
        await session.execute(
            select(CanonicalFinding, Organization, Asset)
            .join(Organization, CanonicalFinding.organization_id == Organization.id)
            .join(
                Asset,
                and_(
                    Asset.id == CanonicalFinding.asset_id,
                    Asset.organization_id == CanonicalFinding.organization_id,
                ),
            )
            .where(
                Organization.is_active.is_(True),
                CanonicalFinding.status.in_(("new", "open", "reopened", "mitigated")),
                CanonicalFinding.cve_ids != [],
                or_(
                    CanonicalFinding.intel_refreshed_at.is_(None),
                    CanonicalFinding.intel_refreshed_at < cutoff,
                ),
            )
            .order_by(CanonicalFinding.intel_refreshed_at.asc().nullsfirst(), CanonicalFinding.id)
            .limit(limit)
            .with_for_update(of=CanonicalFinding, skip_locked=True)
        )
    ).all()
    if not rows:
        return 0
    finding_ids = [finding.id for finding, _, _ in rows]
    observations = (
        (
            await session.execute(
                select(FindingObservation)
                .join(
                    CanonicalFinding,
                    and_(
                        FindingObservation.canonical_finding_id == CanonicalFinding.id,
                        FindingObservation.organization_id == CanonicalFinding.organization_id,
                    ),
                )
                .where(
                    FindingObservation.canonical_finding_id.in_(finding_ids),
                    FindingObservation.source_status.not_in(("absent", "superseded")),
                )
            )
        )
        .scalars()
        .all()
    )
    evidence_by_finding: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        evidence_by_finding[observation.canonical_finding_id].append(observation.evidence or {})

    nvd_by_tenant: dict[uuid.UUID, Any] = {}
    kev = KEVClient(settings, redis)
    epss = EPSSClient(settings, redis)
    try:
        for finding, organization, asset in rows:
            nvd = nvd_by_tenant.get(finding.organization_id)
            if nvd is None:
                principal = Principal(
                    user_id=None, organization_id=finding.organization_id,
                    role=Role.OWNER, actor_type=ACTOR_WORKER,
                )
                try:
                    scoped = await resolve_settings(
                        session, principal, IntegrationKind.NVD,
                        settings=settings, mark_used=False,
                    )
                    nvd = NVDClient(scoped, redis)
                except CynuxError:
                    nvd = _UnavailableNVD()
                nvd_by_tenant[finding.organization_id] = nvd
            cve_ids = list(dict.fromkeys(
                normalize_cve(cve) for cve in (finding.cve_ids or [])
                if isinstance(cve, str) and CVE_RE.fullmatch(normalize_cve(cve))
            ))[:5]
            prior_snapshots = finding.intel_evidence or {}
            snapshots = {}
            for cve in cve_ids:
                current = await fetch_cve_intelligence(cve, nvd=nvd, kev=kev, epss=epss)
                prior = prior_snapshots.get(cve)
                snapshots[cve] = merge_last_known_intelligence(
                    current, prior if isinstance(prior, dict) else {}
                )
            finding.intel_evidence = snapshots
            finding.intel_refreshed_at = now
            finding.risk_score, finding.risk_factors = score_canonical(
                finding.severity,
                asset,
                [*evidence_by_finding.get(finding.id, []), *verified_intel_evidence(snapshots)],
                load_policy(organization).risk_weights,
            )
            finding.risk_factors = with_stale_intel_provenance(finding.risk_factors, snapshots)
            finding.risk_policy_version = organization.risk_policy_version
        await session.flush()
    finally:
        await asyncio.gather(
            *(client.aclose() for client in nvd_by_tenant.values()),
            kev.aclose(), epss.aclose(),
            return_exceptions=True,
        )
    return len(rows)
