"""Bounded background refresh for scores stale after tenant policy changes."""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.identity import Organization
from app.services.canonical_intel_refresh import (
    verified_intel_evidence,
    with_stale_intel_provenance,
)
from app.services.canonical_risk import score_canonical
from app.services.organization import load_policy


async def refresh_stale_risk_batch(session: AsyncSession, *, limit: int = 100) -> int:
    """Recalculate one locked page; the caller commits before requesting another.

    ``SKIP LOCKED`` allows multiple workers to share the backlog without re-scoring
    the same row. A policy change that lands during a batch increments the tenant's
    version again, so the next sweep still recognizes that row as stale.
    """
    if not 1 <= limit <= 500:
        raise ValueError("risk refresh batch size must be between 1 and 500")
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
                CanonicalFinding.status != "closed",
                CanonicalFinding.risk_policy_version < Organization.risk_policy_version,
            )
            .order_by(CanonicalFinding.organization_id, CanonicalFinding.id)
            .limit(limit)
            .with_for_update(of=CanonicalFinding, skip_locked=True)
        )
    ).all()
    if not rows:
        return 0
    finding_ids = {finding.id for finding, _, _ in rows}
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
    evidence_by_finding: dict[object, list[dict]] = defaultdict(list)
    for observation in observations:
        evidence_by_finding[observation.canonical_finding_id].append(observation.evidence or {})
    for finding, organization, asset in rows:
        finding.risk_score, finding.risk_factors = score_canonical(
            finding.severity,
            asset,
            [
                *evidence_by_finding.get(finding.id, []),
                *verified_intel_evidence(finding.intel_evidence or {}),
            ],
            load_policy(organization).risk_weights,
        )
        finding.risk_factors = with_stale_intel_provenance(
            finding.risk_factors, finding.intel_evidence or {}
        )
        finding.risk_policy_version = organization.risk_policy_version
    await session.flush()
    return len(rows)
