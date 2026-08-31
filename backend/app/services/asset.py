"""Asset inventory, criticality inference, and FR-010 scope selection.

Three ideas, each with a reason it is done the way it is.

**Deduplication is per organization, not per assessment.**  :func:`upsert_assets` merges on
``(name, port, protocol)`` -- the ``unique_asset`` constraint -- so a subdomain rediscovered
by the third assessment this quarter is one row with three entries in
``seen_in_assessments``.  Per-assessment rows would make "when did we first see this host"
unanswerable, which is the question that distinguishes an inventory from a scan log.

**Criticality never silently claims to be curated.**  :func:`infer_criticality` returns the
:class:`~app.db.enums.CriticalitySource` alongside the value, and an operator tag always
wins over a keyword guess.  FR-022's point is that business context comes from the business;
an inferred value that rendered identically to a curated one would quietly launder a guess
into a fact.

**Selection is explainable and bounded.**  :func:`score_and_select` writes
``selection_rationale`` for every asset it selects and refuses to exceed the scope budget.
FR-010 requires the operator to see why each asset is in scope before they approve it, and
an unexplained selection cannot be meaningfully approved.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence
from typing import Any

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import ConflictError, UserError
from app.db.enums import (
    AssetStatus,
    Criticality,
    CriticalitySource,
    Permission,
)
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset, AssetTag
from app.db.repository import TenantRepository, tenant_select
from app.scanners.recon_assets import DiscoveredAsset
from app.schemas.asset import AssetCriticalityIn, AssetFilter, AssetTagIn
from app.schemas.common import PaginationParams
from app.services import audit as audit_service
from app.services.context import Principal

log = structlog.get_logger(__name__)

#: Tag keys that set criticality directly. An operator writing ``criticality: high`` on an
#: asset means it, and a keyword heuristic must not be allowed to argue.
_CRITICALITY_TAG_KEYS: frozenset[str] = frozenset({"criticality", "critical", "tier"})

#: Tag values recognised as criticality levels, plus the shorthand operators actually type.
_TAG_VALUE_CRITICALITY: dict[str, Criticality] = {
    "critical": Criticality.CRITICAL,
    "high": Criticality.HIGH,
    "normal": Criticality.NORMAL,
    "medium": Criticality.NORMAL,
    "low": Criticality.LOW,
    "tier0": Criticality.CRITICAL,
    "tier1": Criticality.HIGH,
    "tier2": Criticality.NORMAL,
    "tier3": Criticality.LOW,
    "prod": Criticality.HIGH,
    "production": Criticality.HIGH,
    "staging": Criticality.LOW,
    "dev": Criticality.LOW,
    "test": Criticality.LOW,
}

#: Substrings that mark a host as non-production, which lowers rather than raises its score.
#: Kept separate from the keyword list in settings: that list is what an operator tunes to
#: describe *their* naming, while these are near-universal.
_NONPROD_MARKERS: tuple[str, ...] = ("dev", "test", "staging", "stage", "qa", "sandbox", "uat")

#: Ports that make an asset materially more interesting to scan. Weighted, not gating -- an
#: unusual port is still scanned, it just does not outrank an exposed admin panel.
_NOTABLE_PORTS: dict[int, float] = {
    21: 0.10,
    22: 0.05,
    23: 0.15,
    80: 0.10,
    443: 0.10,
    445: 0.15,
    1433: 0.12,
    3306: 0.12,
    3389: 0.15,
    5432: 0.12,
    6379: 0.15,
    8080: 0.10,
    8443: 0.10,
    9200: 0.15,
    27017: 0.15,
}

#: Cap on ``seen_in_assessments``. An asset in a weekly assessment accumulates 52 ids a
#: year; the recent ones answer "is this still live", which is what the column is for.
_MAX_SEEN_HISTORY = 50


async def upsert_assets(
    session: AsyncSession,
    assessment: Assessment,
    records: Sequence[DiscoveredAsset],
) -> list[Asset]:
    """Merge discovered assets into the organization's inventory.

    Existing rows are updated in place and gain the assessment id in
    ``seen_in_assessments``; new rows are created.  Returns every asset touched, in the
    order the records arrived, so the caller can report discovery counts truthfully.

    Merging is by ``(name, port, protocol)`` because that is the unique constraint.  A
    record whose port is ``None`` and one with port 443 for the same host are *different*
    assets: the bare hostname is the DNS-level finding, the port is the service-level one,
    and collapsing them would lose the distinction that decides which scanner runs.
    """
    if not records:
        return []

    merged = _merge_duplicates(records)
    keys = {(r.name, r.port, r.protocol) for r in merged}
    existing = await _load_by_keys(session, assessment.organization_id, keys)

    now = _now()
    assessment_id = str(assessment.id)
    touched: list[Asset] = []

    for record in merged:
        key = (record.name, record.port, record.protocol)
        asset = existing.get(key)
        if asset is None:
            asset = Asset(
                organization_id=assessment.organization_id,
                assessment_id=assessment.id,
                name=record.name[:512],
                asset_type=record.asset_type,
                status=record.status,
                first_seen_at=now,
                criticality=Criticality.UNKNOWN.value,
                criticality_source=CriticalitySource.DEFAULT.value,
                evidence={},
                seen_in_assessments=[],
                technology=[],
            )
            session.add(asset)
            existing[key] = asset

        _apply_record(asset, record, assessment_id=assessment_id, now=now)
        touched.append(asset)

    # Flushed so ``asset.id`` is available to the caller -- the approval payload is built
    # from these ids, and a pending row has none.
    await session.flush()

    assessment.assets_discovered = await _count_assets(session, assessment.id)
    log.info(
        "assets.upserted",
        assessment_id=assessment_id,
        discovered=len(records),
        merged=len(merged),
        touched=len(touched),
    )
    return touched


async def score_and_select(
    session: AsyncSession,
    assessment: Assessment,
    *,
    budget: int,
    settings: Settings,
) -> list[Asset]:
    """Score this assessment's assets and select the top ``budget`` for scanning (FR-010).

    Scoring is deterministic and local -- exposure, criticality, notable ports, detected
    technology, freshness.  No model is consulted, for two reasons: the ranking has to be
    reproducible when an operator asks why an asset was picked, and a scope decision is
    exactly the kind of thing that must not vary with a sampling temperature.  The agent's
    contribution is the *narrative* around the selection, not the selection.

    Everything not selected is left with ``selected_for_scanning=False`` and its score, so
    the operator can see the assets that just missed the cut and widen the budget.
    """
    if budget <= 0:
        raise UserError(
            "scope budget must be positive",
            user_message="The number of assets to scan must be at least one.",
            context={"assessment_id": str(assessment.id), "budget": budget},
        )
    budget = min(budget, settings.agent.max_scope_budget)

    assets = list(
        (
            await session.execute(
                tenant_select(Asset, assessment.organization_id, selectinload(Asset.tags))
                # Filter on seen_in_assessments membership, NOT the assessment_id
                # first-discovery FK: assessment_id is never re-pointed, so a
                # re-scan of a known target would otherwise score zero assets.
                .where(
                    Asset.seen_in_assessments.contains([str(assessment.id)]),
                    Asset.status != AssetStatus.OUT_OF_SCOPE.value,
                )
                .order_by(Asset.name, Asset.port)
            )
        )
        .scalars()
        .all()
    )
    if not assets:
        assessment.assets_in_scope = 0
        return []

    scored: list[tuple[float, Asset]] = []
    for asset in assets:
        criticality, source, rationale = await infer_criticality(asset, settings)
        asset.criticality = criticality.value
        asset.criticality_source = source.value
        asset.criticality_rationale = rationale
        score, reasons = _score(asset, settings)
        asset.risk_score = score
        # Stored on every asset, selected or not: the rationale explains the score, and the
        # score is what the operator is being asked to trust.
        asset.selection_rationale = "; ".join(reasons) if reasons else "No risk signals observed."
        asset.selected_for_scanning = False
        scored.append((score, asset))

    # ``name``/``port`` as the tie-break keeps the order stable across runs, so re-running
    # a plan does not silently reshuffle which assets made the cut.
    scored.sort(key=lambda pair: (-pair[0], pair[1].name, pair[1].port or 0))
    selected = [asset for _, asset in scored[:budget]]
    for asset in selected:
        asset.selected_for_scanning = True

    assessment.assets_in_scope = len(selected)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSET_SCOPE_SELECT,
        principal=None,
        organization_id=assessment.organization_id,
        resource_type="assessment",
        resource_id=assessment.id,
        detail={
            "candidates": len(assets),
            "budget": budget,
            "selected": len(selected),
            "top_score": round(scored[0][0], 4) if scored else 0.0,
            "cutoff_score": round(scored[min(budget, len(scored)) - 1][0], 4) if scored else 0.0,
        },
    )
    log.info(
        "assets.selected",
        assessment_id=str(assessment.id),
        candidates=len(assets),
        selected=len(selected),
        budget=budget,
    )
    return selected


async def infer_criticality(
    asset: Asset,
    settings: Settings,
) -> tuple[Criticality, CriticalitySource, str]:
    """Decide an asset's criticality, reporting where the answer came from (FR-022).

    Precedence: an operator tag, then a keyword in the hostname, then observed internet
    exposure, then the default.  An already-curated value is returned untouched -- once a
    human has said a host is critical, no later inference gets to disagree.

    ``asset.tags`` must be loaded.  ``lazy="raise_on_sql"`` makes that explicit rather than
    letting the function emit a query per asset inside the selection loop.
    """
    if asset.criticality_source == CriticalitySource.OPERATOR_TAG.value:
        return (
            asset.criticality_enum,
            CriticalitySource.OPERATOR_TAG,
            asset.criticality_rationale or "Set by an operator.",
        )

    tagged = _criticality_from_tags(asset)
    if tagged is not None:
        criticality, tag = tagged
        return (
            criticality,
            CriticalitySource.OPERATOR_TAG,
            f"Operator tag {tag} marks this asset {criticality.value}.",
        )

    keyword = _matched_keyword(asset.name, settings.agent.criticality_keywords)
    if keyword is not None:
        level = Criticality.LOW if _is_nonprod(asset.name) else Criticality.HIGH
        detail = (
            f'Name contains "{keyword}", but also looks non-production.'
            if level is Criticality.LOW
            else f'Name contains "{keyword}", which suggests a sensitive service.'
        )
        return level, CriticalitySource.INFERRED_KEYWORD, detail

    if asset.internet_exposed:
        return (
            Criticality.NORMAL,
            CriticalitySource.INFERRED_EXPOSURE,
            "Reachable from the internet, so treated as normal rather than unknown.",
        )

    return (
        Criticality.UNKNOWN,
        CriticalitySource.DEFAULT,
        "No operator tag and no signal in the name or exposure. Tag it to improve ranking.",
    )


async def tag_asset(
    session: AsyncSession,
    principal: Principal,
    asset_id: uuid.UUID,
    payload: AssetTagIn,
) -> AssetTag:
    """Apply (or update) an operator tag.

    Upserts on ``(asset_id, key)``: re-tagging with a new value is the common case and
    should not be a constraint violation.  ``is_operator_applied`` is forced true because
    this path is only reachable from an authenticated human -- inference writes tags through
    :func:`infer_criticality`, which does not touch this table at all.
    """
    principal.require(Permission.ASSET_TAG)
    repo: TenantRepository[Asset] = TenantRepository(session, Asset, principal.organization_id)
    asset = await repo.get_or_404(asset_id)

    key = payload.key.strip().lower()
    existing = (
        await session.execute(
            select(AssetTag).where(AssetTag.asset_id == asset.id, AssetTag.key == key)
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.value = payload.value
        existing.applied_by_id = principal.user_id
        existing.is_operator_applied = True
        tag = existing
    else:
        tag = AssetTag(
            organization_id=principal.organization_id,
            asset_id=asset.id,
            key=key,
            value=payload.value,
            applied_by_id=principal.user_id,
            is_operator_applied=True,
        )
        session.add(tag)
        await session.flush()

    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSET_TAG,
        principal=principal,
        resource_type="asset",
        resource_id=asset.id,
        detail={"key": key, "value": payload.value, "replaced": existing is not None},
    )
    return tag


async def set_criticality(
    session: AsyncSession,
    principal: Principal,
    asset_id: uuid.UUID,
    payload: AssetCriticalityIn,
) -> Asset:
    """Operator override of criticality (FR-009).

    Writes ``CriticalitySource.OPERATOR_TAG``, which is what makes the value survive the
    next :func:`infer_criticality` pass.  The rationale is stored verbatim and audited: an
    override changes which assets get scanned, so it needs to be attributable.
    """
    principal.require(Permission.ASSET_TAG)
    repo: TenantRepository[Asset] = TenantRepository(session, Asset, principal.organization_id)
    asset = await repo.get_or_404(asset_id)
    previous = asset.criticality

    asset.criticality = payload.criticality.value
    asset.criticality_source = CriticalitySource.OPERATOR_TAG.value
    asset.criticality_rationale = (
        payload.rationale or f"Set to {payload.criticality.value} by an operator."
    )

    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSET_CRITICALITY_SET,
        principal=principal,
        resource_type="asset",
        resource_id=asset.id,
        reason=payload.rationale,
        detail={"from": previous, "to": asset.criticality},
    )
    return asset


async def get_asset(
    session: AsyncSession,
    principal: Principal,
    asset_id: uuid.UUID,
) -> Asset:
    """One asset with its tags, tenant-scoped."""
    principal.require(Permission.ASSET_READ)
    repo: TenantRepository[Asset] = TenantRepository(session, Asset, principal.organization_id)
    return await repo.get_or_404(asset_id, selectinload(Asset.tags))


async def list_assets(
    session: AsyncSession,
    principal: Principal,
    *,
    filters: AssetFilter | None = None,
    pagination: PaginationParams | None = None,
) -> tuple[Sequence[Asset], int]:
    """Assets, highest risk first. Returns ``(rows, total)``."""
    principal.require(Permission.ASSET_READ)
    filters = filters or AssetFilter()
    page = pagination or PaginationParams()

    conditions: list[Any] = []
    if filters.criticality is not None:
        conditions.append(Asset.criticality == filters.criticality.value)
    if filters.selected is not None:
        conditions.append(Asset.selected_for_scanning.is_(filters.selected))
    if filters.internet_exposed is not None:
        conditions.append(Asset.internet_exposed.is_(filters.internet_exposed))
    if filters.status is not None:
        conditions.append(Asset.status == filters.status.value)
    if filters.assessment_id is not None:
        conditions.append(Asset.assessment_id == filters.assessment_id)
    if filters.q:
        term = f"%{_escape_like(filters.q)}%"
        conditions.append(
            or_(
                Asset.name.ilike(term, escape="\\"),
                Asset.ip_address.ilike(term, escape="\\"),
                Asset.service.ilike(term, escape="\\"),
            )
        )

    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Asset)
                .where(Asset.organization_id == principal.organization_id, *conditions)
            )
        ).scalar_one()
    )
    stmt = (
        tenant_select(Asset, principal.organization_id, selectinload(Asset.tags))
        .where(*conditions)
        .order_by(Asset.risk_score.desc(), Asset.name, Asset.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return rows, total


async def selected_assets(session: AsyncSession, assessment_id: uuid.UUID) -> list[Asset]:
    """The assets flagged for scanning, highest risk first.

    Takes no principal: the scan node calls it after re-reading the approval, and its
    authority comes from that row rather than from a user session.
    """
    stmt = (
        select(Asset)
        # seen_in_assessments membership, not the first-discovery assessment_id
        # FK: the scan node must see assets this assessment selected even when
        # another assessment first discovered them.
        .where(
            Asset.seen_in_assessments.contains([str(assessment_id)]),
            Asset.selected_for_scanning.is_(True),
        )
        .order_by(Asset.risk_score.desc(), Asset.name, Asset.id)
    )
    return list((await session.execute(stmt)).scalars().all())


async def assets_by_ids(
    session: AsyncSession,
    organization_id: uuid.UUID,
    asset_ids: Sequence[uuid.UUID],
) -> list[Asset]:
    """Load specific assets, tenant-filtered.

    Used by the scan node to resolve an approval's ``approved_payload``.  Silently drops ids
    that are not in the organization: an approval that named a foreign asset is not a partial
    authorization to be honored, and refusing the whole scan over one stale id would be worse
    than scanning the ids that are genuinely in scope.  The count difference is logged.
    """
    if not asset_ids:
        return []
    stmt = tenant_select(Asset, organization_id).where(Asset.id.in_(list(asset_ids)))
    rows = list((await session.execute(stmt)).scalars().all())
    if len(rows) != len(set(asset_ids)):
        log.warning(
            "assets.ids_not_resolved",
            organization_id=str(organization_id),
            requested=len(set(asset_ids)),
            resolved=len(rows),
        )
    return rows


async def mark_out_of_scope(
    session: AsyncSession,
    principal: Principal,
    asset_id: uuid.UUID,
    *,
    reason: str | None = None,
) -> Asset:
    """Exclude an asset from future selection.

    A separate status rather than a delete: the asset was observed, and an inventory that
    forgets what it was told to ignore will rediscover and re-propose it every assessment.
    """
    principal.require(Permission.ASSET_TAG)
    repo: TenantRepository[Asset] = TenantRepository(session, Asset, principal.organization_id)
    asset = await repo.get_or_404(asset_id)
    if asset.status == AssetStatus.OUT_OF_SCOPE.value:
        raise ConflictError(
            "asset already out of scope",
            user_message="That asset is already excluded.",
            context={"asset_id": str(asset.id)},
        )
    asset.status = AssetStatus.OUT_OF_SCOPE.value
    asset.selected_for_scanning = False
    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSET_TAG,
        principal=principal,
        resource_type="asset",
        resource_id=asset.id,
        reason=reason,
        detail={"status": asset.status},
    )
    return asset


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _merge_duplicates(records: Sequence[DiscoveredAsset]) -> list[DiscoveredAsset]:
    """Collapse records that share a key, preserving first-seen order.

    Recon emits the same host from several output files -- subdomain list, httpx probe, DNS
    resolution -- each carrying a different attribute.  ``DiscoveredAsset.merged_with``
    combines them, so the inventory gets one row holding everything observed instead of the
    last file's view overwriting the others.
    """
    order: list[tuple[str, int | None, str | None]] = []
    merged: dict[tuple[str, int | None, str | None], DiscoveredAsset] = {}
    for record in records:
        key = record.key
        if key in merged:
            merged[key] = merged[key].merged_with(record)
        else:
            merged[key] = record
            order.append(key)
    return [merged[key] for key in order]


async def _load_by_keys(
    session: AsyncSession,
    organization_id: uuid.UUID,
    keys: set[tuple[str, int | None, str | None]],
) -> dict[tuple[str, int | None, str | None], Asset]:
    """Existing inventory rows for the discovered keys, indexed by key.

    Filters on ``name`` only and matches the port/protocol in Python.  A three-column
    ``IN`` over tuples with NULLs does not do what it reads as in Postgres, and a per-record
    query would be one round trip per discovered host -- thousands, for a large recon run.
    """
    names = {name for name, _, _ in keys}
    if not names:
        return {}
    stmt = tenant_select(Asset, organization_id, selectinload(Asset.tags)).where(
        Asset.name.in_(list(names))
    )
    rows = (await session.execute(stmt)).scalars().all()
    return {(row.name, row.port, row.protocol): row for row in rows}


def _apply_record(
    asset: Asset,
    record: DiscoveredAsset,
    *,
    assessment_id: str,
    now: dt.datetime,
) -> None:
    """Fold one discovery into an asset row.

    Only ever *adds* information.  A field the record leaves empty keeps whatever an earlier
    assessment observed, because "httpx did not report a title this time" is not evidence
    that the title changed -- and treating absence as a new observation would make the
    inventory oscillate between runs.
    """
    asset.asset_type = record.asset_type or asset.asset_type
    asset.ip_address = record.ip_address or asset.ip_address
    asset.port = record.port if record.port is not None else asset.port
    asset.protocol = record.protocol or asset.protocol
    asset.service = record.service or asset.service
    asset.http_title = record.http_title or asset.http_title
    asset.http_status_code = (
        record.http_status_code if record.http_status_code is not None else asset.http_status_code
    )
    asset.tls_subject = record.tls_subject or asset.tls_subject
    asset.internet_exposed = asset.internet_exposed or record.internet_exposed
    asset.status = record.status or asset.status

    if record.technology:
        # Ordered dedup: the display order is the order things were first detected.
        combined = list(asset.technology or [])
        for tech in record.technology:
            if tech not in combined:
                combined.append(tech)
        asset.technology = combined

    if record.evidence:
        asset.evidence = {**(asset.evidence or {}), **record.evidence}

    if asset.first_seen_at is None:
        asset.first_seen_at = now
    asset.last_seen_at = now

    history = [h for h in (asset.seen_in_assessments or []) if h != assessment_id]
    history.append(assessment_id)
    asset.seen_in_assessments = history[-_MAX_SEEN_HISTORY:]


def _score(asset: Asset, settings: Settings) -> tuple[float, list[str]]:
    """Risk score in [0, 1] plus the human-readable reasons behind it.

    The reasons are returned with the number rather than derived from it, so the rationale
    cannot describe a different calculation than the one that ran.  Weights are additive and
    clamped: an asset that trips every signal saturates at 1.0 instead of dominating the
    ranking by an arbitrary multiple.
    """
    score = 0.0
    reasons: list[str] = []

    criticality = asset.criticality_enum
    weight = criticality.weight
    score += 0.40 * weight
    if criticality is not Criticality.UNKNOWN:
        reasons.append(f"Criticality {criticality.value} ({asset.criticality_source})")

    if asset.internet_exposed:
        score += 0.25
        reasons.append("Reachable from the internet")

    if asset.port is not None:
        bonus = _NOTABLE_PORTS.get(asset.port)
        if bonus is not None:
            score += bonus
            reasons.append(f"Port {asset.port} exposes a commonly attacked service")
        else:
            score += 0.03
            reasons.append(f"Port {asset.port} open")

    if asset.technology:
        score += min(0.10, 0.03 * len(asset.technology))
        reasons.append(f"Detected {', '.join(asset.technology[:3])}")

    if asset.http_status_code is not None and 200 <= asset.http_status_code < 400:
        score += 0.05
        reasons.append(f"HTTP {asset.http_status_code} responds")

    keyword = _matched_keyword(asset.name, settings.agent.criticality_keywords)
    if keyword is not None:
        score += 0.10
        reasons.append(f'Name suggests a sensitive service ("{keyword}")')

    if _is_nonprod(asset.name):
        # Subtractive rather than excluding: a vulnerable staging host still matters, it
        # just should not outrank production when the budget is tight.
        score -= 0.15
        reasons.append("Looks non-production, ranked lower")

    if asset.status != AssetStatus.ACTIVE.value:
        score -= 0.20
        reasons.append(f"Status {asset.status}")

    return max(0.0, min(1.0, round(score, 4))), reasons


def _criticality_from_tags(asset: Asset) -> tuple[Criticality, str] | None:
    """Criticality asserted by an operator tag, if any.

    Checks the dedicated keys first (``criticality: high``), then falls back to a bare tag
    whose *key* is itself a level (``production``, ``tier1``).  Only operator-applied tags
    count: an inferred tag feeding back in as an operator signal would launder a guess.
    """
    tags = [t for t in (asset.tags or []) if t.is_operator_applied]
    for tag in tags:
        if tag.key in _CRITICALITY_TAG_KEYS and tag.value:
            level = _TAG_VALUE_CRITICALITY.get(tag.value.strip().lower())
            if level is not None:
                return level, f"{tag.key}={tag.value}"
    for tag in tags:
        level = _TAG_VALUE_CRITICALITY.get(tag.key)
        if level is not None:
            return level, tag.key
    return None


def _matched_keyword(name: str, keywords: Sequence[str]) -> str | None:
    """The first configured keyword appearing in a hostname label.

    Matched against dot- and dash-separated labels rather than the raw string, so
    ``api.example.com`` matches ``api`` while ``rapidfire.example.com`` does not.  Substring
    matching on the whole name produces exactly that kind of false positive, and a
    misclassified asset changes what gets scanned.
    """
    labels = {
        label for label in name.lower().replace("-", ".").replace("_", ".").split(".") if label
    }
    for keyword in keywords:
        if keyword in labels:
            return keyword
    return None


def _is_nonprod(name: str) -> bool:
    labels = {
        label for label in name.lower().replace("-", ".").replace("_", ".").split(".") if label
    }
    return any(marker in labels for marker in _NONPROD_MARKERS)


async def _count_assets(session: AsyncSession, assessment_id: uuid.UUID) -> int:
    # Count assets this assessment touched (seen_in_assessments), not just those it first
    # discovered (assessment_id) -- otherwise assets_discovered under-counts on re-scans.
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Asset)
                .where(Asset.seen_in_assessments.contains([str(assessment_id)]))
            )
        ).scalar_one()
    )


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "assets_by_ids",
    "get_asset",
    "infer_criticality",
    "list_assets",
    "mark_out_of_scope",
    "score_and_select",
    "selected_assets",
    "set_criticality",
    "tag_asset",
    "upsert_assets",
]
