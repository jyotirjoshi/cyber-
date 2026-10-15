"""Normalized multi-source threat observations and deterministic aggregation."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.db.models.threat_intelligence import (
    ThreatActor,
    ThreatObservation,
    ThreatWatchlist,
    ThreatWatchlistMatch,
)
from app.db.repository import tenant_select
from app.schemas.threat_intelligence import ThreatWatchlistCreateIn
from app.services.context import Principal

SOURCE_PRIORITY: dict[str, int] = {
    "cisa_kev": 100,
    "nvd": 90,
    "epss": 85,
    "github_advisory": 75,
    "ransomware_feed": 70,
    "community": 20,
}
_BOOLEAN_FACTS = frozenset({"exploited", "ransomware_use", "exploit_available"})
_SCORE_FACTS = {"cvss_score": 10.0, "epss_score": 1.0, "confidence": 1.0}


@dataclass(frozen=True)
class ThreatFeedObservation:
    entity_type: str
    entity_key: str
    source: str
    source_reference: str
    confidence: float
    observed_at: dt.datetime
    facts: dict[str, Any]
    published_at: dt.datetime | None = None
    freshness: str = "fresh"
    license_reference: str | None = None


@dataclass(frozen=True)
class MergedThreatIntelligence:
    entity_type: str
    entity_key: str
    facts: dict[str, Any]
    fact_confidence: dict[str, float]
    fact_sources: dict[str, str]
    provenance: tuple[ThreatFeedObservation, ...]
    freshness: str
    merged_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.UTC))


def _valid_fact(name: str, value: Any) -> bool:
    if name in _BOOLEAN_FACTS:
        return isinstance(value, bool)
    if name in _SCORE_FACTS:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and 0 <= float(value) <= _SCORE_FACTS[name]
        )
    if isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return len(value) <= 100 and all(isinstance(item, str) for item in value)
    return False


def _rank(observation: ThreatFeedObservation) -> tuple[float, int, float, str]:
    timestamp = observation.observed_at.timestamp() if observation.observed_at.tzinfo else 0.0
    return (
        max(0.0, min(1.0, float(observation.confidence))),
        SOURCE_PRIORITY.get(observation.source, 0),
        timestamp,
        observation.source,
    )


def merge_observations(
    observations: Iterable[ThreatFeedObservation],
) -> MergedThreatIntelligence:
    rows = tuple(observations)
    if not rows:
        raise ValueError("at least one threat observation is required")
    identity = (rows[0].entity_type, rows[0].entity_key.casefold())
    if any((row.entity_type, row.entity_key.casefold()) != identity for row in rows):
        raise ValueError("threat observations must describe one entity")
    winners: dict[str, tuple[ThreatFeedObservation, Any]] = {}
    for row in rows:
        if row.freshness not in {"fresh", "stale"}:
            raise ValueError("observation freshness must be fresh or stale")
        if row.observed_at.tzinfo is None:
            raise ValueError("observation timestamps must be timezone-aware")
        for name, value in row.facts.items():
            if not _valid_fact(name, value):
                continue
            previous = winners.get(name)
            if previous is None or _rank(row) > _rank(previous[0]):
                winners[name] = (row, value)
    ordered = tuple(sorted(rows, key=lambda row: (row.source, row.source_reference)))
    freshness_values = {row.freshness for row in rows}
    freshness = "partial" if len(freshness_values) > 1 else next(iter(freshness_values))
    return MergedThreatIntelligence(
        entity_type=rows[0].entity_type,
        entity_key=rows[0].entity_key.upper() if rows[0].entity_type == "cve" else rows[0].entity_key,
        facts={name: value for name, (_, value) in sorted(winners.items())},
        fact_confidence={
            name: max(0.0, min(1.0, float(row.confidence)))
            for name, (row, _) in sorted(winners.items())
        },
        fact_sources={name: row.source for name, (row, _) in sorted(winners.items())},
        provenance=ordered,
        freshness=freshness,
    )


def normalize_entity_key(entity_type: str, entity_key: str) -> str:
    value = entity_key.strip()
    if not value or len(value) > 512:
        raise ValueError("invalid threat entity key")
    if entity_type in {"cve", "domain"}:
        return value.upper() if entity_type == "cve" else value.casefold().rstrip(".")
    return value.casefold()


async def create_watchlist(
    session: AsyncSession, principal: Principal, payload: ThreatWatchlistCreateIn
) -> ThreatWatchlist:
    principal.require(Permission.FINDING_ANALYZE)
    row = ThreatWatchlist(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        entity_type=payload.entity_type,
        entity_key=normalize_entity_key(payload.entity_type, payload.entity_key),
        label=payload.label.strip() if payload.label else None,
        is_active=True,
    )
    session.add(row)
    await session.flush()
    existing = await session.scalars(
        select(ThreatObservation)
        .where(
            ThreatObservation.entity_type == row.entity_type,
            ThreatObservation.entity_key == row.entity_key,
        )
        .order_by(ThreatObservation.observed_at.desc())
        .limit(100)
    )
    for observation in existing.all():
        await _match_active_watchlists(
            session, observation, now=dt.datetime.now(dt.UTC)
        )
    return row


async def delete_watchlist(
    session: AsyncSession, principal: Principal, watchlist_id: uuid.UUID
) -> None:
    principal.require(Permission.FINDING_ANALYZE)
    row = await session.scalar(
        tenant_select(ThreatWatchlist, principal.organization_id).where(
            ThreatWatchlist.id == watchlist_id
        )
    )
    if row is None:
        raise ResourceNotFoundError("Threat watchlist not found")
    await session.delete(row)


async def ingest_observation(
    session: AsyncSession,
    observation: ThreatFeedObservation,
    *,
    now: dt.datetime | None = None,
) -> tuple[ThreatObservation, int]:
    """Persist immutable provenance, match tenant inventory, and invalidate risk caches."""
    now = now or dt.datetime.now(dt.UTC)
    entity_key = normalize_entity_key(observation.entity_type, observation.entity_key)
    # Running the merge validates timestamps, freshness and fact types. Invalid
    # provider fields are dropped rather than becoming tenant-visible assertions.
    validated = merge_observations([observation])
    statement = (
        insert(ThreatObservation)
        .values(
            id=uuid.uuid4(),
            entity_type=observation.entity_type,
            entity_key=entity_key,
            source=observation.source,
            source_reference=observation.source_reference,
            confidence=max(0.0, min(1.0, observation.confidence)),
            facts=validated.facts,
            observed_at=observation.observed_at,
            published_at=observation.published_at,
            freshness=observation.freshness,
            license_reference=observation.license_reference,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_nothing(constraint="unique_threat_observation_source_reference")
        .returning(ThreatObservation.id)
    )
    observation_id = (await session.execute(statement)).scalar_one_or_none()
    if observation_id is None:
        persisted = await session.scalar(
            select(ThreatObservation).where(
                ThreatObservation.source == observation.source,
                ThreatObservation.source_reference == observation.source_reference,
            )
        )
        if persisted is None:
            raise RuntimeError("threat observation conflict without existing row")
        return persisted, 0
    persisted = await session.get(ThreatObservation, observation_id)
    assert persisted is not None
    if persisted.entity_type == "actor":
        name = persisted.facts.get("name")
        if isinstance(name, str) and name.strip():
            await session.execute(
                insert(ThreatActor)
                .values(
                    id=uuid.uuid4(),
                    slug=persisted.entity_key,
                    name=name.strip()[:255],
                    aliases=list(persisted.facts.get("aliases") or [])[:100],
                    references=list(persisted.facts.get("references") or [])[:100],
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_update(
                    index_elements=[ThreatActor.slug],
                    set_={
                        "name": name.strip()[:255],
                        "aliases": list(persisted.facts.get("aliases") or [])[:100],
                        "references": list(persisted.facts.get("references") or [])[:100],
                        "updated_at": now,
                    },
                )
            )
    matches = await _match_active_watchlists(session, persisted, now=now)
    return persisted, matches


def normalize_github_advisory(payload: dict[str, Any], *, observed_at: dt.datetime) -> list[ThreatFeedObservation]:
    """Normalize one GitHub Security Advisory response without retaining its raw body."""
    advisory_id = payload.get("ghsa_id")
    if not isinstance(advisory_id, str) or not advisory_id.startswith("GHSA-"):
        return []
    references = [
        item.get("url") for item in payload.get("references", [])
        if isinstance(item, dict) and isinstance(item.get("url"), str)
    ][:20]
    cves = [
        item.get("value", "").upper()
        for item in payload.get("identifiers", [])
        if isinstance(item, dict) and item.get("type") == "CVE"
    ]
    return [
        ThreatFeedObservation(
            entity_type="cve",
            entity_key=cve,
            source="github_advisory",
            source_reference=f"github:{advisory_id}:{cve}",
            confidence=0.85,
            observed_at=observed_at,
            published_at=None,
            facts={"advisory_id": advisory_id, "exploit_references": references},
            license_reference="https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features",
        )
        for cve in cves
        if cve.startswith("CVE-")
    ]


def normalize_ransomware_record(payload: dict[str, Any], *, observed_at: dt.datetime, source: str) -> list[ThreatFeedObservation]:
    """Normalize a licensed ransomware/actor feed record into actor and CVE facts."""
    actor = payload.get("actor")
    cves = payload.get("cve_ids")
    if not isinstance(actor, str) or not actor.strip() or not isinstance(cves, list):
        return []
    normalized_cves = sorted({str(cve).upper() for cve in cves if str(cve).upper().startswith("CVE-")})[:100]
    if not normalized_cves:
        return []
    actor_slug = "-".join(actor.casefold().split())[:160]
    reference = str(payload.get("reference") or f"{source}:{actor_slug}:{observed_at.date().isoformat()}")
    rows = [
        ThreatFeedObservation(
            entity_type="actor",
            entity_key=actor_slug,
            source=source,
            source_reference=f"{reference}:actor",
            confidence=float(payload.get("confidence", 0.7)),
            observed_at=observed_at,
            facts={"name": actor.strip(), "cve_ids": normalized_cves, "aliases": list(payload.get("aliases") or [])[:100], "references": [reference]},
            license_reference=str(payload.get("license_reference") or "provider-license"),
        )
    ]
    rows.extend(
        ThreatFeedObservation(
            entity_type="cve",
            entity_key=cve,
            source=source,
            source_reference=f"{reference}:{cve}",
            confidence=float(payload.get("confidence", 0.7)),
            observed_at=observed_at,
            facts={"ransomware_use": True, "threat_actors": [actor.strip()]},
            license_reference=str(payload.get("license_reference") or "provider-license"),
        )
        for cve in normalized_cves
    )
    return rows


async def _match_active_watchlists(
    session: AsyncSession, observation: ThreatObservation, *, now: dt.datetime
) -> int:
    watchlists = list(
        (
            await session.scalars(
                select(ThreatWatchlist).where(
                    ThreatWatchlist.is_active.is_(True),
                    ThreatWatchlist.entity_type == observation.entity_type,
                    ThreatWatchlist.entity_key == observation.entity_key,
                )
            )
        ).all()
    )
    created = 0
    for watch in watchlists:
        findings: list[CanonicalFinding] = []
        assets: list[Asset] = []
        if watch.entity_type == "cve":
            findings = list(
                (
                    await session.scalars(
                        tenant_select(CanonicalFinding, watch.organization_id).where(
                            CanonicalFinding.cve_ids.contains([watch.entity_key])
                        )
                    )
                ).all()
            )
        elif watch.entity_type == "product":
            assets = list(
                (
                    await session.scalars(
                        tenant_select(Asset, watch.organization_id).where(
                            Asset.technology.contains([watch.entity_key])
                        )
                    )
                ).all()
            )
        elif watch.entity_type in {"domain", "brand"}:
            assets = list(
                (
                    await session.scalars(
                        tenant_select(Asset, watch.organization_id).where(
                            Asset.name.ilike(f"%{watch.entity_key}%")
                        )
                    )
                ).all()
            )
        cve_ids = observation.facts.get("cve_ids", [])
        if watch.entity_type == "actor" and isinstance(cve_ids, list):
            findings = list(
                (
                    await session.scalars(
                        tenant_select(CanonicalFinding, watch.organization_id).where(
                            or_(*(CanonicalFinding.cve_ids.contains([str(cve).upper()]) for cve in cve_ids[:100]))
                        )
                    )
                ).all()
            ) if cve_ids else []
        for finding in findings:
            inserted = await _insert_match(
                session, watch, observation, f"finding:{finding.id}", now,
                canonical_finding_id=finding.id, asset_id=finding.asset_id,
            )
            finding.intel_refreshed_at = None
            created += int(inserted)
        for asset in assets:
            inserted = await _insert_match(
                session, watch, observation, f"asset:{asset.id}", now, asset_id=asset.id
            )
            created += int(inserted)
        if findings or assets:
            watch.last_matched_at = now
    return created


async def _insert_match(
    session: AsyncSession,
    watch: ThreatWatchlist,
    observation: ThreatObservation,
    match_key: str,
    now: dt.datetime,
    *,
    canonical_finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
) -> bool:
    inserted_id = (await session.execute(
        insert(ThreatWatchlistMatch)
        .values(
            id=uuid.uuid4(),
            organization_id=watch.organization_id,
            watchlist_id=watch.id,
            observation_id=observation.id,
            canonical_finding_id=canonical_finding_id,
            asset_id=asset_id,
            match_key=match_key,
            matched_at=now,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_nothing(constraint="unique_threat_watchlist_match")
        .returning(ThreatWatchlistMatch.id)
    )).scalar_one_or_none()
    return inserted_id is not None


__all__ = [
    "MergedThreatIntelligence",
    "SOURCE_PRIORITY",
    "ThreatFeedObservation",
    "create_watchlist",
    "delete_watchlist",
    "ingest_observation",
    "merge_observations",
    "normalize_github_advisory",
    "normalize_entity_key",
    "normalize_ransomware_record",
]
