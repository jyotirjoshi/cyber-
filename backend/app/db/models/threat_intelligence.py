"""Platform-wide vulnerability intelligence snapshots.

NVD, CISA KEV, and EPSS publish public CVE facts.  Keeping one shared snapshot per
CVE avoids multiplying identical provider traffic by tenant while canonical findings
remain fully tenant-owned.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class VulnerabilityIntelligence(Base, TimestampMixin):
    __tablename__ = "vulnerability_intelligence"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    refreshed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_vulnerability_intelligence_expiry", "expires_at", "cve_id"),
    )


class ThreatObservation(Base, TimestampMixin):
    """Immutable provider fact; aggregation never destroys conflicting provenance."""

    __tablename__ = "threat_observations"

    id: Mapped[uuid.UUID] = uuid_pk()
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(1024), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    facts: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    freshness: Mapped[str] = mapped_column(String(20), nullable=False, default="fresh")
    license_reference: Mapped[str | None] = mapped_column(String(1024))

    __table_args__ = (
        CheckConstraint("entity_type IN ('cve','product','actor','domain','brand')", name="valid_threat_entity_type"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_threat_observation_confidence"),
        CheckConstraint("freshness IN ('fresh','stale')", name="valid_threat_observation_freshness"),
        UniqueConstraint("source", "source_reference", name="unique_threat_observation_source_reference"),
        Index("ix_threat_observations_entity_time", "entity_type", "entity_key", "observed_at"),
    )


class ThreatActor(Base, TimestampMixin):
    __tablename__ = "threat_actors"

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    references: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)


class RansomwareAssociation(Base, TimestampMixin):
    __tablename__ = "ransomware_associations"

    id: Mapped[uuid.UUID] = uuid_pk()
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    threat_actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="SET NULL")
    )
    family: Mapped[str | None] = mapped_column(String(255))
    source_observation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("threat_observations.id", ondelete="CASCADE"), nullable=False
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    __table_args__ = (
        UniqueConstraint("cve_id", "source_observation_id", name="unique_ransomware_observation"),
        Index("ix_ransomware_associations_cve", "cve_id", "active"),
    )


class ThreatWatchlist(Base, TenantMixin, TimestampMixin):
    __tablename__ = "threat_watchlists"

    id: Mapped[uuid.UUID] = uuid_pk()
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    last_matched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("entity_type IN ('cve','product','actor','domain','brand')", name="valid_watchlist_entity_type"),
        UniqueConstraint("organization_id", "entity_type", "entity_key", name="unique_tenant_threat_watch"),
        Index("ix_threat_watchlists_org_active", "organization_id", "is_active"),
    )


class ThreatWatchlistMatch(Base, TenantMixin, TimestampMixin):
    __tablename__ = "threat_watchlist_matches"

    id: Mapped[uuid.UUID] = uuid_pk()
    watchlist_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("threat_watchlists.id", ondelete="CASCADE"), nullable=False
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("threat_observations.id", ondelete="CASCADE"), nullable=False
    )
    canonical_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("canonical_findings.id", ondelete="CASCADE")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    match_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    matched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        UniqueConstraint("watchlist_id", "observation_id", "match_key", name="unique_threat_watchlist_match"),
        Index("ix_threat_watchlist_matches_org_time", "organization_id", "matched_at"),
    )


__all__ = [
    "RansomwareAssociation",
    "ThreatActor",
    "ThreatObservation",
    "ThreatWatchlist",
    "ThreatWatchlistMatch",
    "VulnerabilityIntelligence",
]
