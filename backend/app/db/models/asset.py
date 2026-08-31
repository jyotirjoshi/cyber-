"""Assets and their criticality tags (FR-009, FR-010, FR-022).

Assets are deduplicated per organization on ``(host, port, protocol)`` so a
subdomain rediscovered by three assessments is one asset with a growing history,
not three rows.  ``asset_tags`` is a separate table because tags are the operator's
input to prioritization and must be attributable and revocable.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk
from app.db.enums import AssetStatus, Criticality, CriticalitySource

if TYPE_CHECKING:
    from app.db.models.assessment import Assessment
    from app.db.models.finding import Finding
    from app.db.models.identity import Organization, User


class Asset(Base, TenantMixin, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: The assessment that first discovered it. Later assessments update in place and
    #: append to ``seen_in_assessments`` rather than creating duplicates.
    #:
    #: ``SET NULL`` rather than ``CASCADE``: the inventory is organization-level and
    #: deduplicated, so deleting a year-old assessment must not delete a host that is
    #: still live and still being scanned.
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )

    #: Identity: hostname, IP, or URL origin.
    name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20))
    service: Mapped[str | None] = mapped_column(String(120))
    #: Detected stack, e.g. ["nginx", "PHP 8.1"]. Provenance is in ``evidence``.
    technology: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=AssetStatus.ACTIVE.value, index=True
    )

    #: True when the asset was reachable from outside the organization's perimeter,
    #: as observed by recon -- not inferred from the address alone.
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    http_title: Mapped[str | None] = mapped_column(String(512))
    http_status_code: Mapped[int | None] = mapped_column(Integer)
    tls_subject: Mapped[str | None] = mapped_column(String(512))

    # --- FR-022 business context ------------------------------------------
    criticality: Mapped[str] = mapped_column(
        String(20), nullable=False, default=Criticality.UNKNOWN.value, index=True
    )
    #: Whether criticality came from an operator tag or a keyword guess. The UI shows
    #: this so an inferred value is never mistaken for a curated one.
    criticality_source: Mapped[str] = mapped_column(
        String(30), nullable=False, default=CriticalitySource.DEFAULT.value
    )
    criticality_rationale: Mapped[str | None] = mapped_column(Text)

    # --- FR-010 scope selection -------------------------------------------
    #: 0-1 ranking produced by the asset-analysis node.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    #: The agent's explanation for the score. FR-010 requires the selection to be
    #: explainable, so this is mandatory whenever ``selected_for_scanning`` is true.
    selection_rationale: Mapped[str | None] = mapped_column(Text)
    selected_for_scanning: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    #: Where each attribute came from: {"technology": "httpx", "ports": "nmap"}.
    #: Used by the report appendix and by the hallucination guard, which refuses to
    #: let the model assert an attribute with no provenance.
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    seen_in_assessments: Mapped[list[str]] = mapped_column(default=list, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="assets", lazy=LAZY)
    assessment: Mapped[Assessment | None] = relationship(back_populates="assets", lazy=LAZY)
    tags: Mapped[list[AssetTag]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy=LAZY
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="asset", lazy=LAZY)

    __table_args__ = (
        # ``port`` and ``protocol`` are nullable for a bare hostname, and in Postgres
        # NULL != NULL -- so a plain unique constraint would happily store the same
        # host twice, defeating the deduplication FR-009 depends on.
        # ``NULLS NOT DISTINCT`` (Postgres 15+; we pin 16) makes the constraint mean
        # what it reads as.
        UniqueConstraint(
            "organization_id",
            "name",
            "port",
            "protocol",
            name="unique_asset",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint("risk_score BETWEEN 0 AND 1", name="risk_score_bounds"),
        CheckConstraint(
            "status IN ('active','inactive','unreachable','out_of_scope')",
            name="valid_asset_status",
        ),
        CheckConstraint(
            "criticality IN ('critical','high','normal','low','unknown')",
            name="valid_criticality",
        ),
        # Constrained for the same reason the column exists: the UI distinguishes a
        # curated tag from a keyword guess, and an unrecognized source would render as
        # neither.
        CheckConstraint(
            "criticality_source IN ('operator_tag','inferred_keyword','inferred_exposure',"
            "'default')",
            name="valid_criticality_source",
        ),
        CheckConstraint("port IS NULL OR port BETWEEN 0 AND 65535", name="valid_port"),
        Index("ix_assets_organization_id_criticality", "organization_id", "criticality"),
        Index(
            "ix_assets_assessment_id_selected_for_scanning",
            "assessment_id",
            "selected_for_scanning",
        ),
    )

    @property
    def criticality_enum(self) -> Criticality:
        return Criticality(self.criticality)

    @property
    def endpoint(self) -> str:
        """Canonical "host:port" used in scanner input and finding correlation."""
        return f"{self.name}:{self.port}" if self.port else self.name


class AssetTag(Base, TenantMixin, TimestampMixin):
    """An operator-applied label, e.g. ``critical``, ``production``, ``pci``.

    Tags feed FR-022 business context. ``applied_by_id`` makes a tag attributable:
    "who told us this was a payments host?" is answerable.
    """

    __tablename__ = "asset_tags"

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    value: Mapped[str | None] = mapped_column(String(200))
    applied_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    #: False when the tag came from a rule or from keyword inference.
    is_operator_applied: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="tags", lazy=LAZY)
    applied_by: Mapped[User | None] = relationship(lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("asset_id", "key", name="unique_tag"),
        Index("ix_asset_tags_organization_id_key", "organization_id", "key"),
    )


__all__ = ["Asset", "AssetTag"]
