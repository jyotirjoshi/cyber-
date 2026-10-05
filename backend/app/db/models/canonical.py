"""Tenant-owned canonical findings with lossless provider provenance."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class CanonicalFinding(Base, TenantMixin, TimestampMixin):
    __tablename__ = "canonical_findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="new")
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    risk_policy_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    absence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disposition_reason: Mapped[str | None] = mapped_column(Text)
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    remediation_plan: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint", name="unique_canonical_fingerprint"),
        CheckConstraint(
            "status IN ('new','open','reopened','mitigated','accepted_risk','false_positive','closed')",
            name="valid_canonical_status",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="valid_canonical_severity"
        ),
        CheckConstraint("absence_count >= 0", name="valid_canonical_absence_count"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="valid_canonical_risk_score"),
        CheckConstraint("risk_policy_version >= 0", name="valid_canonical_risk_policy_version"),
        Index("ix_canonical_findings_org_asset_status", "organization_id", "asset_id", "status"),
        Index("ix_canonical_findings_org_status_risk", "organization_id", "status", "risk_score"),
        Index("ix_canonical_findings_org_risk_policy_version", "organization_id", "risk_policy_version"),
        Index("ix_canonical_findings_org_assignee_due", "organization_id", "assignee_user_id", "due_at"),
    )


class FindingObservation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "finding_observations"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("canonical_findings.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    external_id: Mapped[str] = mapped_column(String(300), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False, default="")
    source_record_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    source_status: Mapped[str] = mapped_column(String(30), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2000))
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    missing_sync_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", "external_id", "cve_id", name="unique_finding_observation_source"
        ),
        CheckConstraint("missing_sync_count >= 0", name="valid_observation_missing_count"),
        Index("ix_finding_observations_org_finding", "organization_id", "canonical_finding_id"),
    )


class FindingHistory(Base, TenantMixin):
    __tablename__ = "finding_history"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("canonical_findings.id", ondelete="CASCADE"), nullable=False
    )
    previous_status: Mapped[str | None] = mapped_column(String(30))
    new_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_finding_history_org_finding_time", "organization_id", "canonical_finding_id", "occurred_at"),
    )
