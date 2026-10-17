"""Tenant-owned PTaaS engagement, staffing, delivery, and retest records."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
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


class Engagement(Base, TenantMixin, TimestampMixin):
    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft")
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    starts_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    client_visible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','scoping','active','retesting','completed','cancelled')",
            name="valid_engagement_status",
        ),
        CheckConstraint("version > 0", name="valid_engagement_version"),
        CheckConstraint("ends_at IS NULL OR starts_at IS NULL OR ends_at >= starts_at", name="valid_engagement_dates"),
        Index("ix_engagements_org_status_time", "organization_id", "status", "created_at"),
        Index("ix_engagements_org_assessment", "organization_id", "assessment_id"),
    )


class EngagementParticipant(Base, TenantMixin, TimestampMixin):
    __tablename__ = "engagement_participants"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="invited")

    __table_args__ = (
        CheckConstraint(
            "role IN ('lead_tester','tester','client_manager','client_observer')",
            name="valid_engagement_participant_role",
        ),
        CheckConstraint(
            "status IN ('invited','active','removed')",
            name="valid_engagement_participant_status",
        ),
        UniqueConstraint(
            "engagement_id", "email", name="unique_engagement_participant_email"
        ),
        Index("ix_engagement_participants_org_engagement", "organization_id", "engagement_id"),
    )


class EngagementMilestone(Base, TenantMixin, TimestampMixin):
    __tablename__ = "engagement_milestones"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','in_progress','completed','blocked','cancelled')",
            name="valid_engagement_milestone_status",
        ),
        CheckConstraint("sort_order >= 0", name="valid_engagement_milestone_order"),
        Index("ix_engagement_milestones_org_engagement", "organization_id", "engagement_id"),
    )


class EngagementTimeEntry(Base, TenantMixin, TimestampMixin):
    __tablename__ = "engagement_time_entries"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    work_date: Mapped[dt.date] = mapped_column(Date, nullable=False)
    note: Mapped[str | None] = mapped_column(String(1000))
    billable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        CheckConstraint("minutes > 0 AND minutes <= 1440", name="valid_engagement_time_minutes"),
        Index("ix_engagement_time_entries_org_engagement_date", "organization_id", "engagement_id", "work_date"),
    )


class EngagementDocument(Base, TenantMixin, TimestampMixin):
    __tablename__ = "engagement_documents"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    content_type: Mapped[str] = mapped_column(String(160), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    client_visible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('scope','authorization','evidence','report','deliverable','other')",
            name="valid_engagement_document_kind",
        ),
        CheckConstraint("size_bytes >= 0", name="valid_engagement_document_size"),
        UniqueConstraint("engagement_id", "storage_key", name="unique_engagement_document_key"),
        Index("ix_engagement_documents_org_engagement", "organization_id", "engagement_id"),
    )


class EngagementRetestRound(Base, TenantMixin, TimestampMixin):
    __tablename__ = "engagement_retest_rounds"

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="requested")
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    note: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC)
    )
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("ordinal > 0 AND ordinal <= 100", name="valid_engagement_retest_ordinal"),
        CheckConstraint(
            "status IN ('requested','scheduled','running','completed','cancelled','failed')",
            name="valid_engagement_retest_status",
        ),
        UniqueConstraint("engagement_id", "ordinal", name="unique_engagement_retest_round"),
        Index("ix_engagement_retests_org_engagement", "organization_id", "engagement_id"),
    )


__all__ = [
    "Engagement",
    "EngagementDocument",
    "EngagementMilestone",
    "EngagementParticipant",
    "EngagementRetestRound",
    "EngagementTimeEntry",
]
