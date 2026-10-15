"""Generated reports (FR-039).

A report is a rendered snapshot, not a live view.  ``content_digest`` stores the
structured data the template was rendered from, so re-opening a three-month-old
report shows what was true then even though the findings have since been fixed and
DefectDojo's current state disagrees.

The ``degradations`` copied onto the report matter as much as the findings: a report
that silently omits ZAP coverage reads as "the web app is clean".
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk
from app.db.enums import ReportFormat, ReportStatus

if TYPE_CHECKING:
    from app.db.models.assessment import Assessment
    from app.db.models.identity import User


class Report(Base, TenantMixin, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("report_templates.id", ondelete="SET NULL")
    )
    template_version: Mapped[int | None] = mapped_column()
    template_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False, default=ReportFormat.PDF.value)
    #: "executive" or "technical" (FR-039 requires both audiences).
    audience: Mapped[str] = mapped_column(String(30), nullable=False, default="technical")
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ReportStatus.PENDING.value, index=True
    )

    #: Object storage key for the rendered file.
    storage_key: Mapped[str | None] = mapped_column(String(1000))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))

    #: The structured snapshot the template rendered. Frozen at generation time.
    content_digest: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    #: Copied from the assessment so the appendix can state what coverage was missing.
    degradations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    #: Executive summary text. Stored separately because it is the one section a
    #: reviewer may want to read, cite or correct without opening the PDF.
    executive_summary: Mapped[str | None] = mapped_column(Text)
    #: True when the summary was written by the model. Shown in the document footer:
    #: a reader is entitled to know which prose is generated.
    summary_ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ai_model: Mapped[str | None] = mapped_column(String(120))

    generated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)

    assessment: Mapped[Assessment] = relationship(back_populates="reports", lazy=LAZY)
    requested_by: Mapped[User | None] = relationship(lazy=LAZY)

    __table_args__ = (
        CheckConstraint("format IN ('html','pdf','json')", name="valid_report_format"),
        CheckConstraint(
            "status IN ('pending','generating','ready','failed')", name="valid_report_status"
        ),
        CheckConstraint("audience IN ('executive','technical')", name="valid_report_audience"),
        Index("ix_reports_assessment_id_created_at", "assessment_id", "created_at"),
        Index("ix_reports_organization_id_status", "organization_id", "status"),
    )

    @property
    def format_enum(self) -> ReportFormat:
        return ReportFormat(self.format)

    @property
    def status_enum(self) -> ReportStatus:
        return ReportStatus(self.status)


class ReportSchedule(Base, TenantMixin, TimestampMixin):
    """A durable cron trigger for fresh point-in-time assessment reports."""

    __tablename__ = "report_schedules"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("report_templates.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    title: Mapped[str | None] = mapped_column(String(300))
    format: Mapped[str] = mapped_column(String(20), nullable=False, default=ReportFormat.PDF.value)
    audience: Mapped[str] = mapped_column(String(30), nullable=False, default="executive")
    cron_expression: Mapped[str] = mapped_column(String(120), nullable=False)
    timezone: Mapped[str] = mapped_column(String(80), nullable=False, default="UTC")
    recipients: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    next_run_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_report_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("reports.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("format IN ('html','pdf','json')", name="valid_report_schedule_format"),
        CheckConstraint("audience IN ('executive','technical')", name="valid_report_schedule_audience"),
        UniqueConstraint("organization_id", "name", name="unique_report_schedule_name"),
        Index("ix_report_schedules_due", "is_enabled", "next_run_at"),
    )


class ReportShareLink(Base, TenantMixin, TimestampMixin):
    """Opaque, revocable external access grant for one ready report."""

    __tablename__ = "report_share_links"

    id: Mapped[uuid.UUID] = uuid_pk()
    report_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True, unique=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (Index("ix_report_share_links_org_report", "organization_id", "report_id"),)


class ReportTemplate(Base, TenantMixin, TimestampMixin):
    """One immutable version of a safe block-based report definition."""

    __tablename__ = "report_templates"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("version > 0", name="valid_report_template_version"),
        UniqueConstraint("organization_id", "name", "version", name="unique_report_template_version"),
        Index("ix_report_templates_org_active", "organization_id", "is_active"),
    )


class ReportDistribution(Base, TenantMixin, TimestampMixin):
    """Durable status for one email or webhook delivery of a rendered report."""

    __tablename__ = "report_distributions"

    id: Mapped[uuid.UUID] = uuid_pk()
    report_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("report_schedules.id", ondelete="SET NULL")
    )
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    destination: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    next_retry_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(1000))

    __table_args__ = (
        CheckConstraint("channel IN ('email','webhook')", name="valid_report_distribution_channel"),
        CheckConstraint("status IN ('pending','sent','failed')", name="valid_report_distribution_status"),
        CheckConstraint("attempts >= 0", name="valid_report_distribution_attempts"),
        UniqueConstraint("report_id", "channel", "destination", name="unique_report_distribution_destination"),
        Index("ix_report_distributions_due", "status", "next_retry_at"),
    )


__all__ = ["Report", "ReportDistribution", "ReportSchedule", "ReportShareLink", "ReportTemplate"]
