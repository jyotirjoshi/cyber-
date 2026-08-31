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


__all__ = ["Report"]
