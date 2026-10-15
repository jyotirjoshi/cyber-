"""Tenant-owned compliance controls and the findings that evidence their risk.

Controls deliberately belong to an organization rather than a global catalogue.  A
tenant can use its own control naming, scope and evidence while still selecting one
of the framework identifiers that Cynux understands.  Mapping a control to a
canonical finding preserves the evidence chain without copying finding data into a
second, eventually-stale table.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class ComplianceControl(Base, TenantMixin, TimestampMixin):
    """A control in an organization's selected compliance framework."""

    __tablename__ = "compliance_controls"

    id: Mapped[uuid.UUID] = uuid_pk()
    framework: Mapped[str] = mapped_column(String(40), nullable=False)
    control_id: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    family: Mapped[str | None] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    # An operator can explicitly mark a control out of scope.  All other statuses
    # are calculated at read time from the active canonical findings mapped to it.
    assessment_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="not_assessed"
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "framework", "control_id", name="unique_compliance_control"
        ),
        CheckConstraint(
            "framework IN ('pci_dss','iso_27001','soc_2','hipaa','nist_csf','cis_controls')",
            name="valid_compliance_framework",
        ),
        CheckConstraint(
            "assessment_status IN ('not_assessed','satisfied','partially_satisfied','at_risk','not_applicable')",
            name="valid_compliance_assessment_status",
        ),
        Index("ix_compliance_controls_org_framework", "organization_id", "framework"),
    )


class ComplianceFindingMapping(Base, TenantMixin, TimestampMixin):
    """Evidence link from a compliance control to one canonical finding."""

    __tablename__ = "compliance_finding_mappings"

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    mapping_type: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    note: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "control_id",
            "canonical_finding_id",
            name="unique_compliance_finding_mapping",
        ),
        CheckConstraint(
            "mapping_type IN ('manual','import','automated')", name="valid_compliance_mapping_type"
        ),
        Index(
            "ix_compliance_mappings_org_control", "organization_id", "control_id"
        ),
        Index(
            "ix_compliance_mappings_org_finding", "organization_id", "canonical_finding_id"
        ),
    )


__all__ = ["ComplianceControl", "ComplianceFindingMapping"]
