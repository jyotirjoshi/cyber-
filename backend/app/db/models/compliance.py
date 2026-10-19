"""Tenant-owned compliance controls and the findings that evidence their risk.

Controls deliberately belong to an organization rather than a global catalogue.  A
tenant can use its own control naming, scope and evidence while still selecting one
of the framework identifiers that Cynux understands.  Mapping a control to a
canonical finding preserves the evidence chain without copying finding data into a
second, eventually-stale table.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
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
        Index("ix_compliance_mappings_org_control", "organization_id", "control_id"),
        Index(
            "ix_compliance_mappings_org_finding", "organization_id", "canonical_finding_id"
        ),
    )


class ComplianceEvidenceItem(Base, TenantMixin, TimestampMixin):
    """One immutable evidence reference with an explicit review state."""

    __tablename__ = "compliance_evidence_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(30), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(2048), nullable=False)
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    collection_status: Mapped[str] = mapped_column(String(24), nullable=False, default="requested")
    collected_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    collected_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    verified_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    review_note: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "evidence_type IN ('artifact','report','screenshot','log','ticket','attestation','external_link')",
            name="valid_compliance_evidence_type",
        ),
        CheckConstraint(
            "collection_status IN ('requested','collected','verified','rejected','expired')",
            name="valid_compliance_evidence_status",
        ),
        Index("ix_compliance_evidence_org_control", "organization_id", "control_id"),
        Index("ix_compliance_evidence_org_status", "organization_id", "collection_status"),
    )


class ComplianceControlException(Base, TenantMixin, TimestampMixin):
    """Time-bounded, independently reviewed exception for one control."""

    __tablename__ = "compliance_control_exceptions"

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected','expired','revoked')",
            name="valid_compliance_exception_status",
        ),
        Index(
            "uq_compliance_control_active_exception",
            "organization_id",
            "control_id",
            unique=True,
            postgresql_where=text("status IN ('pending','approved')"),
        ),
        Index("ix_compliance_exceptions_org_expiry", "organization_id", "status", "expires_at"),
    )


class ComplianceAuditWorkspace(Base, TenantMixin, TimestampMixin):
    """A bounded evidence-review room for an internal or external audit period."""

    __tablename__ = "compliance_audit_workspaces"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    framework: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    control_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    auditor_emails: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    starts_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_cutoff_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint(
            "framework IN ('pci_dss','iso_27001','soc_2','hipaa','nist_csf','cis_controls')",
            name="valid_compliance_workspace_framework",
        ),
        CheckConstraint(
            "status IN ('draft','open','in_review','completed','archived')",
            name="valid_compliance_workspace_status",
        ),
        UniqueConstraint("organization_id", "name", name="unique_compliance_audit_workspace"),
        Index("ix_compliance_workspaces_org_status", "organization_id", "status"),
    )


__all__ = [
    "ComplianceAuditWorkspace",
    "ComplianceControl",
    "ComplianceControlException",
    "ComplianceEvidenceItem",
    "ComplianceFindingMapping",
]
