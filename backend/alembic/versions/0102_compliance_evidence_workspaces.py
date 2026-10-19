"""Add compliance evidence, exceptions, and audit workspaces."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0102_compliance_evidence_workspaces"
down_revision = "0101_business_risk_context"
branch_labels = None
depends_on = None


def _tenant_timestamps() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "compliance_evidence_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("evidence_type", sa.String(30), nullable=False),
        sa.Column("source_reference", sa.String(2048), nullable=False),
        sa.Column("content_sha256", sa.String(64)),
        sa.Column("collection_status", sa.String(24), server_default="requested", nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True)),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.Column("collected_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("verified_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("review_note", sa.Text()),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint("evidence_type IN ('artifact','report','screenshot','log','ticket','attestation','external_link')", name="ck_compliance_evidence_items_valid_compliance_evidence_type"),
        sa.CheckConstraint("collection_status IN ('requested','collected','verified','rejected','expired')", name="ck_compliance_evidence_items_valid_compliance_evidence_status"),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["collected_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["verified_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_evidence_items")),
    )
    op.create_index("ix_compliance_evidence_org_control", "compliance_evidence_items", ["organization_id", "control_id"])
    op.create_index("ix_compliance_evidence_org_status", "compliance_evidence_items", ["organization_id", "collection_status"])

    op.create_table(
        "compliance_control_exceptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("compensating_controls", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requested_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("resolved_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolution_note", sa.Text()),
        *_tenant_timestamps(),
        sa.CheckConstraint("status IN ('pending','approved','rejected','expired','revoked')", name="ck_compliance_control_exceptions_valid_compliance_exception_status"),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["resolved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_control_exceptions")),
    )
    op.create_index("uq_compliance_control_active_exception", "compliance_control_exceptions", ["organization_id", "control_id"], unique=True, postgresql_where=sa.text("status IN ('pending','approved')"))
    op.create_index("ix_compliance_exceptions_org_expiry", "compliance_control_exceptions", ["organization_id", "status", "expires_at"])

    op.create_table(
        "compliance_audit_workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("framework", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), server_default="draft", nullable=False),
        sa.Column("control_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("auditor_emails", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("evidence_cutoff_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint("framework IN ('pci_dss','iso_27001','soc_2','hipaa','nist_csf','cis_controls')", name="ck_compliance_audit_workspaces_valid_compliance_workspace_framework"),
        sa.CheckConstraint("status IN ('draft','open','in_review','completed','archived')", name="ck_compliance_audit_workspaces_valid_compliance_workspace_status"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_audit_workspaces")),
        sa.UniqueConstraint("organization_id", "name", name="unique_compliance_audit_workspace"),
    )
    op.create_index("ix_compliance_workspaces_org_status", "compliance_audit_workspaces", ["organization_id", "status"])


def downgrade() -> None:
    op.drop_table("compliance_audit_workspaces")
    op.drop_table("compliance_control_exceptions")
    op.drop_table("compliance_evidence_items")
