"""Add tenant-scoped compliance controls and canonical-finding evidence links.

Revision ID: 0037_compliance_controls
Revises: 0036_m4_saml_connections
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0037_compliance_controls"
down_revision = "0036_m4_saml_connections"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_controls",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("framework", sa.String(40), nullable=False),
        sa.Column("control_id", sa.String(120), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("family", sa.String(160)),
        sa.Column("description", sa.Text()),
        sa.Column("owner_user_id", pg.UUID(as_uuid=True)),
        sa.Column("assessment_status", sa.String(24), nullable=False, server_default="not_assessed"),
        sa.Column("evidence", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "framework", "control_id", name="unique_compliance_control"),
        sa.CheckConstraint("framework IN ('pci_dss','iso_27001','soc_2','hipaa','nist_csf','cis_controls')", name="valid_compliance_framework"),
        sa.CheckConstraint("assessment_status IN ('not_assessed','satisfied','partially_satisfied','at_risk','not_applicable')", name="valid_compliance_assessment_status"),
    )
    op.create_index("ix_compliance_controls_organization_id", "compliance_controls", ["organization_id"])
    op.create_index("ix_compliance_controls_created_at", "compliance_controls", ["created_at"])
    op.create_index("ix_compliance_controls_org_framework", "compliance_controls", ["organization_id", "framework"])
    op.create_table(
        "compliance_finding_mappings",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("mapping_type", sa.String(20), nullable=False, server_default="manual"),
        sa.Column("note", sa.Text()),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "control_id", "canonical_finding_id", name="unique_compliance_finding_mapping"),
        sa.CheckConstraint("mapping_type IN ('manual','import','automated')", name="valid_compliance_mapping_type"),
    )
    op.create_index("ix_compliance_finding_mappings_organization_id", "compliance_finding_mappings", ["organization_id"])
    op.create_index("ix_compliance_finding_mappings_created_at", "compliance_finding_mappings", ["created_at"])
    op.create_index("ix_compliance_mappings_org_control", "compliance_finding_mappings", ["organization_id", "control_id"])
    op.create_index("ix_compliance_mappings_org_finding", "compliance_finding_mappings", ["organization_id", "canonical_finding_id"])


def downgrade() -> None:
    op.drop_index("ix_compliance_mappings_org_finding", table_name="compliance_finding_mappings")
    op.drop_index("ix_compliance_mappings_org_control", table_name="compliance_finding_mappings")
    op.drop_index("ix_compliance_finding_mappings_created_at", table_name="compliance_finding_mappings")
    op.drop_index("ix_compliance_finding_mappings_organization_id", table_name="compliance_finding_mappings")
    op.drop_table("compliance_finding_mappings")
    op.drop_index("ix_compliance_controls_org_framework", table_name="compliance_controls")
    op.drop_index("ix_compliance_controls_created_at", table_name="compliance_controls")
    op.drop_index("ix_compliance_controls_organization_id", table_name="compliance_controls")
    op.drop_table("compliance_controls")
