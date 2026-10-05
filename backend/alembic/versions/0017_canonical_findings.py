"""Add tenant-owned canonical findings and source-preserving observations.

Revision ID: 0017_canonical_findings
Revises: 0016_github_alert_agent_action
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0017_canonical_findings"
down_revision = "0016_github_alert_agent_action"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "canonical_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=1000), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("cve_ids", postgresql.JSONB(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("absence_count", sa.Integer(), nullable=False),
        sa.Column("status_version", sa.Integer(), nullable=False),
        sa.Column("disposition_reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("organization_id", "fingerprint", name="unique_canonical_fingerprint"),
        sa.CheckConstraint("status IN ('new','open','reopened','mitigated','accepted_risk','false_positive','closed')", name=op.f("ck_canonical_findings_valid_canonical_status")),
        sa.CheckConstraint("severity IN ('critical','high','medium','low','info')", name=op.f("ck_canonical_findings_valid_canonical_severity")),
        sa.CheckConstraint("absence_count >= 0", name=op.f("ck_canonical_findings_valid_canonical_absence_count")),
    )
    op.create_index("ix_canonical_findings_organization_id", "canonical_findings", ["organization_id"])
    op.create_index("ix_canonical_findings_created_at", "canonical_findings", ["created_at"])
    op.create_index("ix_canonical_findings_org_asset_status", "canonical_findings", ["organization_id", "asset_id", "status"])

    op.create_table(
        "finding_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("canonical_finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("canonical_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("external_id", sa.String(length=300), nullable=False),
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True)),
        sa.Column("source_status", sa.String(length=30), nullable=False),
        sa.Column("source_url", sa.String(length=2000)),
        sa.Column("title", sa.String(length=1000), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("missing_sync_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("organization_id", "provider", "external_id", "cve_id", name="unique_finding_observation_source"),
        sa.CheckConstraint("missing_sync_count >= 0", name=op.f("ck_finding_observations_valid_observation_missing_count")),
    )
    op.create_index("ix_finding_observations_organization_id", "finding_observations", ["organization_id"])
    op.create_index("ix_finding_observations_created_at", "finding_observations", ["created_at"])
    op.create_index("ix_finding_observations_org_finding", "finding_observations", ["organization_id", "canonical_finding_id"])

    op.create_table(
        "finding_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("canonical_finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("canonical_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("previous_status", sa.String(length=30)),
        sa.Column("new_status", sa.String(length=30), nullable=False),
        sa.Column("reason", sa.String(length=1000), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_history_organization_id", "finding_history", ["organization_id"])
    op.create_index("ix_finding_history_org_finding_time", "finding_history", ["organization_id", "canonical_finding_id", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_finding_history_org_finding_time", table_name="finding_history")
    op.drop_index("ix_finding_history_organization_id", table_name="finding_history")
    op.drop_table("finding_history")
    op.drop_index("ix_finding_observations_org_finding", table_name="finding_observations")
    op.drop_index("ix_finding_observations_created_at", table_name="finding_observations")
    op.drop_index("ix_finding_observations_organization_id", table_name="finding_observations")
    op.drop_table("finding_observations")
    op.drop_index("ix_canonical_findings_org_asset_status", table_name="canonical_findings")
    op.drop_index("ix_canonical_findings_created_at", table_name="canonical_findings")
    op.drop_index("ix_canonical_findings_organization_id", table_name="canonical_findings")
    op.drop_table("canonical_findings")
