"""Add a durable, tenant-scoped PTaaS collaboration feed to canonical findings.

Revision ID: 0038_ptaas_finding_collaboration
Revises: 0037_compliance_controls
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0038_ptaas_finding_collaboration"
down_revision = "0037_compliance_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_collaboration_comments",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("author_user_id", pg.UUID(as_uuid=True)),
        sa.Column("kind", sa.String(24), nullable=False, server_default="note"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("evidence_reference", sa.String(2048)),
        sa.Column("visible_to_client", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["author_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "kind IN ('note','evidence','remediation','retest','status_update')",
            name="valid_finding_collaboration_comment_kind",
        ),
    )
    op.create_index(
        "ix_finding_collaboration_comments_org_finding_time",
        "finding_collaboration_comments",
        ["organization_id", "canonical_finding_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_collaboration_comments_org_finding_time",
        table_name="finding_collaboration_comments",
    )
    op.drop_table("finding_collaboration_comments")
