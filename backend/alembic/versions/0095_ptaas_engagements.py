"""Add first-class PTaaS engagement delivery records."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0095_ptaas_engagements"
down_revision = "0094_custom_connector_execution"
branch_labels = None
depends_on = None


def _tenant_columns() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    ]


def _tenant_constraints(table: str):
    return (
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
    )


def _tenant_indexes(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def _drop_indexes(table: str, *extra: str) -> None:
    for name in extra:
        op.drop_index(name, table_name=table)
    op.drop_index(op.f(f"ix_{table}_created_at"), table_name=table)
    op.drop_index(op.f(f"ix_{table}_organization_id"), table_name=table)


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True)),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(24), nullable=False, server_default="draft"),
        sa.Column(
            "scope",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("starts_at", sa.DateTime(timezone=True)),
        sa.Column("ends_at", sa.DateTime(timezone=True)),
        sa.Column(
            "client_visible", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        *_tenant_columns(),
        sa.CheckConstraint(
            "status IN ('draft','scoping','active','retesting','completed','cancelled')",
            name=op.f("ck_engagements_valid_engagement_status"),
        ),
        sa.CheckConstraint(
            "version > 0", name=op.f("ck_engagements_valid_engagement_version")
        ),
        sa.CheckConstraint(
            "ends_at IS NULL OR starts_at IS NULL OR ends_at >= starts_at",
            name=op.f("ck_engagements_valid_engagement_dates"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["assessments.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"], ondelete="SET NULL"
        ),
        *_tenant_constraints("engagements"),
    )
    _tenant_indexes("engagements")
    op.create_index(
        "ix_engagements_org_status_time",
        "engagements",
        ["organization_id", "status", "created_at"],
    )
    op.create_index(
        "ix_engagements_org_assessment",
        "engagements",
        ["organization_id", "assessment_id"],
    )

    op.create_table(
        "engagement_participants",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(200)),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="invited"),
        *_tenant_columns(),
        sa.CheckConstraint(
            "role IN ('lead_tester','tester','client_manager','client_observer')",
            name=op.f(
                "ck_engagement_participants_valid_engagement_participant_role"
            ),
        ),
        sa.CheckConstraint(
            "status IN ('invited','active','removed')",
            name=op.f(
                "ck_engagement_participants_valid_engagement_participant_status"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "engagement_id", "email", name="unique_engagement_participant_email"
        ),
        *_tenant_constraints("engagement_participants"),
    )
    _tenant_indexes("engagement_participants")
    op.create_index(
        "ix_engagement_participants_org_engagement",
        "engagement_participants",
        ["organization_id", "engagement_id"],
    )

    op.create_table(
        "engagement_milestones",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        *_tenant_columns(),
        sa.CheckConstraint(
            "status IN ('pending','in_progress','completed','blocked','cancelled')",
            name=op.f("ck_engagement_milestones_valid_engagement_milestone_status"),
        ),
        sa.CheckConstraint(
            "sort_order >= 0",
            name=op.f("ck_engagement_milestones_valid_engagement_milestone_order"),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
        ),
        *_tenant_constraints("engagement_milestones"),
    )
    _tenant_indexes("engagement_milestones")
    op.create_index(
        "ix_engagement_milestones_org_engagement",
        "engagement_milestones",
        ["organization_id", "engagement_id"],
    )

    op.create_table(
        "engagement_time_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("minutes", sa.Integer(), nullable=False),
        sa.Column("work_date", sa.Date(), nullable=False),
        sa.Column("note", sa.String(1000)),
        sa.Column("billable", sa.Boolean(), nullable=False, server_default=sa.true()),
        *_tenant_columns(),
        sa.CheckConstraint(
            "minutes > 0 AND minutes <= 1440",
            name=op.f("ck_engagement_time_entries_valid_engagement_time_minutes"),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints("engagement_time_entries"),
    )
    _tenant_indexes("engagement_time_entries")
    op.create_index(
        "ix_engagement_time_entries_org_engagement_date",
        "engagement_time_entries",
        ["organization_id", "engagement_id", "work_date"],
    )

    op.create_table(
        "engagement_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("uploaded_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("storage_key", sa.String(1000), nullable=False),
        sa.Column("content_type", sa.String(160), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column(
            "client_visible", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        *_tenant_columns(),
        sa.CheckConstraint(
            "kind IN ('scope','authorization','evidence','report','deliverable','other')",
            name=op.f("ck_engagement_documents_valid_engagement_document_kind"),
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name=op.f("ck_engagement_documents_valid_engagement_document_size"),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "engagement_id", "storage_key", name="unique_engagement_document_key"
        ),
        *_tenant_constraints("engagement_documents"),
    )
    _tenant_indexes("engagement_documents")
    op.create_index(
        "ix_engagement_documents_org_engagement",
        "engagement_documents",
        ["organization_id", "engagement_id"],
    )

    op.create_table(
        "engagement_retest_rounds",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True)),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="requested"
        ),
        sa.Column("requested_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("note", sa.Text()),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "ordinal > 0 AND ordinal <= 100",
            name=op.f("ck_engagement_retest_rounds_valid_engagement_retest_ordinal"),
        ),
        sa.CheckConstraint(
            "status IN ('requested','scheduled','running','completed','cancelled','failed')",
            name=op.f("ck_engagement_retest_rounds_valid_engagement_retest_status"),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["assessments.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "engagement_id", "ordinal", name="unique_engagement_retest_round"
        ),
        *_tenant_constraints("engagement_retest_rounds"),
    )
    _tenant_indexes("engagement_retest_rounds")
    op.create_index(
        "ix_engagement_retests_org_engagement",
        "engagement_retest_rounds",
        ["organization_id", "engagement_id"],
    )


def downgrade() -> None:
    _drop_indexes(
        "engagement_retest_rounds", "ix_engagement_retests_org_engagement"
    )
    op.drop_table("engagement_retest_rounds")
    _drop_indexes("engagement_documents", "ix_engagement_documents_org_engagement")
    op.drop_table("engagement_documents")
    _drop_indexes(
        "engagement_time_entries", "ix_engagement_time_entries_org_engagement_date"
    )
    op.drop_table("engagement_time_entries")
    _drop_indexes("engagement_milestones", "ix_engagement_milestones_org_engagement")
    op.drop_table("engagement_milestones")
    _drop_indexes(
        "engagement_participants", "ix_engagement_participants_org_engagement"
    )
    op.drop_table("engagement_participants")
    _drop_indexes(
        "engagements",
        "ix_engagements_org_assessment",
        "ix_engagements_org_status_time",
    )
    op.drop_table("engagements")
