"""Add encrypted target-scoped scanner authentication profiles."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0084_scan_auth_profiles"
down_revision = "0083_durable_workflows"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_auth_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("auth_type", sa.String(length=32), nullable=False),
        sa.Column("target_patterns", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("permitted_scanners", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("fingerprint", sa.String(length=16), nullable=False),
        sa.Column("hint", sa.String(length=8), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("auth_type IN ('basic','bearer','header','cookie','openapi_token','aws_static','aws_role','azure_service_principal','gcp_service_account')", name=op.f("ck_scan_auth_profiles_valid_scan_auth_type")),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_auth_profiles")),
    )
    op.create_index("ix_scan_auth_profiles_org_active", "scan_auth_profiles", ["organization_id", "is_active"])
    op.create_index(op.f("ix_scan_auth_profiles_organization_id"), "scan_auth_profiles", ["organization_id"])
    op.create_index(op.f("ix_scan_auth_profiles_created_at"), "scan_auth_profiles", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_auth_profiles_created_at"), table_name="scan_auth_profiles")
    op.drop_index(op.f("ix_scan_auth_profiles_organization_id"), table_name="scan_auth_profiles")
    op.drop_index("ix_scan_auth_profiles_org_active", table_name="scan_auth_profiles")
    op.drop_table("scan_auth_profiles")
