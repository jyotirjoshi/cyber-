"""Add usage_meter_buckets table for per-tenant monthly consumption metering.

Revision ID: 0041_usage_metering
Revises: 0040_asm_surfaces
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0041_usage_metering"
down_revision = "0040_asm_surfaces"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "usage_meter_buckets",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("month", sa.Date(), nullable=False),
        sa.Column("event", sa.String(60), nullable=False),
        sa.Column("quantity", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "month", "event", name="unique_usage_bucket"
        ),
    )
    op.create_index(
        "ix_usage_meter_buckets_org_month",
        "usage_meter_buckets",
        ["organization_id", "month"],
    )
    op.create_index(
        "ix_usage_meter_buckets_month",
        "usage_meter_buckets",
        ["month"],
    )


def downgrade() -> None:
    op.drop_index("ix_usage_meter_buckets_month", table_name="usage_meter_buckets")
    op.drop_index("ix_usage_meter_buckets_org_month", table_name="usage_meter_buckets")
    op.drop_table("usage_meter_buckets")
