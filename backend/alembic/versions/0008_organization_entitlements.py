"""Add self-service organization entitlement snapshots.

Revision ID: 0008_organization_entitlements
Revises: 0007_external_security_alerts
Create Date: 2026-09-30
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0008_organization_entitlements"
down_revision = "0007_external_security_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "entitlements",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("organizations", "entitlements")
