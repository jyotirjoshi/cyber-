"""Add governed validation policy and per-job credential references.

Revision ID: 0100_governed_validation_policy
Revises: 0099_ticket_webhook_events
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0100_governed_validation_policy"
down_revision = "0099_ticket_webhook_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "attack_simulation_campaigns",
        sa.Column(
            "execution_policy",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "scanner_jobs",
        sa.Column("auth_profile_id", postgresql.UUID(as_uuid=True)),
    )
    op.create_foreign_key(
        "fk_scanner_jobs_auth_profile_id_scan_auth_profiles",
        "scanner_jobs",
        "scan_auth_profiles",
        ["auth_profile_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_scanner_jobs_org_auth_profile",
        "scanner_jobs",
        ["organization_id", "auth_profile_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_scanner_jobs_org_auth_profile", table_name="scanner_jobs")
    op.drop_constraint(
        "fk_scanner_jobs_auth_profile_id_scan_auth_profiles",
        "scanner_jobs",
        type_="foreignkey",
    )
    op.drop_column("scanner_jobs", "auth_profile_id")
    op.drop_column("attack_simulation_campaigns", "execution_policy")
