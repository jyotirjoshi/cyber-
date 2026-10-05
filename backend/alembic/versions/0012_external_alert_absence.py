"""Track consecutive complete-sync misses before resolving external alerts.

Revision ID: 0012_external_alert_absence
Revises: 0011_sonarqube_integration
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0012_external_alert_absence"
down_revision = "0011_sonarqube_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "external_security_alerts",
        sa.Column("missing_sync_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        op.f("ck_external_security_alerts_valid_missing_sync_count"),
        "external_security_alerts",
        "missing_sync_count >= 0",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_external_security_alerts_valid_missing_sync_count"),
        "external_security_alerts",
        type_="check",
    )
    op.drop_column("external_security_alerts", "missing_sync_count")
