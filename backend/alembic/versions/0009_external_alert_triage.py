"""Add local triage state to external security alerts.

Revision ID: 0009_external_alert_triage
Revises: 0008_organization_entitlements
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0009_external_alert_triage"
down_revision = "0008_organization_entitlements"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "external_security_alerts",
        sa.Column("triage_status", sa.String(length=30), nullable=False, server_default="new"),
    )
    op.add_column("external_security_alerts", sa.Column("triage_note", sa.Text()))
    op.add_column(
        "external_security_alerts",
        sa.Column("triage_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "external_security_alerts",
        sa.Column("triaged_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "external_security_alerts",
        sa.Column(
            "triaged_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_external_security_alerts_valid_external_alert_triage_status"),
        "external_security_alerts",
        "triage_status IN ('new','investigating','risk_accepted','false_positive','closed')",
    )
    op.create_index(
        "ix_external_alerts_org_triage_status",
        "external_security_alerts",
        ["organization_id", "triage_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_external_alerts_org_triage_status", table_name="external_security_alerts")
    op.drop_constraint(
        op.f("ck_external_security_alerts_valid_external_alert_triage_status"),
        "external_security_alerts",
    )
    op.drop_column("external_security_alerts", "triaged_by_user_id")
    op.drop_column("external_security_alerts", "triaged_at")
    op.drop_column("external_security_alerts", "triage_version")
    op.drop_column("external_security_alerts", "triage_note")
    op.drop_column("external_security_alerts", "triage_status")
