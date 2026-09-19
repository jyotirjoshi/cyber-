"""Create normalized external security alert ledger.

Revision ID: 0007_external_security_alerts
Revises: 0006_wazuh_integration
Create Date: 2026-09-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0007_external_security_alerts"
down_revision = "0006_wazuh_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_security_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integrations.id", ondelete="SET NULL")),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("external_id", sa.String(length=300), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=1000), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="info"),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="open"),
        sa.Column("resource", sa.String(length=1000)),
        sa.Column("source_url", sa.String(length=2000)),
        sa.Column("cve_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("raw_payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "provider", "external_id", name="unique_external_security_alert"),
        sa.CheckConstraint("severity IN ('critical','high','medium','low','info')", name=op.f("ck_external_security_alerts_valid_external_alert_severity")),
        sa.CheckConstraint("status IN ('open','resolved','dismissed','fixed')", name=op.f("ck_external_security_alerts_valid_external_alert_status")),
    )
    op.create_index("ix_external_security_alerts_organization_id", "external_security_alerts", ["organization_id"])
    op.create_index("ix_external_security_alerts_provider", "external_security_alerts", ["provider"])
    op.create_index("ix_external_security_alerts_severity", "external_security_alerts", ["severity"])
    op.create_index("ix_external_security_alerts_status", "external_security_alerts", ["status"])
    op.create_index("ix_external_security_alerts_created_at", "external_security_alerts", ["created_at"])
    op.create_index("ix_external_security_alerts_last_seen_at", "external_security_alerts", ["last_seen_at"])
    op.create_index("ix_external_alerts_org_provider_status", "external_security_alerts", ["organization_id", "provider", "status"])


def downgrade() -> None:
    op.drop_index("ix_external_alerts_org_provider_status", table_name="external_security_alerts")
    op.drop_index("ix_external_security_alerts_last_seen_at", table_name="external_security_alerts")
    op.drop_index("ix_external_security_alerts_created_at", table_name="external_security_alerts")
    op.drop_index("ix_external_security_alerts_status", table_name="external_security_alerts")
    op.drop_index("ix_external_security_alerts_severity", table_name="external_security_alerts")
    op.drop_index("ix_external_security_alerts_provider", table_name="external_security_alerts")
    op.drop_index("ix_external_security_alerts_organization_id", table_name="external_security_alerts")
    op.drop_table("external_security_alerts")
