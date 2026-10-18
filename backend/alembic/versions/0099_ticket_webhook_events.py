"""Add durable inbound ticket event receipts and provider ordering cursor."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0099_ticket_webhook_events"
down_revision = "0098_asset_inventory_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ticket_links", sa.Column("external_updated_at", sa.DateTime(timezone=True))
    )
    op.create_table(
        "inbound_ticket_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ticket_link_id", postgresql.UUID(as_uuid=True)),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("delivery_id", sa.String(160), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("external_key", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(80)),
        sa.Column("external_status", sa.String(80), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "processing_status",
            sa.String(20),
            server_default="received",
            nullable=False,
        ),
        sa.Column("ignore_reason", sa.String(120)),
        sa.Column(
            "normalized",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
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
        sa.CheckConstraint(
            "provider IN ('jira','github','gitlab','servicenow','azure_devops')",
            name="ck_inbound_ticket_events_valid_inbound_ticket_provider",
        ),
        sa.CheckConstraint(
            "processing_status IN ('received','processed','ignored')",
            name="ck_inbound_ticket_events_valid_inbound_ticket_event_status",
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["ticket_link_id"], ["ticket_links.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inbound_ticket_events")),
        sa.UniqueConstraint(
            "integration_id",
            "delivery_id",
            name="uq_inbound_ticket_events_unique_inbound_ticket_delivery",
        ),
    )
    op.create_index(
        op.f("ix_inbound_ticket_events_organization_id"),
        "inbound_ticket_events",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_inbound_ticket_events_created_at"),
        "inbound_ticket_events",
        ["created_at"],
    )
    op.create_index(
        "ix_inbound_ticket_events_org_occurred",
        "inbound_ticket_events",
        ["organization_id", "occurred_at"],
    )
    op.create_index(
        "ix_inbound_ticket_events_org_ticket",
        "inbound_ticket_events",
        ["organization_id", "ticket_link_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_inbound_ticket_events_org_ticket", table_name="inbound_ticket_events"
    )
    op.drop_index(
        "ix_inbound_ticket_events_org_occurred", table_name="inbound_ticket_events"
    )
    op.drop_index(
        op.f("ix_inbound_ticket_events_created_at"),
        table_name="inbound_ticket_events",
    )
    op.drop_index(
        op.f("ix_inbound_ticket_events_organization_id"),
        table_name="inbound_ticket_events",
    )
    op.drop_table("inbound_ticket_events")
    op.drop_column("ticket_links", "external_updated_at")
