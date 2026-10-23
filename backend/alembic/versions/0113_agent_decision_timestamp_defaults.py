"""Repair server defaults for durable agent decision timestamps.

Revision ID: 0113_agent_decision_timestamp_defaults
Revises: 0112_agent_specialist_timestamp_defaults

The decision ORM uses ``TimestampMixin`` and therefore omits timestamp values so
PostgreSQL can populate them.  Migration 0082 accidentally created both columns
without those defaults, causing the first post-scan supervisor decision to fail.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0113_agent_decision_timestamp_defaults"
down_revision = "0112_agent_specialist_timestamp_defaults"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in ("created_at", "updated_at"):
        op.alter_column(
            "agent_decisions",
            column,
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=False,
            server_default=sa.text("now()"),
        )


def downgrade() -> None:
    for column in ("updated_at", "created_at"):
        op.alter_column(
            "agent_decisions",
            column,
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=False,
            server_default=None,
        )
