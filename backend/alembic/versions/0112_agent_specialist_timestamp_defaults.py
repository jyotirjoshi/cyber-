"""Repair server defaults for durable specialist task timestamps.

Revision ID: 0112_agent_specialist_timestamp_defaults
Revises: 0111_integration_sync_runs

The original table migration declared ``created_at`` and ``updated_at`` as
non-null but omitted the database defaults present on ``TimestampMixin``.  The
ORM intentionally lets PostgreSQL populate these fields with ``RETURNING``;
without the defaults, the first approved specialist plan fails at flush time.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0112_agent_specialist_timestamp_defaults"
down_revision = "0111_integration_sync_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "agent_specialist_tasks",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=sa.text("now()"),
    )
    op.alter_column(
        "agent_specialist_tasks",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=sa.text("now()"),
    )


def downgrade() -> None:
    op.alter_column(
        "agent_specialist_tasks",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=None,
    )
    op.alter_column(
        "agent_specialist_tasks",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=None,
    )
