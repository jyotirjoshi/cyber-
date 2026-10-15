"""Schedule bounded retries for external notification delivery.

Revision ID: 0046_notification_delivery_retries
Revises: 0045_agent_session_autonomy
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0046_notification_delivery_retries"
down_revision = "0045_agent_session_autonomy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "notifications",
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_notifications_delivery_due",
        "notifications",
        ["status", "next_retry_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_notifications_delivery_due", table_name="notifications")
    op.drop_column("notifications", "next_retry_at")
