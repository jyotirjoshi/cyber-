"""Permit webhook rows in the durable notification outbox.

Revision ID: 0031_m4_webhook_notification_channel
Revises: 0030_m4_webhook_subscriptions
"""

from __future__ import annotations

from alembic import op

revision = "0031_m4_webhook_notification_channel"
down_revision = "0030_m4_webhook_subscriptions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_notifications_valid_notification_channel"), "notifications", type_="check")
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_channel"),
        "notifications",
        "channel IN ('slack','email','websocket','pagerduty','webhook')",
    )


def downgrade() -> None:
    op.execute("DELETE FROM notifications WHERE channel = 'webhook'")
    op.drop_constraint(op.f("ck_notifications_valid_notification_channel"), "notifications", type_="check")
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_channel"),
        "notifications",
        "channel IN ('slack','email','websocket','pagerduty')",
    )
