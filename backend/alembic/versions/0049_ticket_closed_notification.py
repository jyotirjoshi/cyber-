"""Permit durable ticket-closure notifications.

Revision ID: 0049_ticket_closed_notification
Revises: 0048_automation_execution_retries
"""

from __future__ import annotations

from alembic import op


revision = "0049_ticket_closed_notification"
down_revision = "0048_automation_execution_retries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        "event IN ('assessment_started','approval_required','critical_finding',"
        "'assessment_completed','assessment_failed','ticket_created','ticket_closed',"
        "'new_asset','sla_breach','automation_notification')",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        "event IN ('assessment_started','approval_required','critical_finding',"
        "'assessment_completed','assessment_failed','ticket_created','new_asset',"
        "'sla_breach','automation_notification')",
    )
