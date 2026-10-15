"""Allow ASM disappearance drift records.

Revision ID: 0050_asm_unreachable_drift
Revises: 0049_ticket_closed_notification
"""

from __future__ import annotations

from alembic import op


revision = "0050_asm_unreachable_drift"
down_revision = "0049_ticket_closed_notification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_asset_changes_valid_asset_change_type"),
        "asset_changes",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_asset_changes_valid_asset_change_type"),
        "asset_changes",
        "change_type IN ('discovered','changed','unreachable')",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_asset_changes_valid_asset_change_type"),
        "asset_changes",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_asset_changes_valid_asset_change_type"),
        "asset_changes",
        "change_type IN ('discovered','changed')",
    )
