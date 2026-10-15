"""Track independent ticket-closure automation cycles.

Revision ID: 0047_ticket_closure_generations
Revises: 0046_notification_delivery_retries
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0047_ticket_closure_generations"
down_revision = "0046_notification_delivery_retries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ticket_links",
        sa.Column(
            "closure_generation",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.alter_column("ticket_links", "closure_generation", server_default=None)


def downgrade() -> None:
    op.drop_column("ticket_links", "closure_generation")
