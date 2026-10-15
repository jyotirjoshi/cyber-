"""Add per-conversation monitored autonomy mode.

Revision ID: 0045_agent_session_autonomy
Revises: 0044_mssp_client_organizations
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0045_agent_session_autonomy"
down_revision = "0044_mssp_client_organizations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_sessions",
        sa.Column("autonomy_mode", sa.String(length=20), nullable=False, server_default="supervised"),
    )
    op.create_check_constraint(
        "valid_agent_session_autonomy_mode",
        "agent_sessions",
        "autonomy_mode IN ('supervised','monitored')",
    )


def downgrade() -> None:
    op.drop_constraint("valid_agent_session_autonomy_mode", "agent_sessions", type_="check")
    op.drop_column("agent_sessions", "autonomy_mode")
