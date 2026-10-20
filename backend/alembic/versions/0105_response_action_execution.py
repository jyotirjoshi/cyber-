"""Make SOC response actions executable and exact-scope approved.

Revision ID: 0105_response_action_execution
Revises: 0104_assurance_runtime
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0105_response_action_execution"
down_revision = "0104_assurance_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "threat_response_actions",
        sa.Column("provider", sa.String(80), nullable=False, server_default="manual"),
    )
    op.add_column(
        "threat_response_actions",
        sa.Column(
            "requested_action",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "threat_response_actions", sa.Column("approval_scope_digest", sa.String(64))
    )
    op.add_column(
        "threat_response_actions",
        sa.Column("approved_by_id", postgresql.UUID(as_uuid=True)),
    )
    op.add_column(
        "threat_response_actions",
        sa.Column(
            "rollback_receipt",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column("threat_response_actions", sa.Column("failure_code", sa.String(120)))
    op.add_column(
        "threat_response_actions", sa.Column("approved_at", sa.DateTime(timezone=True))
    )
    op.create_foreign_key(
        op.f("fk_threat_response_actions_approved_by_id_users"),
        "threat_response_actions",
        "users",
        ["approved_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.alter_column("threat_response_actions", "provider", server_default=None)
    op.alter_column("threat_response_actions", "requested_action", server_default=None)
    op.alter_column("threat_response_actions", "rollback_receipt", server_default=None)


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_threat_response_actions_approved_by_id_users"),
        "threat_response_actions",
        type_="foreignkey",
    )
    op.drop_column("threat_response_actions", "approved_at")
    op.drop_column("threat_response_actions", "failure_code")
    op.drop_column("threat_response_actions", "rollback_receipt")
    op.drop_column("threat_response_actions", "approved_by_id")
    op.drop_column("threat_response_actions", "approval_scope_digest")
    op.drop_column("threat_response_actions", "requested_action")
    op.drop_column("threat_response_actions", "provider")
