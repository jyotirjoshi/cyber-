"""Permit explicit API-key actor attribution in the audit trail.

Revision ID: 0028_m4_platform_api_key_audit_actor
Revises: 0027_m4_platform_api_keys
"""

from __future__ import annotations

from alembic import op

revision = "0028_m4_platform_api_key_audit_actor"
down_revision = "0027_m4_platform_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_audit_events_valid_actor_type"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_valid_actor_type"),
        "audit_events",
        "actor_type IN ('user','agent','system','worker','api_key')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_audit_events_valid_actor_type"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_valid_actor_type"),
        "audit_events",
        "actor_type IN ('user','agent','system','worker')",
    )
