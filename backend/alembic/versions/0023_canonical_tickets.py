"""Allow Jira tickets to target unified canonical findings.

Revision ID: 0023_canonical_tickets
Revises: 0022_agent_canonical_work
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0023_canonical_tickets"
down_revision = "0022_agent_canonical_work"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "ticket_links", "finding_id", existing_type=postgresql.UUID(as_uuid=True), nullable=True
    )
    op.add_column(
        "ticket_links", sa.Column("canonical_finding_id", postgresql.UUID(as_uuid=True))
    )
    op.create_foreign_key(
        op.f("fk_ticket_links_canonical_finding_id_canonical_findings"),
        "ticket_links", "canonical_findings", ["canonical_finding_id"], ["id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint(
        op.f("uq_ticket_links_unique_ticket_per_canonical_finding"),
        "ticket_links", ["canonical_finding_id", "provider"],
    )
    op.create_check_constraint(
        op.f("ck_ticket_links_one_ticket_finding_target"),
        "ticket_links",
        "(finding_id IS NOT NULL) <> (canonical_finding_id IS NOT NULL)",
    )


def downgrade() -> None:
    # Existing canonical-only links intentionally prevent this downgrade until an
    # operator exports or removes them; no customer's ticket mapping is discarded.
    op.drop_constraint(
        op.f("ck_ticket_links_one_ticket_finding_target"), "ticket_links", type_="check"
    )
    op.drop_constraint(
        op.f("uq_ticket_links_unique_ticket_per_canonical_finding"),
        "ticket_links", type_="unique",
    )
    op.drop_constraint(
        op.f("fk_ticket_links_canonical_finding_id_canonical_findings"),
        "ticket_links", type_="foreignkey",
    )
    op.drop_column("ticket_links", "canonical_finding_id")
    op.alter_column(
        "ticket_links", "finding_id", existing_type=postgresql.UUID(as_uuid=True), nullable=False
    )
