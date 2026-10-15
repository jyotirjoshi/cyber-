"""Add durable GraphQL mutation idempotency receipts."""

import sqlalchemy as sa

from alembic import op

revision = "0092_graphql_mutation_receipts"
down_revision = "0091_pin_custom_agent_sessions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "graphql_mutation_receipts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor_key", sa.String(length=80), nullable=False),
        sa.Column("operation", sa.String(length=120), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=80), nullable=True),
        sa.Column("resource_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "actor_key",
            "operation",
            "idempotency_key",
            name="unique_graphql_mutation_receipt",
        ),
    )
    op.create_index(
        "ix_graphql_mutation_receipts_organization_id",
        "graphql_mutation_receipts",
        ["organization_id"],
    )
    op.create_index(
        "ix_graphql_mutation_receipts_org_created",
        "graphql_mutation_receipts",
        ["organization_id", "created_at"],
    )


def downgrade():
    op.drop_index(
        "ix_graphql_mutation_receipts_org_created",
        table_name="graphql_mutation_receipts",
    )
    op.drop_index(
        "ix_graphql_mutation_receipts_organization_id",
        table_name="graphql_mutation_receipts",
    )
    op.drop_table("graphql_mutation_receipts")
