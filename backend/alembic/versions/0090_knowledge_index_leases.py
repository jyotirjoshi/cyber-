"""Durable knowledge indexing claims and resumable progress."""
import sqlalchemy as sa

from alembic import op

revision = "0090_knowledge_index_leases"
down_revision = "0089_custom_agents_knowledge"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("lease_generation", "index_attempts", "indexed_chunks", "total_chunks"):
        op.add_column("knowledge_sources", sa.Column(name, sa.Integer(), nullable=False, server_default="0"))
    for name in ("lease_until", "next_index_at"):
        op.add_column("knowledge_sources", sa.Column(name, sa.DateTime(timezone=True)))
    op.add_column("knowledge_sources", sa.Column("embedding_profile", sa.String(160)))
    op.create_check_constraint("valid_knowledge_index_counters", "knowledge_sources",
        "lease_generation >= 0 AND index_attempts >= 0 AND indexed_chunks >= 0 AND total_chunks >= 0")
    op.create_index("ix_knowledge_sources_index_queue", "knowledge_sources", ["status", "next_index_at", "lease_until"])


def downgrade():
    op.drop_index("ix_knowledge_sources_index_queue", table_name="knowledge_sources")
    op.drop_constraint("valid_knowledge_index_counters", "knowledge_sources", type_="check")
    for name in ("embedding_profile", "next_index_at", "lease_until", "total_chunks", "indexed_chunks", "index_attempts", "lease_generation"):
        op.drop_column("knowledge_sources", name)
