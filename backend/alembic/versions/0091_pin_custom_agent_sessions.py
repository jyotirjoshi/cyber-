"""Pin custom-agent conversations to immutable definition versions."""
import sqlalchemy as sa
from alembic import op

revision = "0091_pin_custom_agent_sessions"
down_revision = "0090_knowledge_index_leases"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("agent_sessions", sa.Column("agent_version_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_agent_sessions_agent_version_id_agent_definition_versions",
        "agent_sessions", "agent_definition_versions", ["agent_version_id"], ["id"], ondelete="RESTRICT")
    op.create_index("ix_agent_sessions_agent_version_id", "agent_sessions", ["agent_version_id"])


def downgrade():
    op.drop_index("ix_agent_sessions_agent_version_id", table_name="agent_sessions")
    op.drop_constraint("fk_agent_sessions_agent_version_id_agent_definition_versions", "agent_sessions", type_="foreignkey")
    op.drop_column("agent_sessions", "agent_version_id")
