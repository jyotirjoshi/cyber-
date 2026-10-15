"""Add tenant-configurable agents and first-party vector knowledge."""

from __future__ import annotations

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0089_custom_agents_knowledge"
down_revision = "0088_custom_connectors"
branch_labels = None
depends_on = None


TABLES = (
    "knowledge_collections",
    "agent_definitions",
    "agent_definition_versions",
    "agent_version_tools",
    "agent_templates",
    "agent_evaluations",
    "knowledge_sources",
    "knowledge_source_versions",
    "agent_version_collections",
    "knowledge_chunks",
    "knowledge_embeddings",
    "knowledge_feedback",
    "agent_memory_candidates",
)


def _tenant_columns() -> tuple[sa.Column, sa.Column, sa.Column]:
    return (
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def _tenant_constraints() -> tuple[sa.ForeignKeyConstraint]:
    return (
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
    )


def _tenant_indexes(table: str) -> None:
    op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])
    op.create_index(f"ix_{table}_created_at", table, ["created_at"])


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "knowledge_collections",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("retrieval_provider", sa.String(20), server_default="internal", nullable=False),
        sa.Column(
            "retrieval_policy",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "retrieval_provider IN ('internal','dify')",
            name=op.f("ck_knowledge_collections_valid_knowledge_collection_provider"),
        ),
        sa.CheckConstraint(
            "revision > 0", name=op.f("ck_knowledge_collections_valid_knowledge_collection_revision")
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_collections")),
        sa.UniqueConstraint(
            "organization_id", "name", name="unique_knowledge_collection_name"
        ),
    )
    _tenant_indexes("knowledge_collections")
    op.create_index(
        "ix_knowledge_collections_org_enabled",
        "knowledge_collections",
        ["organization_id", "is_enabled"],
    )

    op.create_table(
        "agent_definitions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("avatar_reference", sa.String(1000)),
        sa.Column("active_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("version_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "version_count >= 0", name=op.f("ck_agent_definitions_valid_agent_definition_version_count")
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_definitions")),
        sa.UniqueConstraint("organization_id", "name", name="unique_agent_definition_name"),
    )
    _tenant_indexes("agent_definitions")
    op.create_index(
        "ix_agent_definitions_org_enabled",
        "agent_definitions",
        ["organization_id", "is_enabled"],
    )

    op.create_table(
        "agent_definition_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_definition_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(160), nullable=False),
        sa.Column("instructions", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(40), nullable=False),
        sa.Column("model", sa.String(160), nullable=False),
        sa.Column("autonomy_mode", sa.String(20), server_default="supervised", nullable=False),
        sa.Column("temperature", sa.Numeric(4, 3), server_default="0", nullable=False),
        sa.Column("max_output_tokens", sa.Integer(), server_default="4096", nullable=False),
        sa.Column("max_parallel_tasks", sa.Integer(), server_default="1", nullable=False),
        sa.Column("max_runtime_seconds", sa.Integer(), server_default="900", nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), server_default="20", nullable=False),
        sa.Column("max_input_tokens", sa.Integer(), server_default="100000", nullable=False),
        sa.Column(
            "max_estimated_spend_micros", sa.BigInteger(), server_default="1000000", nullable=False
        ),
        sa.Column(
            "scope_policy", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "retrieval_policy",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("configuration_digest", sa.String(64), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "version > 0", name=op.f("ck_agent_definition_versions_valid_agent_definition_version_number")
        ),
        sa.CheckConstraint(
            "autonomy_mode IN ('manual','supervised','bounded')",
            name=op.f("ck_agent_definition_versions_valid_agent_definition_autonomy_mode"),
        ),
        sa.CheckConstraint(
            "temperature BETWEEN 0 AND 2",
            name=op.f("ck_agent_definition_versions_valid_agent_temperature"),
        ),
        sa.CheckConstraint(
            "max_output_tokens > 0",
            name=op.f("ck_agent_definition_versions_valid_agent_output_tokens"),
        ),
        sa.CheckConstraint(
            "max_parallel_tasks BETWEEN 1 AND 30",
            name=op.f("ck_agent_definition_versions_valid_agent_parallel_tasks"),
        ),
        sa.CheckConstraint(
            "max_runtime_seconds BETWEEN 1 AND 86400",
            name=op.f("ck_agent_definition_versions_valid_agent_runtime"),
        ),
        sa.CheckConstraint(
            "max_tool_calls >= 0",
            name=op.f("ck_agent_definition_versions_valid_agent_tool_calls"),
        ),
        sa.CheckConstraint(
            "max_input_tokens > 0",
            name=op.f("ck_agent_definition_versions_valid_agent_input_tokens"),
        ),
        sa.CheckConstraint(
            "max_estimated_spend_micros >= 0",
            name=op.f("ck_agent_definition_versions_valid_agent_estimated_spend"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_definition_id"], ["agent_definitions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_definition_versions")),
        sa.UniqueConstraint(
            "agent_definition_id", "version", name="unique_agent_definition_version"
        ),
        sa.UniqueConstraint(
            "agent_definition_id",
            "configuration_digest",
            name="unique_agent_definition_configuration",
        ),
    )
    _tenant_indexes("agent_definition_versions")
    op.create_index(
        "ix_agent_definition_versions_org_definition",
        "agent_definition_versions",
        ["organization_id", "agent_definition_id"],
    )
    op.create_foreign_key(
        "fk_agent_definitions_active_version",
        "agent_definitions",
        "agent_definition_versions",
        ["active_version_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "agent_version_tools",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.String(120), nullable=False),
        sa.Column("tool_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("approval_mode", sa.String(20), server_default="policy", nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), server_default="60", nullable=False),
        sa.Column("per_run_call_limit", sa.Integer(), server_default="5", nullable=False),
        *_tenant_columns(),
        sa.CheckConstraint(
            "tool_version > 0", name=op.f("ck_agent_version_tools_valid_agent_tool_version")
        ),
        sa.CheckConstraint(
            "approval_mode IN ('never','policy','always')",
            name=op.f("ck_agent_version_tools_valid_agent_tool_approval"),
        ),
        sa.CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 3600",
            name=op.f("ck_agent_version_tools_valid_agent_tool_timeout"),
        ),
        sa.CheckConstraint(
            "per_run_call_limit >= 0",
            name=op.f("ck_agent_version_tools_valid_agent_tool_call_limit"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_version_id"], ["agent_definition_versions.id"], ondelete="CASCADE"
        ),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_version_tools")),
        sa.UniqueConstraint(
            "agent_version_id", "tool_name", name="unique_agent_version_tool"
        ),
    )
    _tenant_indexes("agent_version_tools")
    op.create_index(
        "ix_agent_version_tools_org_version",
        "agent_version_tools",
        ["organization_id", "agent_version_id"],
    )

    op.create_table(
        "agent_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column(
            "configuration", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("is_system", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_templates")),
        sa.UniqueConstraint("organization_id", "name", name="unique_agent_template_name"),
    )
    _tenant_indexes("agent_templates")
    op.create_index(
        "ix_agent_templates_org_enabled",
        "agent_templates",
        ["organization_id", "is_enabled"],
    )

    op.create_table(
        "agent_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column(
            "test_case", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "expected_criteria",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("actual_run_id", postgresql.UUID(as_uuid=True)),
        sa.Column(
            "grader_results",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("cost_micros", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("reviewer_decision", sa.String(20)),
        sa.Column("reviewed_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "cost_micros >= 0", name=op.f("ck_agent_evaluations_valid_agent_evaluation_cost")
        ),
        sa.CheckConstraint(
            "latency_ms IS NULL OR latency_ms >= 0",
            name=op.f("ck_agent_evaluations_valid_agent_evaluation_latency"),
        ),
        sa.CheckConstraint(
            "reviewer_decision IS NULL OR reviewer_decision IN ('approved','rejected')",
            name=op.f("ck_agent_evaluations_valid_agent_evaluation_decision"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_version_id"], ["agent_definition_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["actual_run_id"], ["agent_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_evaluations")),
        sa.UniqueConstraint("agent_version_id", "name", name="unique_agent_evaluation_name"),
    )
    _tenant_indexes("agent_evaluations")
    op.create_index(
        "ix_agent_evaluations_org_version",
        "agent_evaluations",
        ["organization_id", "agent_version_id"],
    )

    op.create_table(
        "knowledge_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("collection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(30), server_default="upload", nullable=False),
        sa.Column("filename", sa.String(500), nullable=False),
        sa.Column("title", sa.String(500)),
        sa.Column("object_key", sa.String(1000), nullable=False),
        sa.Column("mime_type", sa.String(160), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(30), server_default="stored", nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("error_detail", sa.Text()),
        sa.Column(
            "document_metadata",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("current_revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("current_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("tombstoned_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "size_bytes >= 0", name=op.f("ck_knowledge_sources_valid_knowledge_source_size")
        ),
        sa.CheckConstraint(
            "current_revision > 0",
            name=op.f("ck_knowledge_sources_valid_knowledge_source_revision"),
        ),
        sa.CheckConstraint(
            "status IN ('storing','stored','extracting','chunking','embedding','ready','failed','deleted')",
            name=op.f("ck_knowledge_sources_valid_knowledge_source_status"),
        ),
        sa.ForeignKeyConstraint(
            ["collection_id"], ["knowledge_collections.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_sources")),
        sa.UniqueConstraint(
            "collection_id", "content_hash", name="unique_knowledge_source_content"
        ),
    )
    _tenant_indexes("knowledge_sources")
    op.create_index(
        "ix_knowledge_sources_org_collection_status",
        "knowledge_sources",
        ["organization_id", "collection_id", "status"],
    )

    op.create_table(
        "knowledge_source_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("object_key", sa.String(1000), nullable=False),
        sa.Column("mime_type", sa.String(160), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "extraction_provenance",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        *_tenant_columns(),
        sa.CheckConstraint(
            "revision > 0",
            name=op.f("ck_knowledge_source_versions_valid_knowledge_source_version_revision"),
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name=op.f("ck_knowledge_source_versions_valid_knowledge_source_version_size"),
        ),
        sa.ForeignKeyConstraint(["source_id"], ["knowledge_sources.id"], ondelete="CASCADE"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_source_versions")),
        sa.UniqueConstraint("source_id", "revision", name="unique_knowledge_source_version"),
        sa.UniqueConstraint(
            "source_id", "content_hash", name="unique_knowledge_source_version_content"
        ),
    )
    _tenant_indexes("knowledge_source_versions")
    op.create_index(
        "ix_knowledge_source_versions_org_source",
        "knowledge_source_versions",
        ["organization_id", "source_id"],
    )
    op.create_foreign_key(
        "fk_knowledge_sources_current_version",
        "knowledge_sources",
        "knowledge_source_versions",
        ["current_version_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "agent_version_collections",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("collection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "metadata_filter",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        *_tenant_columns(),
        sa.ForeignKeyConstraint(
            ["agent_version_id"], ["agent_definition_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["collection_id"], ["knowledge_collections.id"], ondelete="CASCADE"
        ),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_version_collections")),
        sa.UniqueConstraint(
            "agent_version_id", "collection_id", name="unique_agent_version_collection"
        ),
    )
    _tenant_indexes("agent_version_collections")
    op.create_index(
        "ix_agent_version_collections_org_version",
        "agent_version_collections",
        ["organization_id", "agent_version_id"],
    )

    op.create_table(
        "knowledge_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("normalized_text", sa.Text(), nullable=False),
        sa.Column("token_count", sa.Integer(), nullable=False),
        sa.Column("page", sa.Integer()),
        sa.Column("section", sa.String(500)),
        sa.Column(
            "chunk_metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column(
            "search_document",
            postgresql.TSVECTOR(),
            sa.Computed("to_tsvector('english', normalized_text)", persisted=True),
            nullable=False,
        ),
        *_tenant_columns(),
        sa.CheckConstraint(
            "ordinal >= 0", name=op.f("ck_knowledge_chunks_valid_knowledge_chunk_ordinal")
        ),
        sa.CheckConstraint(
            "token_count > 0", name=op.f("ck_knowledge_chunks_valid_knowledge_chunk_token_count")
        ),
        sa.CheckConstraint(
            "page IS NULL OR page > 0", name=op.f("ck_knowledge_chunks_valid_knowledge_chunk_page")
        ),
        sa.ForeignKeyConstraint(
            ["source_version_id"], ["knowledge_source_versions.id"], ondelete="CASCADE"
        ),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_chunks")),
        sa.UniqueConstraint(
            "source_version_id", "ordinal", name="unique_knowledge_chunk_ordinal"
        ),
    )
    _tenant_indexes("knowledge_chunks")
    op.create_index(
        "ix_knowledge_chunks_org_source_version",
        "knowledge_chunks",
        ["organization_id", "source_version_id"],
    )
    op.create_index(
        "ix_knowledge_chunks_search_document",
        "knowledge_chunks",
        ["search_document"],
        postgresql_using="gin",
    )

    op.create_table(
        "knowledge_embeddings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("chunk_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("embedding_profile", sa.String(160), nullable=False),
        sa.Column("embedding", Vector(1536), nullable=False),
        sa.Column("status", sa.String(20), server_default="ready", nullable=False),
        sa.Column("embedding_content_hash", sa.String(64), nullable=False),
        *_tenant_columns(),
        sa.CheckConstraint(
            "status IN ('pending','ready','failed')",
            name=op.f("ck_knowledge_embeddings_valid_knowledge_embedding_status"),
        ),
        sa.ForeignKeyConstraint(["chunk_id"], ["knowledge_chunks.id"], ondelete="CASCADE"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_embeddings")),
        sa.UniqueConstraint(
            "chunk_id", "embedding_profile", name="unique_knowledge_embedding_profile"
        ),
    )
    _tenant_indexes("knowledge_embeddings")
    op.create_index(
        "ix_knowledge_embeddings_org_profile",
        "knowledge_embeddings",
        ["organization_id", "embedding_profile"],
    )
    op.create_index(
        "ix_knowledge_embeddings_vector_hnsw",
        "knowledge_embeddings",
        ["embedding"],
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )

    op.create_table(
        "knowledge_feedback",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("chunk_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True)),
        sa.Column("is_useful", sa.Boolean(), nullable=False),
        sa.Column("rationale", sa.Text()),
        sa.Column("reviewed_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.ForeignKeyConstraint(["chunk_id"], ["knowledge_chunks.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_feedback")),
    )
    _tenant_indexes("knowledge_feedback")
    op.create_index(
        "ix_knowledge_feedback_org_chunk",
        "knowledge_feedback",
        ["organization_id", "chunk_id"],
    )

    op.create_table(
        "agent_memory_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("key", sa.String(120), nullable=False),
        sa.Column("category", sa.String(40), server_default="operational", nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "evidence", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("proposed_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("reviewed_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("decision_rationale", sa.Text()),
        sa.Column("approved_memory_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "confidence BETWEEN 0 AND 1",
            name=op.f("ck_agent_memory_candidates_valid_memory_candidate_confidence"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','expired')",
            name=op.f("ck_agent_memory_candidates_valid_memory_candidate_status"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_version_id"], ["agent_definition_versions.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["proposed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["approved_memory_id"], ["agent_memories.id"], ondelete="SET NULL"
        ),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_memory_candidates")),
    )
    _tenant_indexes("agent_memory_candidates")
    op.create_index(
        "ix_memory_candidates_org_status",
        "agent_memory_candidates",
        ["organization_id", "status"],
    )


def downgrade() -> None:
    for table, indexes in (
        ("agent_memory_candidates", ["ix_memory_candidates_org_status"]),
        ("knowledge_feedback", ["ix_knowledge_feedback_org_chunk"]),
        (
            "knowledge_embeddings",
            ["ix_knowledge_embeddings_org_profile", "ix_knowledge_embeddings_vector_hnsw"],
        ),
        (
            "knowledge_chunks",
            ["ix_knowledge_chunks_org_source_version", "ix_knowledge_chunks_search_document"],
        ),
        ("agent_version_collections", ["ix_agent_version_collections_org_version"]),
        ("knowledge_source_versions", ["ix_knowledge_source_versions_org_source"]),
        ("knowledge_sources", ["ix_knowledge_sources_org_collection_status"]),
        ("agent_evaluations", ["ix_agent_evaluations_org_version"]),
        ("agent_templates", ["ix_agent_templates_org_enabled"]),
        ("agent_version_tools", ["ix_agent_version_tools_org_version"]),
        ("agent_definition_versions", ["ix_agent_definition_versions_org_definition"]),
        ("agent_definitions", ["ix_agent_definitions_org_enabled"]),
        ("knowledge_collections", ["ix_knowledge_collections_org_enabled"]),
    ):
        for index in indexes:
            op.drop_index(index, table_name=table)
        op.drop_index(f"ix_{table}_created_at", table_name=table)
        op.drop_index(f"ix_{table}_organization_id", table_name=table)

    op.drop_table("agent_memory_candidates")
    op.drop_table("knowledge_feedback")
    op.drop_table("knowledge_embeddings")
    op.drop_table("knowledge_chunks")
    op.drop_table("agent_version_collections")
    op.drop_constraint(
        "fk_knowledge_sources_current_version",
        "knowledge_sources",
        type_="foreignkey",
    )
    op.drop_table("knowledge_source_versions")
    op.drop_table("knowledge_sources")
    op.drop_table("agent_evaluations")
    op.drop_table("agent_templates")
    op.drop_table("agent_version_tools")
    op.drop_constraint(
        "fk_agent_definitions_active_version",
        "agent_definitions",
        type_="foreignkey",
    )
    op.drop_table("agent_definition_versions")
    op.drop_table("agent_definitions")
    op.drop_table("knowledge_collections")
