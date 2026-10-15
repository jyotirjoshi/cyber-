"""First-party tenant knowledge, embeddings, feedback, and approved learning candidates."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class KnowledgeCollection(Base, TenantMixin, TimestampMixin):
    __tablename__ = "knowledge_collections"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    retrieval_provider: Mapped[str] = mapped_column(String(20), nullable=False, default="internal")
    retrieval_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_knowledge_collection_name"),
        CheckConstraint(
            "retrieval_provider IN ('internal','dify')",
            name="valid_knowledge_collection_provider",
        ),
        CheckConstraint("revision > 0", name="valid_knowledge_collection_revision"),
        Index("ix_knowledge_collections_org_enabled", "organization_id", "is_enabled"),
    )


class KnowledgeSource(Base, TenantMixin, TimestampMixin):
    __tablename__ = "knowledge_sources"

    id: Mapped[uuid.UUID] = uuid_pk()
    collection_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_collections.id", ondelete="CASCADE"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(30), nullable=False, default="upload")
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str | None] = mapped_column(String(500))
    object_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(160), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="stored")
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_detail: Mapped[str | None] = mapped_column(Text)
    document_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    current_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_source_versions.id", ondelete="SET NULL")
    )
    tombstoned_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    lease_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    index_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_index_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    embedding_profile: Mapped[str | None] = mapped_column(String(160))
    indexed_chunks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_chunks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("lease_generation >= 0 AND index_attempts >= 0 AND indexed_chunks >= 0 AND total_chunks >= 0", name="valid_knowledge_index_counters"),
        Index("ix_knowledge_sources_index_queue", "status", "next_index_at", "lease_until"),
        UniqueConstraint(
            "collection_id", "content_hash", name="unique_knowledge_source_content"
        ),
        CheckConstraint("size_bytes >= 0", name="valid_knowledge_source_size"),
        CheckConstraint("current_revision > 0", name="valid_knowledge_source_revision"),
        CheckConstraint(
            "status IN ('storing','stored','extracting','chunking','embedding','ready','failed','deleted')",
            name="valid_knowledge_source_status",
        ),
        Index(
            "ix_knowledge_sources_org_collection_status",
            "organization_id",
            "collection_id",
            "status",
        ),
    )


class KnowledgeSourceVersion(Base, TenantMixin, TimestampMixin):
    __tablename__ = "knowledge_source_versions"

    id: Mapped[uuid.UUID] = uuid_pk()
    source_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_sources.id", ondelete="CASCADE"), nullable=False
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    object_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(160), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    extraction_provenance: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        UniqueConstraint("source_id", "revision", name="unique_knowledge_source_version"),
        UniqueConstraint(
            "source_id", "content_hash", name="unique_knowledge_source_version_content"
        ),
        CheckConstraint("revision > 0", name="valid_knowledge_source_version_revision"),
        CheckConstraint("size_bytes >= 0", name="valid_knowledge_source_version_size"),
        Index("ix_knowledge_source_versions_org_source", "organization_id", "source_id"),
    )


class KnowledgeChunk(Base, TenantMixin, TimestampMixin):
    __tablename__ = "knowledge_chunks"

    id: Mapped[uuid.UUID] = uuid_pk()
    source_version_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("knowledge_source_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    normalized_text: Mapped[str] = mapped_column(Text, nullable=False)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False)
    page: Mapped[int | None] = mapped_column(Integer)
    section: Mapped[str | None] = mapped_column(String(500))
    chunk_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    search_document: Mapped[Any] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('english', normalized_text)", persisted=True),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("source_version_id", "ordinal", name="unique_knowledge_chunk_ordinal"),
        CheckConstraint("ordinal >= 0", name="valid_knowledge_chunk_ordinal"),
        CheckConstraint("token_count > 0", name="valid_knowledge_chunk_token_count"),
        CheckConstraint("page IS NULL OR page > 0", name="valid_knowledge_chunk_page"),
        Index("ix_knowledge_chunks_org_source_version", "organization_id", "source_version_id"),
        Index("ix_knowledge_chunks_search_document", "search_document", postgresql_using="gin"),
    )


class KnowledgeEmbedding(Base, TenantMixin, TimestampMixin):
    __tablename__ = "knowledge_embeddings"

    id: Mapped[uuid.UUID] = uuid_pk()
    chunk_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_chunks.id", ondelete="CASCADE"), nullable=False
    )
    embedding_profile: Mapped[str] = mapped_column(String(160), nullable=False)
    embedding: Mapped[list[float]] = mapped_column(Vector(1536), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ready")
    embedding_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "chunk_id", "embedding_profile", name="unique_knowledge_embedding_profile"
        ),
        CheckConstraint(
            "status IN ('pending','ready','failed')", name="valid_knowledge_embedding_status"
        ),
        Index("ix_knowledge_embeddings_org_profile", "organization_id", "embedding_profile"),
        Index(
            "ix_knowledge_embeddings_vector_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


class KnowledgeFeedback(Base, TenantMixin, TimestampMixin):
    __tablename__ = "knowledge_feedback"

    id: Mapped[uuid.UUID] = uuid_pk()
    query: Mapped[str] = mapped_column(Text, nullable=False)
    chunk_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_chunks.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    is_useful: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_knowledge_feedback_org_chunk", "organization_id", "chunk_id"),
    )


class AgentMemoryCandidate(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_memory_candidates"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_definition_versions.id", ondelete="SET NULL")
    )
    key: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False, default="operational")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Numeric(4, 3), nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    proposed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    decision_rationale: Mapped[str | None] = mapped_column(Text)
    approved_memory_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_memories.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_memory_candidate_confidence"),
        CheckConstraint(
            "status IN ('pending','approved','rejected','expired')",
            name="valid_memory_candidate_status",
        ),
        Index("ix_memory_candidates_org_status", "organization_id", "status"),
    )


__all__ = [
    "AgentMemoryCandidate",
    "KnowledgeChunk",
    "KnowledgeCollection",
    "KnowledgeEmbedding",
    "KnowledgeFeedback",
    "KnowledgeSource",
    "KnowledgeSourceVersion",
]
