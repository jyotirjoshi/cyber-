"""Persistence invariants for tenant-configurable agents and knowledge."""

from __future__ import annotations

import sqlalchemy as sa

from app.db.models.agent_definition import (
    AgentDefinition,
    AgentDefinitionVersion,
    AgentEvaluation,
    AgentTemplate,
    AgentVersionCollection,
    AgentVersionTool,
)
from app.db.models.knowledge import (
    AgentMemoryCandidate,
    KnowledgeChunk,
    KnowledgeCollection,
    KnowledgeEmbedding,
    KnowledgeFeedback,
    KnowledgeSource,
    KnowledgeSourceVersion,
)

NEW_MODELS = (
    AgentDefinition,
    AgentDefinitionVersion,
    AgentVersionTool,
    AgentVersionCollection,
    AgentTemplate,
    AgentEvaluation,
    KnowledgeCollection,
    KnowledgeSource,
    KnowledgeSourceVersion,
    KnowledgeChunk,
    KnowledgeEmbedding,
    KnowledgeFeedback,
    AgentMemoryCandidate,
)


def _constraint_names(model: type) -> set[str | None]:
    return {constraint.name for constraint in model.__table__.constraints}


def test_knowledge_embedding_is_fixed_1536_vector() -> None:
    """Changing the vector width would corrupt provider/index compatibility."""
    column = KnowledgeEmbedding.__table__.c.embedding

    assert str(column.type) == "VECTOR(1536)"


def test_agent_version_configuration_digest_is_unique_per_definition() -> None:
    """Two immutable versions cannot occupy the same sequence number."""
    assert "unique_agent_definition_version" in _constraint_names(AgentDefinitionVersion)


def test_every_custom_agent_and_knowledge_table_is_tenant_scoped() -> None:
    """Omitting organization_id would permit an unscoped repository query."""
    for model in NEW_MODELS:
        organization = model.__table__.c.get("organization_id")
        assert organization is not None, model.__tablename__
        assert organization.nullable is False, model.__tablename__
        assert any(
            foreign_key.target_fullname == "organizations.id"
            and foreign_key.ondelete == "CASCADE"
            for foreign_key in organization.foreign_keys
        ), model.__tablename__


def test_knowledge_chunk_search_document_is_database_generated() -> None:
    """Full-text content must stay synchronized when normalized text changes."""
    column = KnowledgeChunk.__table__.c.search_document

    assert isinstance(column.computed, sa.Computed)
    assert column.computed.persisted is True


def test_embedding_identity_prevents_duplicate_profile_rows() -> None:
    """A resumed indexing batch must update, not duplicate, a chunk/profile vector."""
    assert "unique_knowledge_embedding_profile" in _constraint_names(KnowledgeEmbedding)
