"""Validated public contracts for tenant knowledge resources."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmbeddingConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["openai", "google"] = "openai"
    model: str = "text-embedding-3-small"


class CollectionRetrievalPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    embedding: EmbeddingConfiguration = Field(default_factory=EmbeddingConfiguration)

    @field_validator("embedding")
    @classmethod
    def valid_profile(cls, value):
        from app.services.embedding import EmbeddingProfile
        EmbeddingProfile(value.provider, value.model)
        return value


class KnowledgeCollectionCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10_000)
    retrieval_provider: Literal["internal", "dify"] = "internal"
    retrieval_policy: dict[str, Any] = Field(default_factory=dict)

    @field_validator("retrieval_policy")
    @classmethod
    def bounded_policy(cls, value):
        return CollectionRetrievalPolicy.model_validate(value).model_dump()

    @field_validator("name")
    @classmethod
    def clean_name(cls, value):
        if not value.strip():
            raise ValueError("name must not be blank")
        return value.strip()


class KnowledgeCollectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    retrieval_provider: str
    retrieval_policy: dict[str, Any]
    is_enabled: bool
    revision: int
    created_at: dt.datetime
    updated_at: dt.datetime


class KnowledgeSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    collection_id: uuid.UUID
    filename: str
    title: str | None
    mime_type: str
    content_hash: str
    size_bytes: int
    status: str
    error_code: str | None
    current_revision: int
    current_version_id: uuid.UUID | None
    tombstoned_at: dt.datetime | None
    created_at: dt.datetime
    updated_at: dt.datetime
    embedding_profile: str | None = None
    indexed_chunks: int = 0
    total_chunks: int = 0
    index_attempts: int = 0


class KnowledgeSearchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=2000)
    collection_ids: list[uuid.UUID] = Field(min_length=1, max_length=20)
    limit: int = Field(default=6, ge=1, le=20)
    min_similarity: float = Field(default=0.25, ge=0, le=1)


class KnowledgeFeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=2000)
    chunk_id: uuid.UUID
    is_useful: bool
    rationale: str | None = Field(default=None, max_length=2000)


__all__ = [
    "KnowledgeCollectionCreateIn",
    "KnowledgeCollectionOut",
    "KnowledgeSourceOut",
]
