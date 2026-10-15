"""Explicit public projections: no credentials, provider payloads or storage keys."""
from datetime import datetime
from typing import Generic, TypeVar

import strawberry

from app.graphql.ids import encode_global_id


@strawberry.type
class PageInfo:
    has_next_page: bool
    end_cursor: str | None


NodeT = TypeVar("NodeT")


@strawberry.type
class Connection(Generic[NodeT]):
    nodes: list[NodeT]
    page_info: PageInfo


@strawberry.type(name="AgentDefinition")
class AgentDefinitionNode:
    id: strawberry.ID
    name: str
    description: str | None
    is_enabled: bool
    version_count: int
    active_version_id: strawberry.ID | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("AgentDefinition", row.id)),
            name=row.name,
            description=row.description,
            is_enabled=row.is_enabled,
            version_count=row.version_count,
            active_version_id=strawberry.ID(
                encode_global_id("AgentDefinitionVersion", row.active_version_id)
            )
            if row.active_version_id
            else None,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


@strawberry.type(name="KnowledgeCollection")
class KnowledgeCollectionNode:
    id: strawberry.ID
    name: str
    description: str | None
    is_enabled: bool
    retrieval_provider: str
    revision: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("KnowledgeCollection", row.id)),
            name=row.name,
            description=row.description,
            is_enabled=row.is_enabled,
            retrieval_provider=row.retrieval_provider,
            revision=row.revision,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
