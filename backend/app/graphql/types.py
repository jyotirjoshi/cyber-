"""Explicit public projections: no credentials, provider payloads or storage keys."""
from datetime import datetime
from typing import Generic, TypeVar

import strawberry

from app.graphql.ids import encode_global_id


@strawberry.type
class KnowledgeCitationNode:
    collection_id: strawberry.ID
    source_id: strawberry.ID
    source_version_id: strawberry.ID
    filename: str
    page: int | None
    section: str | None
    ordinal: int
    content_hash: str
    provider: str


@strawberry.type
class KnowledgeSearchHitNode:
    chunk_id: strawberry.ID
    source_id: strawberry.ID
    text: str
    score: float
    citation: KnowledgeCitationNode

    @classmethod
    def from_hit(cls, hit):
        citation = hit.citation
        return cls(
            chunk_id=strawberry.ID(encode_global_id("KnowledgeChunk", hit.chunk_id)),
            source_id=strawberry.ID(encode_global_id("KnowledgeSource", hit.source_id)),
            text=hit.text,
            score=hit.score,
            citation=KnowledgeCitationNode(
                collection_id=strawberry.ID(
                    encode_global_id("KnowledgeCollection", citation.collection_id)
                ),
                source_id=strawberry.ID(encode_global_id("KnowledgeSource", citation.source_id)),
                source_version_id=strawberry.ID(
                    encode_global_id("KnowledgeSourceVersion", citation.source_version_id)
                ),
                filename=citation.filename,
                page=citation.page,
                section=citation.section,
                ordinal=citation.ordinal,
                content_hash=citation.content_hash,
                provider=citation.provider,
            ),
        )


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


@strawberry.type(name="AgentDefinitionVersion")
class AgentDefinitionVersionNode:
    id: strawberry.ID
    agent_definition_id: strawberry.ID
    version: int
    role: str
    provider: str
    model: str
    autonomy_mode: str
    temperature: float
    max_output_tokens: int
    max_parallel_tasks: int
    max_runtime_seconds: int
    max_tool_calls: int
    max_input_tokens: int
    max_estimated_spend_micros: str
    created_at: datetime

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("AgentDefinitionVersion", row.id)),
            agent_definition_id=strawberry.ID(
                encode_global_id("AgentDefinition", row.agent_definition_id)
            ),
            version=row.version,
            role=row.role,
            provider=row.provider,
            model=row.model,
            autonomy_mode=row.autonomy_mode,
            temperature=float(row.temperature),
            max_output_tokens=row.max_output_tokens,
            max_parallel_tasks=row.max_parallel_tasks,
            max_runtime_seconds=row.max_runtime_seconds,
            max_tool_calls=row.max_tool_calls,
            max_input_tokens=row.max_input_tokens,
            max_estimated_spend_micros=str(row.max_estimated_spend_micros),
            created_at=row.created_at,
        )


@strawberry.type(name="KnowledgeSource")
class KnowledgeSourceNode:
    id: strawberry.ID
    collection_id: strawberry.ID
    source_type: str
    filename: str
    title: str | None
    mime_type: str
    content_hash: str
    size_bytes: int
    status: str
    error_code: str | None
    current_revision: int
    indexed_chunks: int
    total_chunks: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("KnowledgeSource", row.id)),
            collection_id=strawberry.ID(encode_global_id("KnowledgeCollection", row.collection_id)),
            source_type=row.source_type,
            filename=row.filename,
            title=row.title,
            mime_type=row.mime_type,
            content_hash=row.content_hash,
            size_bytes=row.size_bytes,
            status=row.status,
            error_code=row.error_code,
            current_revision=row.current_revision,
            indexed_chunks=row.indexed_chunks,
            total_chunks=row.total_chunks,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


@strawberry.type(name="AgentTool")
class AgentToolNode:
    name: str
    version: int
    permission: str
    side_effect: str
    approval: str
    timeout_seconds: int
    permitted: bool


@strawberry.type(name="Asset")
class AssetNode:
    id: strawberry.ID
    name: str
    asset_type: str
    status: str
    criticality: str
    environment: str
    internet_exposed: bool
    groups: list[str]
    owner_team: str | None
    risk_score: float
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("Asset", row.id)),
            name=row.name,
            asset_type=row.asset_type,
            status=row.status,
            criticality=row.criticality,
            environment=row.environment,
            internet_exposed=row.internet_exposed,
            groups=list(row.groups or []),
            owner_team=row.owner_team,
            risk_score=float(row.risk_score or 0),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


@strawberry.type(name="CanonicalFinding")
class CanonicalFindingNode:
    id: strawberry.ID
    asset_id: strawberry.ID
    title: str
    severity: str
    status: str
    cve_ids: list[str]
    risk_score: float
    first_seen_at: datetime
    last_seen_at: datetime
    due_at: datetime | None
    remediation_group: str | None

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("CanonicalFinding", row.id)),
            asset_id=strawberry.ID(encode_global_id("Asset", row.asset_id)),
            title=row.title,
            severity=row.severity,
            status=row.status,
            cve_ids=list(row.cve_ids or []),
            risk_score=float(row.risk_score or 0),
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
            due_at=row.due_at,
            remediation_group=row.remediation_group,
        )


@strawberry.type(name="Assessment")
class AssessmentNode:
    id: strawberry.ID
    reference: int
    title: str
    scope: str
    depth: str
    engagement_type: str
    execution_mode: str
    status: str
    current_stage: str
    progress_percent: int
    findings_total: int
    assets_discovered: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row):
        return cls(
            id=strawberry.ID(encode_global_id("Assessment", row.id)),
            reference=row.reference,
            title=row.title,
            scope=row.scope,
            depth=row.depth,
            engagement_type=row.engagement_type,
            execution_mode=row.execution_mode,
            status=row.status,
            current_stage=row.current_stage,
            progress_percent=row.progress_percent,
            findings_total=row.findings_total,
            assets_discovered=row.assets_discovered,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
