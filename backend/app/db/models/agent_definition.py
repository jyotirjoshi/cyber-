"""Tenant-configurable agent identities, immutable versions, and evaluations."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class AgentDefinition(Base, TenantMixin, TimestampMixin):
    """Stable identity whose behavior is supplied by immutable versions."""

    __tablename__ = "agent_definitions"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    avatar_reference: Mapped[str | None] = mapped_column(String(1000))
    active_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(
            "agent_definition_versions.id",
            name="fk_agent_definitions_active_version",
            ondelete="SET NULL",
        ),
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_agent_definition_name"),
        CheckConstraint("version_count >= 0", name="valid_agent_definition_version_count"),
        Index("ix_agent_definitions_org_enabled", "organization_id", "is_enabled"),
    )


class AgentDefinitionVersion(Base, TenantMixin, TimestampMixin):
    """Frozen execution configuration selected by sessions and runs."""

    __tablename__ = "agent_definition_versions"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_definition_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_definitions.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(160), nullable=False)
    instructions: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    autonomy_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="supervised")
    temperature: Mapped[float] = mapped_column(Numeric(4, 3), nullable=False, default=0)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    max_parallel_tasks: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_runtime_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    max_tool_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    max_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=100000)
    max_estimated_spend_micros: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1_000_000
    )
    scope_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    retrieval_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "agent_definition_id", "version", name="unique_agent_definition_version"
        ),
        UniqueConstraint(
            "agent_definition_id",
            "configuration_digest",
            name="unique_agent_definition_configuration",
        ),
        CheckConstraint("version > 0", name="valid_agent_definition_version_number"),
        CheckConstraint(
            "autonomy_mode IN ('manual','supervised','bounded')",
            name="valid_agent_definition_autonomy_mode",
        ),
        CheckConstraint("temperature BETWEEN 0 AND 2", name="valid_agent_temperature"),
        CheckConstraint("max_output_tokens > 0", name="valid_agent_output_tokens"),
        CheckConstraint("max_parallel_tasks BETWEEN 1 AND 30", name="valid_agent_parallel_tasks"),
        CheckConstraint("max_runtime_seconds BETWEEN 1 AND 86400", name="valid_agent_runtime"),
        CheckConstraint("max_tool_calls >= 0", name="valid_agent_tool_calls"),
        CheckConstraint("max_input_tokens > 0", name="valid_agent_input_tokens"),
        CheckConstraint(
            "max_estimated_spend_micros >= 0", name="valid_agent_estimated_spend"
        ),
        Index(
            "ix_agent_definition_versions_org_definition",
            "organization_id",
            "agent_definition_id",
        ),
    )


class AgentVersionTool(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_version_tools"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_version_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    tool_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    approval_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="policy")
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    per_run_call_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=5)

    __table_args__ = (
        UniqueConstraint("agent_version_id", "tool_name", name="unique_agent_version_tool"),
        CheckConstraint("tool_version > 0", name="valid_agent_tool_version"),
        CheckConstraint(
            "approval_mode IN ('never','policy','always')", name="valid_agent_tool_approval"
        ),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 3600", name="valid_agent_tool_timeout"),
        CheckConstraint("per_run_call_limit >= 0", name="valid_agent_tool_call_limit"),
        Index("ix_agent_version_tools_org_version", "organization_id", "agent_version_id"),
    )


class AgentVersionCollection(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_version_collections"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_version_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_collections.id", ondelete="CASCADE"), nullable=False
    )
    metadata_filter: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint(
            "agent_version_id", "collection_id", name="unique_agent_version_collection"
        ),
        Index(
            "ix_agent_version_collections_org_version",
            "organization_id",
            "agent_version_id",
        ),
    )


class AgentTemplate(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_templates"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_agent_template_name"),
        Index("ix_agent_templates_org_enabled", "organization_id", "is_enabled"),
    )


class AgentEvaluation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_evaluations"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_version_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    test_case: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    expected_criteria: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    actual_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    grader_results: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    cost_micros: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    reviewer_decision: Mapped[str | None] = mapped_column(String(20))
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("agent_version_id", "name", name="unique_agent_evaluation_name"),
        CheckConstraint("cost_micros >= 0", name="valid_agent_evaluation_cost"),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="valid_agent_evaluation_latency"),
        CheckConstraint(
            "reviewer_decision IS NULL OR reviewer_decision IN ('approved','rejected')",
            name="valid_agent_evaluation_decision",
        ),
        Index("ix_agent_evaluations_org_version", "organization_id", "agent_version_id"),
    )


__all__ = [
    "AgentDefinition",
    "AgentDefinitionVersion",
    "AgentEvaluation",
    "AgentTemplate",
    "AgentVersionCollection",
    "AgentVersionTool",
]
