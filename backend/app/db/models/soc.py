"""Durable SOC case-management and detection-engineering persistence."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class SocIncidentCase(Base, TenantMixin, TimestampMixin):
    __tablename__ = "soc_incident_cases"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_key: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    threat_story_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("security_threat_stories.id", ondelete="SET NULL"))
    assigned_user_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    owner_team: Mapped[str | None] = mapped_column(String(120))
    event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    asset_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    finding_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    resolution: Mapped[str | None] = mapped_column(Text)
    opened_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    contained_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("organization_id", "case_key", name="unique_soc_incident_case_key"),
        CheckConstraint("severity IN ('info','low','medium','high','critical')", name="valid_soc_case_severity"),
        CheckConstraint("status IN ('open','investigating','contained','resolved','dismissed')", name="valid_soc_case_status"),
        CheckConstraint("priority BETWEEN 0 AND 100", name="valid_soc_case_priority"),
        Index("ix_soc_cases_org_status", "organization_id", "status"),
        Index("ix_soc_cases_org_assignee", "organization_id", "assigned_user_id"),
    )


class SocCaseTask(Base, TenantMixin, TimestampMixin):
    __tablename__ = "soc_case_tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("soc_incident_cases.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    assigned_user_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        CheckConstraint("status IN ('open','in_progress','blocked','completed','cancelled')", name="valid_soc_case_task_status"),
        Index("ix_soc_case_tasks_org_case", "organization_id", "case_id"),
        Index("ix_soc_case_tasks_org_status", "organization_id", "status"),
    )


class DetectionRule(Base, TenantMixin, TimestampMixin):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    rule_key: Mapped[str] = mapped_column(String(160), nullable=False)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    minimum_event_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    event_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    group_by: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    auto_create_case: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    last_matched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("organization_id", "rule_key", name="unique_detection_rule_key"),
        CheckConstraint("status IN ('draft','active','disabled')", name="valid_detection_rule_status"),
        CheckConstraint("severity IN ('info','low','medium','high','critical')", name="valid_detection_rule_severity"),
        CheckConstraint("minimum_event_severity IN ('info','low','medium','high','critical')", name="valid_detection_rule_minimum_severity"),
        CheckConstraint("version > 0", name="valid_detection_rule_version"),
        Index("ix_detection_rules_org_status", "organization_id", "status"),
    )


class DetectionRuleMatch(Base, TenantMixin, TimestampMixin):
    __tablename__ = "detection_rule_matches"

    id: Mapped[uuid.UUID] = uuid_pk()
    rule_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("soc_incident_cases.id", ondelete="SET NULL"))
    matched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id", "event_id", name="unique_detection_rule_event_match"),
        Index("ix_detection_matches_org_rule", "organization_id", "rule_id"),
        Index("ix_detection_matches_org_case", "organization_id", "case_id"),
    )


__all__ = ["DetectionRule", "DetectionRuleMatch", "SocCaseTask", "SocIncidentCase"]
