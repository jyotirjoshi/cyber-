"""Declarative, tenant-owned HTTP connector definitions and execution history."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class CustomConnector(Base, TenantMixin, TimestampMixin):
    __tablename__ = "custom_connectors"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    routes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    pagination: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    field_mapping: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    output_type: Mapped[str] = mapped_column(String(32), nullable=False)
    credential_integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL")
    )
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    __table_args__ = (
        CheckConstraint("output_type IN ('external_alert','canonical_finding')", name="valid_custom_connector_output"),
        CheckConstraint("rate_limit_per_minute BETWEEN 1 AND 600", name="valid_custom_connector_rate_limit"),
        UniqueConstraint("organization_id", "name", name="unique_custom_connector_name"),
        Index("ix_custom_connectors_org_enabled", "organization_id", "is_enabled"),
    )


class CustomConnectorRun(Base, TenantMixin, TimestampMixin):
    __tablename__ = "custom_connector_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("custom_connectors.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    checkpoint: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    records_read: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(80))
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("status IN ('running','completed','failed')", name="valid_custom_connector_run_status"),
        Index("ix_custom_connector_runs_org_connector_time", "organization_id", "connector_id", "created_at"),
    )


__all__ = ["CustomConnector", "CustomConnectorRun"]
