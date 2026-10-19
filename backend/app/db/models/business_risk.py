"""Tenant-owned business services and quantitative cyber-risk scenarios."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
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


class BusinessService(Base, TenantMixin, TimestampMixin):
    __tablename__ = "business_services"

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner_team: Mapped[str | None] = mapped_column(String(120))
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="normal")
    environment: Mapped[str] = mapped_column(String(20), nullable=False, default="production")
    revenue_per_hour_usd: Mapped[float | None] = mapped_column(Float)
    maximum_loss_usd: Mapped[float | None] = mapped_column(Float)
    data_records_at_risk: Mapped[int | None] = mapped_column(Integer)
    regulatory_scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="unique_business_service_slug"),
        CheckConstraint(
            "criticality IN ('critical','high','normal','low')",
            name="valid_business_service_criticality",
        ),
        CheckConstraint(
            "environment IN ('production','staging','development','test')",
            name="valid_business_service_environment",
        ),
        CheckConstraint("status IN ('active','retired')", name="valid_business_service_status"),
        CheckConstraint("version > 0", name="valid_business_service_version"),
        CheckConstraint(
            "revenue_per_hour_usd IS NULL OR revenue_per_hour_usd >= 0",
            name="valid_business_service_revenue",
        ),
        CheckConstraint(
            "maximum_loss_usd IS NULL OR maximum_loss_usd >= 0",
            name="valid_business_service_maximum_loss",
        ),
        CheckConstraint(
            "data_records_at_risk IS NULL OR data_records_at_risk >= 0",
            name="valid_business_service_records",
        ),
        Index("ix_business_services_org_status", "organization_id", "status"),
    )


class AssetBusinessService(Base, TenantMixin, TimestampMixin):
    __tablename__ = "asset_business_services"

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    business_service_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    dependency_type: Mapped[str] = mapped_column(String(30), nullable=False, default="supporting")
    importance_weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    recovery_time_minutes: Mapped[int | None] = mapped_column(Integer)
    recovery_point_minutes: Mapped[int | None] = mapped_column(Integer)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "business_service_id", name="unique_asset_business_service"
        ),
        CheckConstraint(
            "dependency_type IN ('primary','supporting','data_store','identity','network')",
            name="valid_business_service_dependency_type",
        ),
        CheckConstraint(
            "importance_weight BETWEEN 0.1 AND 10",
            name="valid_business_service_importance",
        ),
        CheckConstraint(
            "recovery_time_minutes IS NULL OR recovery_time_minutes >= 0",
            name="valid_business_service_rto",
        ),
        CheckConstraint(
            "recovery_point_minutes IS NULL OR recovery_point_minutes >= 0",
            name="valid_business_service_rpo",
        ),
        Index("ix_asset_business_services_org_service", "organization_id", "business_service_id"),
        Index("ix_asset_business_services_org_asset", "organization_id", "asset_id"),
    )


class BusinessRiskScenario(Base, TenantMixin, TimestampMixin):
    __tablename__ = "business_risk_scenarios"

    id: Mapped[uuid.UUID] = uuid_pk()
    business_service_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    threat_event: Mapped[str] = mapped_column(String(200), nullable=False)
    annual_probability: Mapped[float] = mapped_column(Float, nullable=False)
    loss_min_usd: Mapped[float] = mapped_column(Float, nullable=False)
    loss_likely_usd: Mapped[float] = mapped_column(Float, nullable=False)
    loss_max_usd: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "business_service_id", "name", name="unique_business_service_risk_scenario"
        ),
        CheckConstraint(
            "annual_probability BETWEEN 0 AND 1", name="valid_risk_scenario_probability"
        ),
        CheckConstraint(
            "loss_min_usd >= 0 AND loss_likely_usd >= loss_min_usd AND loss_max_usd >= loss_likely_usd",
            name="valid_risk_scenario_loss_range",
        ),
        CheckConstraint("status IN ('active','archived')", name="valid_risk_scenario_status"),
        Index("ix_business_risk_scenarios_org_service", "organization_id", "business_service_id"),
    )

    @property
    def annualized_loss_expectancy_usd(self) -> float:
        triangular_mean = (self.loss_min_usd + self.loss_likely_usd + self.loss_max_usd) / 3
        return round(self.annual_probability * triangular_mean, 2)


__all__ = ["AssetBusinessService", "BusinessRiskScenario", "BusinessService"]
