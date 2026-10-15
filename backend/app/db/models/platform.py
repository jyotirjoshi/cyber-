"""Tenant-owned public platform credentials."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class UsageMeterBucket(Base, TenantMixin):
    """Monthly tenant consumption counter used for capacity and billing hooks."""

    __tablename__ = "usage_meter_buckets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    month: Mapped[dt.date] = mapped_column(Date, nullable=False)
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    quantity: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "month", "event", name="unique_usage_bucket"),
        Index("ix_usage_meter_buckets_org_month", "organization_id", "month"),
        Index("ix_usage_meter_buckets_month", "month"),
    )


class PlatformApiKey(Base, TenantMixin, TimestampMixin):
    """A scoped machine credential; only its Argon2 verifier is durable."""

    __tablename__ = "platform_api_keys"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "key_prefix", name="unique_platform_api_key_prefix"),
        Index("ix_platform_api_keys_org_active", "organization_id", "revoked_at", "expires_at"),
    )


class SavedView(Base, TenantMixin, TimestampMixin):
    """A tenant query preset, never executable query text."""

    __tablename__ = "saved_views"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    resource: Mapped[str] = mapped_column(String(20), nullable=False)
    filters: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("resource IN ('findings','assets')", name="valid_saved_view_resource"),
        UniqueConstraint("organization_id", "resource", "name", name="unique_saved_view_name"),
        Index("ix_saved_views_org_resource", "organization_id", "resource"),
    )


class DashboardLayout(Base, TenantMixin, TimestampMixin):
    """A safe, declarative dashboard composition; never arbitrary frontend code."""

    __tablename__ = "dashboard_layouts"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    audience: Mapped[str] = mapped_column(String(20), nullable=False, default="technical")
    widgets: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("audience IN ('executive','technical','team')", name="valid_dashboard_layout_audience"),
        UniqueConstraint("organization_id", "name", name="unique_dashboard_layout_name"),
        Index("ix_dashboard_layouts_org_audience", "organization_id", "audience"),
    )


class WebhookSubscription(Base, TenantMixin, TimestampMixin):
    """Tenant-owned signed outbound event destination.

    The signing secret is encrypted because a receiver needs it to verify HMAC
    signatures. It is never serialized once issued.
    """

    __tablename__ = "webhook_subscriptions"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    event_types: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    secret_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    disabled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_webhook_subscription_name"),
        Index("ix_webhook_subscriptions_org_enabled", "organization_id", "is_enabled"),
    )


__all__ = [
    "DashboardLayout",
    "PlatformApiKey",
    "SavedView",
    "UsageMeterBucket",
    "WebhookSubscription",
]
