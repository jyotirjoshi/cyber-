"""Tenant-scoped ledger for alerts ingested from external security platforms."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    from app.db.models.integration import Integration


class ExternalSecurityAlert(Base, TenantMixin, TimestampMixin):
    """A normalized, source-preserving security alert.

    These alerts deliberately do not share ``findings``' DefectDojo identifier.
    A correlation step may later promote a vetted alert into a finding, but raw
    external evidence remains attributable to its original provider.
    """

    __tablename__ = "external_security_alerts"

    id: Mapped[uuid.UUID] = uuid_pk()
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info", index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open", index=True)
    resource: Mapped[str | None] = mapped_column(String(1000))
    source_url: Mapped[str | None] = mapped_column(String(2000))
    cve_ids: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    #: The provider document is retained for authorized correlation, never returned
    #: directly by a generic API endpoint because it may contain sensitive code paths.
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    integration: Mapped[Integration | None] = relationship(lazy=LAZY)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", "external_id", name="unique_external_security_alert"
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="valid_external_alert_severity"
        ),
        CheckConstraint(
            "status IN ('open','resolved','dismissed','fixed')", name="valid_external_alert_status"
        ),
        Index("ix_external_alerts_org_provider_status", "organization_id", "provider", "status"),
    )


__all__ = ["ExternalSecurityAlert"]
