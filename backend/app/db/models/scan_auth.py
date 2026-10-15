"""Write-only authenticated scanner profiles."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class ScanAuthProfile(Base, TenantMixin, TimestampMixin):
    __tablename__ = "scan_auth_profiles"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_patterns: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    permitted_scanners: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    hint: Mapped[str | None] = mapped_column(String(8))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_validated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint(
            "auth_type IN ('basic','bearer','header','cookie','openapi_token','aws_static','aws_role','azure_service_principal','gcp_service_account')",
            name="valid_scan_auth_type",
        ),
        Index("ix_scan_auth_profiles_org_active", "organization_id", "is_active"),
    )


__all__ = ["ScanAuthProfile"]
