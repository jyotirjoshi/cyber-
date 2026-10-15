"""Attack Surface Management surfaces — continuous passive discovery schedules."""

from __future__ import annotations

import datetime as dt
import uuid

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


class AsmSurface(Base, TenantMixin, TimestampMixin):
    """A continuously monitored attack surface.

    Owns a set of seed domains/IPs and a cron schedule; the worker calls
    :func:`app.services.asm_discovery.run_due_surfaces` to run passive
    ReconFTW discovery and merge results into the asset inventory.

    Authorization is time-bounded, same as :class:`~app.db.models.assessment.RecurringScan`:
    an expired authorization silently disables the surface and records the reason so an
    operator can renew it.  Nothing runs against a target without a valid, non-expired
    human attestation.
    """

    __tablename__ = "asm_surfaces"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    #: Seed domains / IPs / CIDRs handed to ReconFTW passive mode.
    seeds: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    #: Five-field cron expression, evaluated in ``timezone``.
    cron_expression: Mapped[str] = mapped_column(String(120), nullable=False)
    timezone: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")

    #: Human attestation: "I confirm I am authorized to run passive discovery against
    #: these assets." Stored verbatim for audit.
    authorization_text: Mapped[str] = mapped_column(Text, nullable=False)
    #: Discovery is silently suspended once this timestamp passes.
    authorization_expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: Total assets upserted in the last run (new + updated).
    last_asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: New assets (not previously in inventory) from the last run.
    last_new_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Machine-readable failure code from the most recent run, if any.
    last_error_code: Mapped[str | None] = mapped_column(String(80))

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_asm_surface_name"),
        Index("ix_asm_surfaces_org_enabled", "organization_id", "enabled"),
        Index("ix_asm_surfaces_due", "enabled", "next_run_at"),
    )


__all__ = ["AsmSurface"]
