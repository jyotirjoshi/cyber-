"""Durable tenant-scoped receipts for retry-safe GraphQL mutations."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, uuid_pk


class GraphQLMutationReceipt(Base, TenantMixin):
    """One committed effect for an actor, operation, and idempotency key."""

    __tablename__ = "graphql_mutation_receipts"

    id: Mapped[uuid.UUID] = uuid_pk()
    actor_key: Mapped[str] = mapped_column(String(80), nullable=False)
    operation: Mapped[str] = mapped_column(String(120), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(160), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(80))
    resource_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "actor_key",
            "operation",
            "idempotency_key",
            name="unique_graphql_mutation_receipt",
        ),
        Index(
            "ix_graphql_mutation_receipts_org_created",
            "organization_id",
            "created_at",
        ),
    )


__all__ = ["GraphQLMutationReceipt"]
