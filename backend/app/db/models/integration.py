"""Integrations and their encrypted credentials (FR-028, SEC-001, SEC-002).

Credentials live in a separate table from the integration config for one reason: the
config is read on nearly every request (is Jira configured? which project?) while the
ciphertext is needed only at the moment a client is constructed.  Splitting them means
the common query never loads secret material into the ORM identity map at all.

Nothing here is ever logged or serialized to an API response.  The schema layer
exposes :attr:`IntegrationCredential.fingerprint` so an operator can confirm *which*
key is installed without the value being retrievable.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk
from app.db.enums import IntegrationKind, IntegrationStatus

if TYPE_CHECKING:
    from app.db.models.identity import Organization, User


class Integration(Base, TenantMixin, TimestampMixin):
    __tablename__ = "integrations"

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    #: Operator-facing label, so two Jira instances are distinguishable.
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=IntegrationStatus.UNVERIFIED.value
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    base_url: Mapped[str | None] = mapped_column(String(1000))
    #: Non-secret settings only: project keys, product names, channel ids, template
    #: choices. A validator on the schema rejects anything that looks like a secret so
    #: a token cannot be smuggled into a field that the API returns in plaintext.
    config: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    #: Result of the last connectivity probe. FR-028 requires configuration to be
    #: verifiable rather than assumed, and a stale "configured" flag is worse than an
    #: honest "unverified".
    last_verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: Consecutive failures. The circuit breaker is in Redis for speed; this is the
    #: durable counter an operator sees on the settings screen.
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    organization: Mapped[Organization] = relationship(back_populates="integrations", lazy=LAZY)
    credentials: Mapped[list[IntegrationCredential]] = relationship(
        back_populates="integration", cascade="all, delete-orphan", lazy=LAZY
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "kind", "name", name="unique_integration"),
        # ``kind`` chooses the client class and the credential slots that client expects.
        # An unrecognized kind is a row that can be configured through the API and then
        # never used by anything, which looks to an operator like a working integration.
        CheckConstraint(
            "kind IN ('defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab')",
            name="valid_integration_kind",
        ),
        CheckConstraint(
            "status IN ('configured','unverified','error','disabled')",
            name="valid_integration_status",
        ),
        Index("ix_integrations_organization_id_kind", "organization_id", "kind"),
    )

    @property
    def kind_enum(self) -> IntegrationKind:
        return IntegrationKind(self.kind)

    @property
    def status_enum(self) -> IntegrationStatus:
        return IntegrationStatus(self.status)

    @property
    def is_usable(self) -> bool:
        """Enabled and not known-broken. An unverified integration is still tried --
        refusing to try is how a working setup gets reported as broken forever."""
        return self.is_enabled and self.status != IntegrationStatus.DISABLED.value


class IntegrationCredential(Base, TenantMixin, TimestampMixin):
    """One encrypted secret belonging to an integration (SEC-001).

    Encryption is envelope-style via ``MultiFernet``: the current key encrypts, all
    previous keys can still decrypt, so a key rotation is a config change plus a
    background re-encrypt rather than an outage.  ``key_version`` records which key
    sealed the row so the re-encrypt pass knows what is left to do.
    """

    __tablename__ = "integration_credentials"

    id: Mapped[uuid.UUID] = uuid_pk()
    integration_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False
    )
    #: Logical slot: "api_token", "username", "webhook_url", "bot_token".
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    #: Fernet token. Bytes, not text, so no encoding layer can mangle it.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    #: First 8 hex chars of SHA-256 over the plaintext. Enough to answer "is this the
    #: token I generated?" without being enough to reconstruct it.
    fingerprint: Mapped[str | None] = mapped_column(String(16))
    #: Last four characters, for UI display as "****abcd". Deliberately short.
    hint: Mapped[str | None] = mapped_column(String(8))

    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    integration: Mapped[Integration] = relationship(back_populates="credentials", lazy=LAZY)
    created_by: Mapped[User | None] = relationship(lazy=LAZY)

    __table_args__ = (UniqueConstraint("integration_id", "name", name="unique_credential_name"),)

    def __repr__(self) -> str:  # pragma: no cover - defensive
        # Overridden so an accidental repr in a traceback or log cannot print bytes.
        return f"<IntegrationCredential {self.name} [REDACTED]>"


__all__ = ["Integration", "IntegrationCredential"]
