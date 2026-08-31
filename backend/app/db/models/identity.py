"""Organizations, users and memberships (FR-001, FR-002).

Relationships default to ``lazy="raise_on_sql"``.  Under asyncio an accidental lazy
load raises ``MissingGreenlet`` deep inside SQLAlchemy at an unpredictable moment;
raising at the attribute access instead turns that into an obvious, local bug that
the query author fixes with an explicit ``selectinload``.
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
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TimestampMixin, uuid_pk
from app.db.enums import Role

if TYPE_CHECKING:
    from app.db.models.assessment import Assessment
    from app.db.models.asset import Asset
    from app.db.models.integration import Integration


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)

    #: Per-organization overrides of the global scanner concurrency ceiling
    #: (PRD section 57: "concurrency must be configurable per organization").
    max_concurrent_scanner_jobs: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    #: Organization-level policy: extra denied targets, approval thresholds,
    #: notification routing. Validated against app.schemas.organization.OrgPolicy.
    policy: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy=LAZY
    )
    assessments: Mapped[list[Assessment]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy=LAZY
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy=LAZY
    )
    integrations: Mapped[list[Integration]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy=LAZY
    )

    __table_args__ = (
        CheckConstraint(
            "max_concurrent_scanner_jobs BETWEEN 1 AND 64",
            name="concurrency_bounds",
        ),
    )


class User(Base, TimestampMixin):
    """A person. Users are global; access to data is granted by Membership only.

    A user with no membership can authenticate but can read nothing, which keeps
    tenant isolation a property of the membership join rather than of the session.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: Counter and lock are stored rather than kept in Redis so a Redis flush cannot
    #: silently reset brute-force protection.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    #: ``foreign_keys`` is required on both sides of this relationship: ``memberships``
    #: has two foreign keys to ``users`` (``user_id`` and ``invited_by_id``), so
    #: SQLAlchemy cannot pick the join on its own.  Without it the mapper raises
    #: ``AmbiguousForeignKeysError`` -- and it would do so lazily, on first use, not at
    #: import.
    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy=LAZY,
        foreign_keys="Membership.user_id",
    )

    @property
    def display_name(self) -> str:
        return self.full_name or self.email.split("@")[0]


class Membership(Base, TimestampMixin):
    """Binds a user to an organization with exactly one role (FR-002)."""

    __tablename__ = "memberships"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(40), nullable=False, default=Role.VIEWER.value)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="memberships", lazy=LAZY)
    user: Mapped[User] = relationship(
        back_populates="memberships", lazy=LAZY, foreign_keys=[user_id]
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="unique_member"),
        CheckConstraint(
            "role IN ('owner','admin','security_engineer','developer','viewer')",
            name="valid_role",
        ),
        Index("ix_memberships_user_id_organization_id", "user_id", "organization_id"),
    )

    @property
    def role_enum(self) -> Role:
        return Role(self.role)


class PasswordResetToken(Base):
    """Single-use password reset. Only the hash is stored, so a database read does
    not hand an attacker a working reset link."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    requested_ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


__all__ = ["Membership", "Organization", "PasswordResetToken", "User"]
