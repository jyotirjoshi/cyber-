"""Audit events (FR-029).

Two properties make this table useful in an incident review rather than merely
present: it is append-only (no ``updated_at``, no update path in the repository), and
every row records the *actor*, the *target*, the *outcome* and the *source address*.
An authorization denial is as interesting as a success, which is why
:class:`~app.db.enums.AuditOutcome` includes ``denied`` and the middleware writes a
row on 403 as well as on 200.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, uuid_pk
from app.db.enums import AuditOutcome

if TYPE_CHECKING:
    from app.db.models.identity import User


class AuditEvent(Base):
    """One recorded action.

    ``organization_id`` is nullable and the table deliberately does *not* use
    ``TenantMixin``: a failed login or a cross-tenant access attempt has no valid
    organization context, and those are exactly the events worth keeping.  Reads are
    still tenant-filtered at the query layer for anyone below platform admin.
    """

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    #: Denormalized so the trail survives user deletion -- an audit row that says
    #: "deleted user" is much less useful six months later.
    actor_email: Mapped[str | None] = mapped_column(String(320))
    #: "user", "agent", "system", "worker". Distinguishing agent actions from human
    #: ones is required to answer "did a person approve this, or did the agent?".
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False, default="user")

    #: Dotted verb: "assessment.create", "approval.grant", "scanner.execute",
    #: "integration.credential.update", "auth.login.failed".
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    #: Resource kind and id, e.g. ("assessment", "<uuid>").
    resource_type: Mapped[str | None] = mapped_column(String(60))
    resource_id: Mapped[str | None] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AuditOutcome.SUCCESS.value
    )

    #: Structured context. Passed through the same redaction processor as the logger,
    #: so a credential value cannot land here (SEC-002).
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    #: For denials and failures: the user-safe reason.
    reason: Mapped[str | None] = mapped_column(Text)

    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    #: Correlates the row with an OpenTelemetry trace and a LangSmith run.
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    actor: Mapped[User | None] = relationship(lazy=LAZY)

    __table_args__ = (
        CheckConstraint("outcome IN ('success','failure','denied')", name="valid_outcome"),
        CheckConstraint(
            "actor_type IN ('user','agent','system','worker')", name="valid_actor_type"
        ),
        Index("ix_audit_events_organization_id_created_at", "organization_id", "created_at"),
        Index("ix_audit_events_organization_id_action", "organization_id", "action"),
        Index("ix_audit_events_resource_type_resource_id", "resource_type", "resource_id"),
    )

    @property
    def outcome_enum(self) -> AuditOutcome:
        return AuditOutcome(self.outcome)


__all__ = ["AuditEvent"]
