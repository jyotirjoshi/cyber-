"""Outbound notifications (FR-028).

Rows are written before delivery is attempted, so a Slack outage leaves a record of
what should have been sent rather than nothing at all.  ``dedupe_key`` is what stops a
retried run from re-notifying: the same event for the same resource collapses to one
row per organization.
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
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk
from app.db.enums import NotificationChannel, NotificationEvent, NotificationStatus

if TYPE_CHECKING:
    from app.db.models.identity import User


class Notification(Base, TenantMixin, TimestampMixin):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = uuid_pk()
    event: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=NotificationStatus.PENDING.value, index=True
    )

    #: Recipient. Meaning depends on channel: Slack channel id, email address, or the
    #: user id for an in-app/websocket delivery.
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    subject: Mapped[str | None] = mapped_column(String(500))
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Channel-specific structured payload (Slack blocks, template variables).
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    resource_type: Mapped[str | None] = mapped_column(String(60))
    resource_id: Mapped[str | None] = mapped_column(String(80))
    #: Idempotency key: "<event>:<resource_id>:<channel>:<recipient>".
    dedupe_key: Mapped[str] = mapped_column(String(300), nullable=False)

    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sent_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: User-safe error text; the transport error detail goes to logs, not here.
    last_error: Mapped[str | None] = mapped_column(Text)
    #: Set when the org's notification policy filtered the event out, e.g. a low
    #: severity finding on a channel configured for critical only. Recorded rather
    #: than dropped so "why didn't I get an alert?" is answerable.
    suppressed_reason: Mapped[str | None] = mapped_column(String(200))

    recipient_user: Mapped[User | None] = relationship(lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("organization_id", "dedupe_key", name="unique_notification"),
        # ``event`` is half of ``dedupe_key`` and is what the org's notification policy
        # is keyed on. A misspelled event matches no policy rule, so it is neither
        # delivered nor recorded as suppressed -- it just silently never arrives.
        CheckConstraint(
            "event IN ('assessment_started','approval_required','critical_finding',"
            "'assessment_completed','assessment_failed','ticket_created')",
            name="valid_notification_event",
        ),
        CheckConstraint(
            "status IN ('pending','sent','failed','suppressed')", name="valid_notification_status"
        ),
        CheckConstraint(
            "channel IN ('slack','email','websocket')", name="valid_notification_channel"
        ),
        Index("ix_notifications_organization_id_status", "organization_id", "status"),
        Index("ix_notifications_resource_type_resource_id", "resource_type", "resource_id"),
    )

    @property
    def event_enum(self) -> NotificationEvent:
        return NotificationEvent(self.event)

    @property
    def channel_enum(self) -> NotificationChannel:
        return NotificationChannel(self.channel)

    @property
    def status_enum(self) -> NotificationStatus:
        return NotificationStatus(self.status)


__all__ = ["Notification"]
