"""Deterministic, durable escalation of overdue remediation work."""

from __future__ import annotations

import datetime as dt
import uuid

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.base import utcnow
from app.db.enums import NotificationEvent, Severity
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, SlaEscalation
from app.services.automation import queue_finding_event
from app.services.context import Principal
from app.services.notification import NotificationContent, dispatch


def breach_level(now: dt.datetime, due_at: dt.datetime) -> int:
    """Return the highest escalation level due at ``now``.

    Level one is due immediately; later levels add meaningful follow-up without
    repeatedly paging an owner on every worker maintenance tick.
    """
    if now < due_at + dt.timedelta(days=7):
        return 1
    if now < due_at + dt.timedelta(days=14):
        return 2
    return 3


async def emit_overdue_sla_escalations(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Redis | None,
    now: dt.datetime | None = None,
    limit: int = 100,
) -> int:
    """Persist and notify every newly due escalation level exactly once.

    The unique database constraint is the concurrency boundary. A second worker can
    see the same finding but cannot create another escalation, notification, or
    downstream automation event for that level.
    """
    current_time = now or utcnow()
    rows = await session.execute(
        select(CanonicalFinding, Asset)
        .join(Asset, Asset.id == CanonicalFinding.asset_id)
        .where(
            CanonicalFinding.due_at.is_not(None),
            CanonicalFinding.due_at <= current_time,
            CanonicalFinding.status.in_(("new", "open", "reopened", "mitigated")),
        )
        .order_by(CanonicalFinding.due_at, CanonicalFinding.id)
        .limit(max(1, min(limit, 500)))
        .with_for_update(skip_locked=True)
    )
    emitted = 0
    for finding, asset in rows.all():
        if finding.organization_id != asset.organization_id or finding.due_at is None:
            continue
        level = breach_level(current_time, finding.due_at)
        inserted = await session.execute(
            pg_insert(SlaEscalation)
            .values(
                id=uuid.uuid4(),
                organization_id=finding.organization_id,
                canonical_finding_id=finding.id,
                level=level,
                due_at=finding.due_at,
                escalated_at=current_time,
            )
            .on_conflict_do_nothing(constraint="unique_sla_escalation_level")
            .returning(SlaEscalation.id)
        )
        if inserted.scalar_one_or_none() is None:
            continue
        principal = Principal.for_system(organization_id=finding.organization_id)
        severity = Severity.parse(finding.severity)
        resource_id = f"{finding.id}:sla:{level}"
        await dispatch(
            session,
            principal,
            event=NotificationEvent.SLA_BREACH,
            content=NotificationContent(
                subject=f"SLA breach level {level}: {finding.title}",
                body=(
                    f"{severity.value.title()} finding is overdue at escalation level {level}. "
                    "Review ownership, remediation progress, or a documented risk exception."
                ),
                link=f"/findings/{finding.id}",
            ),
            settings=settings,
            redis=redis,
            resource_type="canonical_finding",
            resource_id=resource_id,
            severity=severity,
        )
        await queue_finding_event(
            session,
            finding=finding,
            asset=asset,
            trigger="sla.breached",
            event_key_suffix=f":level:{level}",
        )
        emitted += 1
    return emitted


__all__ = ["breach_level", "emit_overdue_sla_escalations"]
