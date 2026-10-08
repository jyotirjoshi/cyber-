"""Tenant-scoped remediation ownership for canonical findings."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, InvalidConfigurationError, TenantIsolationError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.canonical import CanonicalFinding, FindingHistory
from app.db.models.identity import Membership, User
from app.db.repository import tenant_select
from app.schemas.canonical import CanonicalWorkIn
from app.services import audit as audit_service
from app.services.context import Principal


async def update_work(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    payload: CanonicalWorkIn,
) -> CanonicalFinding:
    """Assign an active exposure and capture a concrete plan without changing source truth."""
    principal.require(Permission.FINDING_REMEDIATE)
    rows = (
        (
            await session.execute(
                tenant_select(CanonicalFinding, principal.organization_id)
                .where(CanonicalFinding.id == finding_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        raise TenantIsolationError("canonical finding not found in organization")
    finding = rows[0]
    if finding.status_version != payload.expected_version:
        raise ConflictError(
            "canonical finding changed",
            user_message="This finding changed. Refresh it before editing remediation work.",
        )
    if finding.status in {"closed", "false_positive"}:
        raise ConflictError(
            "remediation work on inactive finding",
            user_message="Closed or false-positive findings cannot be assigned for remediation.",
        )
    changes = payload.model_dump(exclude_unset=True, exclude={"expected_version"})
    assignee = changes.get("assignee_user_id")
    if assignee is not None:
        member_id = (
            await session.execute(
                select(Membership.user_id)
                .join(User, User.id == Membership.user_id)
                .where(
                    Membership.organization_id == principal.organization_id,
                    Membership.user_id == assignee,
                    Membership.accepted_at.is_not(None),
                    User.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if member_id is None:
            raise InvalidConfigurationError(
                "assignee is not an active organization member",
                user_message="Choose an active member of this organization.",
            )
    due_at = changes.get("due_at")
    if due_at is not None and due_at <= utcnow():
        raise InvalidConfigurationError(
            "remediation due date is in the past",
            user_message="Choose a future remediation due date.",
        )
    changed = [key for key, value in changes.items() if getattr(finding, key) != value]
    if not changed:
        return finding
    for key in changed:
        setattr(finding, key, changes[key])
    finding.status_version += 1
    now = utcnow()
    session.add(
        FindingHistory(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            canonical_finding_id=finding.id,
            previous_status=finding.status,
            new_status=finding.status,
            reason=f"Remediation work updated: {', '.join(sorted(changed))}",
            actor_user_id=principal.user_id,
            occurred_at=now,
        )
    )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_WORK_UPDATE,
        principal=principal,
        resource_type="canonical_finding",
        resource_id=finding.id,
        detail={"fields": sorted(changed), "version": finding.status_version},
    )
    return finding
