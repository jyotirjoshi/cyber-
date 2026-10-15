"""Tenant-scoped remediation ownership for canonical findings."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, InvalidConfigurationError, TenantIsolationError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingHistory
from app.db.models.identity import Membership, User
from app.db.repository import tenant_select
from app.schemas.canonical import BulkCanonicalWorkIn, CanonicalWorkIn
from app.services import audit as audit_service
from app.services.context import Principal


def remediation_group_key(value: str | None) -> str | None:
    """Stable comparison key; preserve the display label separately for operators."""
    # PostgreSQL's migration backfill uses lower(), so runtime writes must use the
    # same normalization rather than Python casefold() (which differs for a few
    # Unicode characters and would split historical groups).
    return value.lower() if value is not None else None


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
    if "remediation_group" in changed:
        finding.remediation_group_key = remediation_group_key(finding.remediation_group)
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
    asset = (
        await session.execute(
            tenant_select(Asset, principal.organization_id).where(Asset.id == finding.asset_id)
        )
    ).scalar_one_or_none()
    if asset is not None:
        # Imported here because the automation executor invokes this service.
        from app.services.automation import queue_finding_event

        await queue_finding_event(
            session,
            finding=finding,
            asset=asset,
            trigger="finding.updated",
            event_key_suffix=f":version:{finding.status_version}",
        )
    return finding


async def bulk_update_work(
    session: AsyncSession,
    principal: Principal,
    payload: BulkCanonicalWorkIn,
) -> list[CanonicalFinding]:
    """Apply a bounded work batch only when every tenant finding is still current.

    The preflight deliberately completes before a field is written, so a stale or
    inaccessible item cannot leave an earlier item in the same request partially changed.
    """
    principal.require(Permission.FINDING_REMEDIATE)
    item_by_id = {item.finding_id: item for item in payload.items}
    rows = (
        (
            await session.execute(
                tenant_select(CanonicalFinding, principal.organization_id)
                .where(CanonicalFinding.id.in_(item_by_id))
                .order_by(CanonicalFinding.id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    findings = {finding.id: finding for finding in rows}
    if len(findings) != len(item_by_id):
        raise TenantIsolationError("one or more canonical findings were not found in organization")
    now = utcnow()
    for item in payload.items:
        finding = findings[item.finding_id]
        if finding.status_version != item.expected_version:
            raise ConflictError(
                "canonical finding changed",
                user_message="One or more findings changed. Refresh them before bulk editing.",
            )
        if finding.status in {"closed", "false_positive"}:
            raise ConflictError(
                "remediation work on inactive finding",
                user_message="Closed or false-positive findings cannot be assigned for remediation.",
            )
        if item.due_at is not None and item.due_at <= now:
            raise InvalidConfigurationError(
                "remediation due date is in the past",
                user_message="Choose future remediation due dates.",
            )
    assignee_ids = {
        item.assignee_user_id for item in payload.items if item.assignee_user_id is not None
    }
    if assignee_ids:
        member_rows = await session.execute(
            select(Membership.user_id)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == principal.organization_id,
                Membership.user_id.in_(assignee_ids),
                Membership.accepted_at.is_not(None),
                User.is_active.is_(True),
            )
        )
        active_assignees = set(member_rows.scalars().all())
        if active_assignees != assignee_ids:
            raise InvalidConfigurationError(
                "assignee is not an active organization member",
                user_message="Choose active members of this organization.",
            )
    updated: list[CanonicalFinding] = []
    changed_findings: list[CanonicalFinding] = []
    for item in payload.items:
        finding = findings[item.finding_id]
        changes = item.model_dump(
            exclude_unset=True, exclude={"finding_id", "expected_version"}
        )
        changed = [key for key, value in changes.items() if getattr(finding, key) != value]
        if not changed:
            updated.append(finding)
            continue
        for key in changed:
            setattr(finding, key, changes[key])
        if "remediation_group" in changed:
            finding.remediation_group_key = remediation_group_key(finding.remediation_group)
        finding.status_version += 1
        session.add(
            FindingHistory(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                canonical_finding_id=finding.id,
                previous_status=finding.status,
                new_status=finding.status,
                reason=f"Bulk remediation work updated: {', '.join(sorted(changed))}",
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
            detail={"fields": sorted(changed), "version": finding.status_version, "bulk": True},
        )
        changed_findings.append(finding)
        updated.append(finding)
    if changed_findings:
        # Keep this dependency local: automation actions call bulk_update_work.
        from app.services.automation import queue_finding_event

        asset_ids = {finding.asset_id for finding in changed_findings}
        assets = (
            await session.execute(
                tenant_select(Asset, principal.organization_id).where(Asset.id.in_(asset_ids))
            )
        ).scalars().all()
        assets_by_id = {asset.id: asset for asset in assets}
        for finding in changed_findings:
            asset = assets_by_id.get(finding.asset_id)
            if asset is not None:
                await queue_finding_event(
                    session,
                    finding=finding,
                    asset=asset,
                    trigger="finding.updated",
                    event_key_suffix=f":version:{finding.status_version}",
                )
    return updated
