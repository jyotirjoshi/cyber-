"""Audited analyst dispositions for tenant-owned canonical findings."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, InvalidConfigurationError, TenantIsolationError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.canonical import CanonicalFinding, FindingHistory
from app.db.repository import tenant_select
from app.services import audit as audit_service
from app.services.context import Principal

_ALLOWED: dict[str, frozenset[str]] = {
    "new": frozenset({"open", "accepted_risk", "false_positive"}),
    "open": frozenset({"accepted_risk", "false_positive"}),
    "reopened": frozenset({"open", "accepted_risk", "false_positive"}),
    "accepted_risk": frozenset({"open"}),
    "false_positive": frozenset({"open"}),
}


async def decide_status(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    *,
    status: str,
    reason: str,
    expected_version: int,
) -> CanonicalFinding:
    """Apply a human disposition; closure remains evidence-based only."""
    principal.require(Permission.FINDING_VALIDATE)
    clean_reason = reason.strip()
    if not clean_reason or len(clean_reason) > 2000:
        raise InvalidConfigurationError(
            "canonical finding decision reason missing or too long",
            user_message="Provide a rationale of at most 2000 characters.",
        )
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
    if finding.status_version != expected_version:
        raise ConflictError(
            "canonical finding status version changed",
            user_message="This finding changed. Refresh it before deciding again.",
        )
    if status not in _ALLOWED.get(finding.status, frozenset()):
        raise ConflictError(
            "invalid canonical finding status transition",
            user_message="This status change is not allowed from the finding's current state.",
        )
    previous = finding.status
    finding.status = status
    finding.status_version += 1
    finding.disposition_reason = clean_reason
    finding.closed_at = None
    now = utcnow()
    session.add(
        FindingHistory(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            canonical_finding_id=finding.id,
            previous_status=previous,
            new_status=status,
            reason=clean_reason,
            actor_user_id=principal.user_id,
            occurred_at=now,
        )
    )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_STATUS_CHANGE,
        principal=principal,
        resource_type="canonical_finding",
        resource_id=finding.id,
        detail={"from": previous, "to": status, "version": finding.status_version},
        reason=clean_reason,
    )
    return finding
