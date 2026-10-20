"""Governed control inheritance and compliance evidence-request workflows."""

from __future__ import annotations

import datetime as dt
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.assurance import ComplianceControlInheritance, ComplianceEvidenceRequest
from app.db.models.compliance import (
    ComplianceAuditWorkspace,
    ComplianceControl,
    ComplianceEvidenceItem,
)
from app.db.models.identity import Membership, User
from app.db.repository import TenantRepository, tenant_select
from app.schemas.assurance import (
    ComplianceEvidenceRequestCreateIn,
    ComplianceEvidenceRequestTransitionIn,
    ComplianceInheritanceCreateIn,
)
from app.services.context import Principal

_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"collecting", "cancelled"}),
    "collecting": frozenset({"submitted", "cancelled"}),
    "submitted": frozenset({"accepted", "rejected"}),
    "rejected": frozenset({"collecting", "cancelled"}),
    "accepted": frozenset(),
    "cancelled": frozenset(),
}


def validate_inheritance_graph(relationships: Iterable[Mapping[str, Any]]) -> None:
    """Reject self edges and cycles while allowing legitimate shared inheritance."""

    parents: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for relationship in relationships:
        child = str(relationship["control_id"])
        parent = str(relationship["parent_control_id"])
        if child == parent:
            raise ValueError("a control cannot inherit from itself")
        parents[child].add(parent)
        nodes.update((child, parent))

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError("control inheritance cycle detected")
        if node in visited:
            return
        visiting.add(node)
        for parent in parents.get(node, ()):
            visit(parent)
        visiting.remove(node)
        visited.add(node)

    for node in nodes:
        visit(node)


def validate_evidence_request_transition(current: str, target: str) -> None:
    if target not in _TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid evidence request transition from {current} to {target}")


def _aware(moment: dt.datetime) -> dt.datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=dt.UTC)


def evidence_freshness(
    *,
    collected_at: dt.datetime | None,
    valid_until: dt.datetime | None,
    freshness_days: int,
    measured_at: dt.datetime | None = None,
) -> dict[str, Any]:
    """Return an explainable freshness decision for a submitted evidence artifact."""

    now = _aware(measured_at or utcnow())
    if collected_at is None:
        return {"fresh": False, "reason": "not_collected", "age_days": None}
    collected = _aware(collected_at)
    age = now - collected
    age_days = max(0, age.days)
    if collected > now:
        return {"fresh": False, "reason": "collection_time_in_future", "age_days": 0}
    if valid_until is not None and _aware(valid_until) < now:
        return {"fresh": False, "reason": "artifact_expired", "age_days": age_days}
    if age > dt.timedelta(days=freshness_days):
        return {
            "fresh": False,
            "reason": "freshness_window_exceeded",
            "age_days": age_days,
        }
    return {"fresh": True, "reason": "fresh", "age_days": age_days}


async def _require_tenant_user(
    session: AsyncSession, organization_id: uuid.UUID, user_id: uuid.UUID | None
) -> None:
    if user_id is None:
        return
    user_id_found = await session.scalar(
        select(User.id)
        .join(Membership, Membership.user_id == User.id)
        .where(
            User.id == user_id,
            User.is_active.is_(True),
            Membership.organization_id == organization_id,
        )
    )
    if user_id_found is None:
        raise ResourceNotFoundError("evidence request assignee not found")


async def create_inheritance(
    session: AsyncSession,
    principal: Principal,
    payload: ComplianceInheritanceCreateIn,
) -> ComplianceControlInheritance:
    principal.require(Permission.ORG_MANAGE)
    controls = list(
        (
            await session.scalars(
                tenant_select(ComplianceControl, principal.organization_id).where(
                    ComplianceControl.id.in_((payload.control_id, payload.parent_control_id))
                )
            )
        ).all()
    )
    if len({row.id for row in controls}) != 2:
        raise ResourceNotFoundError("an inheritance control was not found")
    existing = list(
        (
            await session.scalars(
                tenant_select(ComplianceControlInheritance, principal.organization_id)
            )
        ).all()
    )
    try:
        validate_inheritance_graph(
            [
                {"control_id": row.control_id, "parent_control_id": row.parent_control_id}
                for row in existing
            ]
            + [
                {
                    "control_id": payload.control_id,
                    "parent_control_id": payload.parent_control_id,
                }
            ]
        )
    except ValueError as exc:
        raise ConflictError(str(exc)) from exc
    row = ComplianceControlInheritance(
        organization_id=principal.organization_id,
        control_id=payload.control_id,
        parent_control_id=payload.parent_control_id,
        source_system=payload.source_system.strip(),
        responsibility=payload.responsibility,
        inherited_percentage=payload.inherited_percentage,
        evidence_refs=list(
            dict.fromkeys(value.strip() for value in payload.evidence_refs if value.strip())
        ),
    )
    try:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    except IntegrityError as exc:
        raise ConflictError("this control inheritance already exists") from exc
    return row


async def list_inheritances(
    session: AsyncSession,
    principal: Principal,
    *,
    control_id: uuid.UUID | None = None,
) -> list[ComplianceControlInheritance]:
    principal.require(Permission.FINDING_READ)
    statement = tenant_select(ComplianceControlInheritance, principal.organization_id)
    if control_id is not None:
        statement = statement.where(ComplianceControlInheritance.control_id == control_id)
    rows = await session.scalars(
        statement.order_by(
            ComplianceControlInheritance.control_id,
            ComplianceControlInheritance.parent_control_id,
        )
    )
    return list(rows.all())


async def delete_inheritance(
    session: AsyncSession, principal: Principal, inheritance_id: uuid.UUID
) -> ComplianceControlInheritance:
    principal.require(Permission.ORG_MANAGE)
    row = await TenantRepository(
        session, ComplianceControlInheritance, principal.organization_id
    ).get_or_404(inheritance_id)
    await session.delete(row)
    await session.flush()
    return row


async def create_evidence_request(
    session: AsyncSession,
    principal: Principal,
    payload: ComplianceEvidenceRequestCreateIn,
) -> ComplianceEvidenceRequest:
    principal.require(Permission.ORG_MANAGE)
    workspace = await TenantRepository(
        session, ComplianceAuditWorkspace, principal.organization_id
    ).get_or_404(payload.workspace_id)
    control = await TenantRepository(
        session, ComplianceControl, principal.organization_id
    ).get_or_404(payload.control_id)
    if control.framework != workspace.framework:
        raise ConflictError("evidence request control is outside the workspace framework")
    if workspace.control_ids and str(control.id) not in workspace.control_ids:
        raise ConflictError("evidence request control is outside the workspace scope")
    await _require_tenant_user(session, principal.organization_id, payload.assignee_user_id)
    now = utcnow()
    if payload.due_at is not None and _aware(payload.due_at) <= now:
        raise ConflictError("evidence request due date must be in the future")
    row = ComplianceEvidenceRequest(
        organization_id=principal.organization_id,
        workspace_id=workspace.id,
        control_id=control.id,
        request_key=payload.request_key.strip(),
        title=payload.title.strip(),
        description=payload.description.strip(),
        assignee_user_id=payload.assignee_user_id,
        requested_by_id=principal.user_id,
        status="open",
        freshness_days=payload.freshness_days,
        due_at=_aware(payload.due_at) if payload.due_at is not None else None,
        fulfilled_evidence_ids=[],
        status_changed_at=now,
    )
    try:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    except IntegrityError as exc:
        raise ConflictError("evidence request key already exists") from exc
    return row


async def list_evidence_requests(
    session: AsyncSession,
    principal: Principal,
    *,
    workspace_id: uuid.UUID | None = None,
    status: str | None = None,
) -> list[ComplianceEvidenceRequest]:
    principal.require(Permission.FINDING_READ)
    statement = tenant_select(ComplianceEvidenceRequest, principal.organization_id)
    if workspace_id is not None:
        statement = statement.where(ComplianceEvidenceRequest.workspace_id == workspace_id)
    if status is not None:
        if status not in _TRANSITIONS:
            raise ConflictError("unknown evidence request status")
        statement = statement.where(ComplianceEvidenceRequest.status == status)
    rows = await session.scalars(
        statement.order_by(
            ComplianceEvidenceRequest.due_at.asc().nullslast(),
            ComplianceEvidenceRequest.created_at.desc(),
        )
    )
    return list(rows.all())


async def _verified_fresh_evidence(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    control_id: uuid.UUID,
    evidence_ids: list[uuid.UUID],
    freshness_days: int,
    measured_at: dt.datetime,
) -> list[ComplianceEvidenceItem]:
    unique_ids = list(dict.fromkeys(evidence_ids))
    if not unique_ids:
        raise ConflictError("submission requires at least one verified evidence item")
    rows = list(
        (
            await session.scalars(
                tenant_select(ComplianceEvidenceItem, organization_id).where(
                    ComplianceEvidenceItem.id.in_(unique_ids),
                    ComplianceEvidenceItem.control_id == control_id,
                    ComplianceEvidenceItem.collection_status == "verified",
                )
            )
        ).all()
    )
    if len(rows) != len(unique_ids):
        raise ConflictError("submission contains missing, unverified, or out-of-scope evidence")
    stale = [
        str(row.id)
        for row in rows
        if not evidence_freshness(
            collected_at=row.collected_at,
            valid_until=row.valid_until,
            freshness_days=freshness_days,
            measured_at=measured_at,
        )["fresh"]
    ]
    if stale:
        raise ConflictError(f"submission contains stale evidence: {', '.join(sorted(stale))}")
    return rows


async def transition_evidence_request(
    session: AsyncSession,
    principal: Principal,
    request_id: uuid.UUID,
    payload: ComplianceEvidenceRequestTransitionIn,
) -> ComplianceEvidenceRequest:
    principal.require(Permission.REPORT_GENERATE)
    row = await session.scalar(
        tenant_select(ComplianceEvidenceRequest, principal.organization_id)
        .where(ComplianceEvidenceRequest.id == request_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("compliance evidence request not found")
    if row.status != payload.expected_status:
        raise ConflictError(
            f"evidence request changed from expected status {payload.expected_status} to {row.status}"
        )
    try:
        validate_evidence_request_transition(row.status, payload.status)
    except ValueError as exc:
        raise ConflictError(str(exc)) from exc
    now = utcnow()
    if payload.status == "submitted":
        evidence = await _verified_fresh_evidence(
            session,
            organization_id=principal.organization_id,
            control_id=row.control_id,
            evidence_ids=payload.evidence_ids,
            freshness_days=row.freshness_days,
            measured_at=now,
        )
        row.fulfilled_evidence_ids = sorted(str(item.id) for item in evidence)
        row.submitted_by_id = principal.user_id
        row.submitted_at = now
        row.reviewed_by_id = None
        row.review_note = None
    elif payload.status in {"accepted", "rejected"}:
        if principal.user_id is None:
            raise ConflictError("evidence review requires an attributable human user")
        if principal.user_id in {
            row.requested_by_id,
            row.submitted_by_id,
        }:
            raise ConflictError("evidence must be reviewed by an independent user")
        if payload.status == "accepted":
            evidence_ids = [uuid.UUID(value) for value in row.fulfilled_evidence_ids]
            await _verified_fresh_evidence(
                session,
                organization_id=principal.organization_id,
                control_id=row.control_id,
                evidence_ids=evidence_ids,
                freshness_days=row.freshness_days,
                measured_at=now,
            )
            row.fulfilled_at = now
        elif not payload.note or len(payload.note.strip()) < 3:
            raise ConflictError("rejected evidence requires a review note")
        row.reviewed_by_id = principal.user_id
        row.review_note = payload.note.strip() if payload.note else None
    elif payload.status == "collecting" and row.status == "rejected":
        row.reviewed_by_id = None
        row.review_note = None
        row.fulfilled_at = None
    row.status = payload.status
    row.status_changed_at = now
    await session.flush()
    return row


__all__ = [
    "create_evidence_request",
    "create_inheritance",
    "delete_inheritance",
    "evidence_freshness",
    "list_evidence_requests",
    "list_inheritances",
    "transition_evidence_request",
    "validate_evidence_request_transition",
    "validate_inheritance_graph",
]
