"""The FR-011 human-in-the-loop gate.

An approval row is *authority*, not a notification.  Everything here exists to keep that
true in the presence of replays, races, and stale UI.

**One pending approval per assessment.**  :func:`open_approval` is idempotent on
``(assessment_id, kind, decision='pending')`` and returns the existing row rather than
adding a second.  A resumed graph re-entering the approval node must not produce two gates,
because a second row is a second chance to approve something the operator already rejected.

**Resolution is a single atomic UPDATE.**  :func:`resolve_approval` narrows on
``decision = 'pending'`` in the ``WHERE`` clause and checks ``rowcount``, so two operators
clicking Approve at the same moment produce one grant and one
:class:`~app.core.errors.ConflictError`.  A read-then-write would let both succeed and the
second would silently overwrite the first's ``approved_payload``.

**``approved_payload`` is computed here, from the request and the decision.**  It is what
the scanner layer is driven by, so it is never taken from the client verbatim: a
``customized`` decision may only *narrow* the asset and scanner sets the agent proposed.
Accepting an arbitrary payload would turn the approval endpoint into a way to scan
something the agent never scoped and no one validated.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import structlog
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import ConflictError, UserError
from app.db.enums import (
    ApprovalDecision,
    ApprovalKind,
    AssessmentStatus,
    AuditOutcome,
    Permission,
    RiskLevel,
    ScannerName,
)
from app.db.models.assessment import Approval, Assessment
from app.db.repository import TenantRepository
from app.schemas.assessment import ApproveIn
from app.services import assessment as assessment_service
from app.services import audit as audit_service
from app.services.context import Principal
from app.services.organization import load_policy

log = structlog.get_logger(__name__)

#: Audit action per granted/refused decision, so the trail names what happened rather than
#: recording "resolved" and making the reader open the detail blob to find out.
_DECISION_ACTIONS: dict[ApprovalDecision, str] = {
    ApprovalDecision.APPROVED: audit_service.AuditAction.APPROVAL_GRANTED,
    ApprovalDecision.APPROVED_ALL: audit_service.AuditAction.APPROVAL_GRANTED,
    ApprovalDecision.CUSTOMIZED: audit_service.AuditAction.APPROVAL_CUSTOMIZED,
    ApprovalDecision.REJECTED: audit_service.AuditAction.APPROVAL_REJECTED,
}

#: Decisions that authorize work. Named here so the three call sites cannot drift.
_GRANTING_DECISIONS: frozenset[ApprovalDecision] = frozenset(
    {
        ApprovalDecision.APPROVED,
        ApprovalDecision.APPROVED_ALL,
        ApprovalDecision.CUSTOMIZED,
    }
)

#: Upper bound on how many assets one approval may authorize, matching ``ApproveIn``.
_MAX_ASSETS = 1000


async def open_approval(
    session: AsyncSession,
    assessment: Assessment,
    *,
    kind: ApprovalKind = ApprovalKind.SCAN_SCOPE,
    prompt: str,
    rationale: str | None = None,
    requested_payload: dict[str, Any] | None = None,
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    agent_run_id: uuid.UUID | None = None,
    settings: Settings | None = None,
) -> Approval:
    """Open (or return) the pending approval for this assessment and kind.

    ``RiskLevel.FORBIDDEN`` is refused outright.  The database CHECK excludes it too, but
    failing here names the guardrail in the error instead of surfacing an IntegrityError:
    a forbidden operation has no approvable form, so asking for one is a bug in the caller.

    Does not transition the assessment -- the approval node does that, because a gate that
    is opened but not yet published to the operator is not the same state as one they are
    looking at.
    """
    if risk_level is RiskLevel.FORBIDDEN:
        raise UserError(
            "forbidden operations cannot be approved",
            user_message="That operation is not permitted and cannot be approved.",
            context={"assessment_id": str(assessment.id), "kind": kind.value},
        )

    existing = await pending_approval(session, assessment.id, kind=kind)
    if existing is not None:
        log.info(
            "approval.reused_pending",
            assessment_id=str(assessment.id),
            approval_id=str(existing.id),
            kind=kind.value,
        )
        return existing

    approval = Approval(
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        agent_run_id=agent_run_id,
        kind=kind.value,
        decision=ApprovalDecision.PENDING.value,
        prompt=prompt,
        rationale=rationale,
        requested_payload=requested_payload or {},
        approved_payload={},
        risk_level=risk_level.value,
        expires_at=_expiry(assessment, settings),
    )
    session.add(approval)
    await session.flush()

    await audit_service.record(
        session,
        action=audit_service.AuditAction.APPROVAL_REQUESTED,
        principal=None,
        organization_id=assessment.organization_id,
        resource_type="approval",
        resource_id=approval.id,
        detail={
            "assessment_id": str(assessment.id),
            "kind": kind.value,
            "risk_level": risk_level.value,
            "asset_count": len(_requested_asset_ids(approval)),
            "scanners": _requested_scanners(approval),
        },
    )
    log.info(
        "approval.opened",
        assessment_id=str(assessment.id),
        approval_id=str(approval.id),
        kind=kind.value,
        risk_level=risk_level.value,
    )
    return approval


async def resolve_approval(
    session: AsyncSession,
    principal: Principal,
    approval_id: uuid.UUID,
    payload: ApproveIn,
) -> Approval:
    """Record a human decision on a pending approval.

    The write is a conditional UPDATE narrowed on ``decision = 'pending'``, so this is the
    concurrency boundary for the whole approval mechanism: exactly one caller can move a
    row out of pending, and the loser is told the decision was already made rather than
    quietly overwriting it.

    An expired approval is refused even though its row is still ``pending`` until
    :func:`expire_stale` runs.  Consent given for a scope proposed hours ago, against a
    world that has since changed, is not consent for the scan that would run now.
    """
    principal.require(Permission.ASSESSMENT_APPROVE)
    repo: TenantRepository[Approval] = TenantRepository(
        session, Approval, principal.organization_id
    )
    approval = await repo.get_or_404(approval_id, selectinload(Approval.assessment))

    decision = ApprovalDecision(payload.decision)
    if approval.decision != ApprovalDecision.PENDING.value:
        raise ConflictError(
            "approval already resolved",
            user_message="Someone already responded to this approval request.",
            context={"approval_id": str(approval.id), "decision": approval.decision},
        )
    if _is_expired(approval):
        # Mark it so the next reader sees the truth, then refuse: the operator must be
        # shown a freshly-scoped request rather than approving a stale one.
        await _mark_expired(session, approval)
        raise ConflictError(
            "approval expired",
            user_message=(
                "This approval request expired. Start the assessment again to review "
                "a current scope."
            ),
            context={"approval_id": str(approval.id)},
        )

    approved_payload = _narrow_payload(approval, payload) if decision in _GRANTING_DECISIONS else {}

    now = _now()
    result = await session.execute(
        update(Approval)
        .where(
            Approval.id == approval.id,
            Approval.organization_id == principal.organization_id,
            Approval.decision == ApprovalDecision.PENDING.value,
        )
        .values(
            decision=decision.value,
            approved_payload=approved_payload,
            resolved_at=now,
            resolved_by_id=principal.user_id,
            resolution_note=payload.note,
        )
    )
    if (result.rowcount or 0) != 1:
        raise ConflictError(
            "approval already resolved",
            user_message="Someone already responded to this approval request.",
            context={"approval_id": str(approval.id)},
        )
    # The UPDATE bypassed the identity map, so refresh the in-memory row before anyone
    # reads ``is_granted`` off it and gets the pre-update value.
    await session.refresh(approval)

    await audit_service.record(
        session,
        action=_DECISION_ACTIONS[decision],
        principal=principal,
        resource_type="approval",
        resource_id=approval.id,
        outcome=(
            AuditOutcome.DENIED if decision is ApprovalDecision.REJECTED else AuditOutcome.SUCCESS
        ),
        reason=payload.note,
        detail={
            "assessment_id": str(approval.assessment_id),
            "kind": approval.kind,
            "decision": decision.value,
            "requested_asset_count": len(_requested_asset_ids(approval)),
            "approved_asset_count": len(approved_payload.get("asset_ids", [])),
            "approved_scanners": approved_payload.get("scanners", []),
        },
    )
    log.info(
        "approval.resolved",
        approval_id=str(approval.id),
        assessment_id=str(approval.assessment_id),
        decision=decision.value,
        **principal.to_log_fields(),
    )
    return approval


async def pending_approval(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    kind: ApprovalKind | None = None,
) -> Approval | None:
    """The open approval for an assessment, if there is one.

    Deliberately takes no principal: the agent nodes and the worker call it to decide
    whether to proceed, and they hold no user identity.  Callers that serve this to an
    operator go through :func:`get_approval`, which is tenant-scoped.
    """
    stmt = (
        select(Approval)
        .where(
            Approval.assessment_id == assessment_id,
            Approval.decision == ApprovalDecision.PENDING.value,
        )
        .order_by(Approval.created_at.desc(), Approval.id.desc())
        .limit(1)
    )
    if kind is not None:
        stmt = stmt.where(Approval.kind == kind.value)
    return (await session.execute(stmt)).scalars().first()


async def get_approval(
    session: AsyncSession,
    principal: Principal,
    approval_id: uuid.UUID,
) -> Approval:
    """One approval, tenant-scoped, with the resolving user loaded for the projection."""
    principal.require(Permission.ASSESSMENT_READ)
    repo: TenantRepository[Approval] = TenantRepository(
        session, Approval, principal.organization_id
    )
    return await repo.get_or_404(approval_id, selectinload(Approval.resolved_by))


async def granted_approval(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    kind: ApprovalKind = ApprovalKind.SCAN_SCOPE,
) -> Approval | None:
    """The most recent *granted* approval, re-read from the database.

    This is the function ``app/agent/nodes/scan.py`` calls.  It exists so that authority to
    scan is read from the ``approvals`` table at the moment of scanning rather than trusted
    from graph state -- state can be replayed from a checkpoint, and a replay must not carry
    an approval forward into a run the operator never saw.
    """
    stmt = (
        select(Approval)
        .where(
            Approval.assessment_id == assessment_id,
            Approval.kind == kind.value,
            Approval.decision.in_(
                [
                    ApprovalDecision.APPROVED.value,
                    ApprovalDecision.APPROVED_ALL.value,
                    ApprovalDecision.CUSTOMIZED.value,
                ]
            ),
            Approval.resolved_by_id.isnot(None),
        )
        .order_by(Approval.resolved_at.desc(), Approval.id.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalars().first()


async def expire_stale(session: AsyncSession, settings: Settings) -> int:
    """Expire pending approvals past their deadline. Returns how many were expired.

    Run by the worker on a timer.  Expiry is a real state change rather than a filter at
    read time so the operator sees *why* an assessment stopped, and so the audit trail
    contains the moment consent lapsed.

    ``resolved_by_id`` stays NULL -- the ``resolved_requires_actor`` CHECK permits that for
    ``expired`` precisely because no human resolved it, and inventing an actor here would
    put a false attribution in the record.
    """
    now = _now()
    stale = (
        (
            await session.execute(
                select(Approval).where(
                    Approval.decision == ApprovalDecision.PENDING.value,
                    Approval.expires_at.isnot(None),
                    Approval.expires_at <= now,
                )
            )
        )
        .scalars()
        .all()
    )
    if not stale:
        return 0

    for approval in stale:
        approval.decision = ApprovalDecision.EXPIRED.value
        approval.resolved_at = now
        await audit_service.record(
            session,
            action=audit_service.AuditAction.APPROVAL_EXPIRED,
            principal=None,
            organization_id=approval.organization_id,
            resource_type="approval",
            resource_id=approval.id,
            outcome=AuditOutcome.FAILURE,
            reason="approval expired before a decision was recorded",
            detail={"assessment_id": str(approval.assessment_id), "kind": approval.kind},
        )
        assessment = await session.get(Assessment, approval.assessment_id)
        if assessment is not None and not assessment.status_enum.is_terminal:
            await assessment_service.transition(
                session,
                assessment,
                AssessmentStatus.FAILED,
                reason="The approval request expired before anyone responded.",
            )

    log.warning(
        "approval.expired_batch",
        count=len(stale),
        ttl_hours=settings.agent.approval_ttl_hours,
    )
    return len(stale)


def approval_targets(approval: Approval) -> tuple[list[uuid.UUID], list[str]]:
    """The asset ids and scanner names an approval authorizes.

    Reads ``approved_payload`` and nothing else, so a caller cannot accidentally act on
    what the agent *requested*.  An un-granted approval authorizes nothing, and that is
    reported as two empty lists rather than an exception: the scan node's job is to refuse
    quietly and record why, not to crash.
    """
    if not approval.is_granted:
        return [], []
    payload = approval.approved_payload or {}
    asset_ids: list[uuid.UUID] = []
    for raw in payload.get("asset_ids", []):
        try:
            asset_ids.append(uuid.UUID(str(raw)))
        except (ValueError, AttributeError, TypeError):
            log.warning("approval.bad_asset_id", approval_id=str(approval.id))
    scanners = [str(s) for s in payload.get("scanners", []) if s in ScannerName.values()]
    return asset_ids, scanners


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _narrow_payload(approval: Approval, payload: ApproveIn) -> dict[str, Any]:
    """Build ``approved_payload`` from the request, allowing only narrowing.

    ``approved_all`` takes the agent's proposal unchanged.  ``approved`` and ``customized``
    intersect the operator's selection with it, so an id or scanner that was never proposed
    is dropped rather than honored -- the approval endpoint is not an alternative path into
    the scanner.  An intersection that comes out empty is a
    :class:`~app.core.errors.UserError`: approving nothing is a rejection wearing the wrong
    label, and the operator should say so explicitly.
    """
    decision = ApprovalDecision(payload.decision)
    proposed_ids = _requested_asset_ids(approval)
    proposed_scanners = _requested_scanners(approval)

    if decision is ApprovalDecision.APPROVED_ALL:
        asset_ids, scanners = proposed_ids, proposed_scanners
    else:
        if decision is ApprovalDecision.CUSTOMIZED and not payload.asset_ids:
            raise UserError(
                "customized approval requires an explicit asset selection",
                user_message="Select the assets you want scanned, or approve the full scope.",
                context={"approval_id": str(approval.id)},
            )
        requested_ids = payload.asset_ids
        asset_ids = (
            [a for a in proposed_ids if a in set(requested_ids)]
            if requested_ids is not None
            else proposed_ids
        )
        requested_scanners = (
            [s.value for s in payload.scanners] if payload.scanners is not None else None
        )
        scanners = (
            [s for s in proposed_scanners if s in set(requested_scanners)]
            if requested_scanners is not None
            else proposed_scanners
        )
        dropped_assets = len(set(requested_ids or [])) - len(asset_ids)
        if dropped_assets > 0:
            log.warning(
                "approval.selection_outside_scope",
                approval_id=str(approval.id),
                dropped_assets=dropped_assets,
            )

    if not asset_ids:
        raise UserError(
            "approval selected no in-scope assets",
            user_message=(
                "None of the selected assets are part of the proposed scope. "
                "Choose from the proposed assets, or reject the request."
            ),
            context={"approval_id": str(approval.id)},
        )
    if not scanners:
        raise UserError(
            "approval selected no proposed scanners",
            user_message=(
                "None of the selected scanners were proposed for this assessment. "
                "Choose from the proposed scanners, or reject the request."
            ),
            context={"approval_id": str(approval.id)},
        )

    approved: dict[str, Any] = {
        "asset_ids": [str(a) for a in asset_ids[:_MAX_ASSETS]],
        "scanners": scanners,
        "decision": decision.value,
    }
    # Carried forward so the report can state the scope the *agent* proposed alongside what
    # the human authorized; FR-011 is only auditable if both halves survive.
    requested = approval.requested_payload or {}
    if "depth" in requested:
        approved["depth"] = requested["depth"]
    if "rate_limit" in requested:
        approved["rate_limit"] = requested["rate_limit"]
    return approved


def _requested_asset_ids(approval: Approval) -> list[uuid.UUID]:
    raw = (approval.requested_payload or {}).get("asset_ids", [])
    out: list[uuid.UUID] = []
    for value in raw:
        try:
            out.append(uuid.UUID(str(value)))
        except (ValueError, AttributeError, TypeError):
            continue
    return out


def _requested_scanners(approval: Approval) -> list[str]:
    raw = (approval.requested_payload or {}).get("scanners", [])
    valid = ScannerName.values()
    return [str(value) for value in raw if str(value) in valid]


def _expiry(assessment: Assessment, settings: Settings | None) -> dt.datetime | None:
    """When this approval stops being valid.

    The organization policy may shorten the window but not lengthen it past a week -- the
    schema caps ``approval_ttl_hours`` at 168 for exactly that reason.  With no settings at
    all the approval simply does not expire, which is the safe direction: the alternative is
    guessing a deadline and failing assessments because of it.
    """
    if settings is None:
        return None
    hours = settings.agent.approval_ttl_hours
    # ``lazy="raise_on_sql"`` means touching an unloaded relationship raises rather than
    # emitting a query, so the load state is checked instead of guarded with try/except.
    if "organization" not in sa_inspect(assessment).unloaded:
        override = load_policy(assessment.organization).approval_ttl_hours
        if override is not None:
            hours = min(hours, override)
    return _now() + dt.timedelta(hours=hours)


def _is_expired(approval: Approval) -> bool:
    return approval.expires_at is not None and approval.expires_at <= _now()


async def _mark_expired(session: AsyncSession, approval: Approval) -> None:
    approval.decision = ApprovalDecision.EXPIRED.value
    approval.resolved_at = _now()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.APPROVAL_EXPIRED,
        principal=None,
        organization_id=approval.organization_id,
        resource_type="approval",
        resource_id=approval.id,
        outcome=AuditOutcome.FAILURE,
        reason="decision arrived after the approval expired",
    )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "approval_targets",
    "expire_stale",
    "get_approval",
    "granted_approval",
    "open_approval",
    "pending_approval",
    "resolve_approval",
]
