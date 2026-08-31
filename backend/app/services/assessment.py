"""Assessment lifecycle (FR-005, FR-006, FR-007, FR-037, FR-039).

Three rules shape this module.

**Authorization is recorded before a target exists.**  :func:`create_assessment` writes an
``authorization_records`` row per target *in the same transaction* as the assessment
itself.  FR-006 wants evidence that a human attested to authority, and an assessment that
could exist without one -- even briefly, even because a later insert failed -- is an
assessment that could be scanned without one.

**Status changes go through :func:`transition`.**  It consults
:data:`~app.db.enums.ALLOWED_TRANSITIONS` rather than assigning the column, so a node that
tries to move a cancelled assessment back into ``SCANNING`` fails loudly instead of
resurrecting it.  Terminal states have an empty transition set, which is what makes
cancellation stick.

**Degradations are data, not log lines.**  FR-039 requires the operator to be told which
dependency was missing, and :func:`record_degradation` appends to a JSONB column that the
detail view and the report appendix both read.  A logged warning would satisfy an engineer
reading logs and nobody reading the report.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence
from typing import Any

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, TargetPolicySettings
from app.core.errors import (
    ConflictError,
    InvalidTargetError,
    ResourceNotFoundError,
    UnauthorizedTargetError,
)
from app.core.targets import ValidatedTarget, validate_target
from app.db.enums import (
    ALLOWED_TRANSITIONS,
    AssessmentStage,
    AssessmentStatus,
    AuditOutcome,
    Permission,
    Severity,
)
from app.db.models.assessment import Assessment, AssessmentTarget, AuthorizationRecord
from app.db.models.finding import Finding
from app.db.models.identity import Organization
from app.db.repository import TenantRepository, tenant_select
from app.schemas.assessment import AssessmentCreateIn, AssessmentFilter, CancelIn
from app.schemas.common import PaginationParams
from app.services import audit as audit_service
from app.services.context import Principal
from app.services.organization import load_policy
from app.services.progress import percent_for, stage_for_status

log = structlog.get_logger(__name__)

#: Detail-view eager loads. :data:`~app.db.base.LAZY` makes every un-loaded relationship
#: raise on access, so the projection's needs are declared here rather than discovered as
#: a ``MissingGreenlet`` at render time.
_LIST_OPTIONS = (
    selectinload(Assessment.targets),
    selectinload(Assessment.created_by),
)
_DETAIL_OPTIONS = (
    *_LIST_OPTIONS,
    selectinload(Assessment.approvals),
    selectinload(Assessment.agent_runs),
)

#: Cap on ``degradations``. A stage that degrades in a retry loop would otherwise grow the
#: row without bound, and the first entries are the informative ones.
_MAX_DEGRADATIONS = 200


async def create_assessment(
    session: AsyncSession,
    principal: Principal,
    payload: AssessmentCreateIn,
    settings: Settings,
) -> Assessment:
    """Validate targets, record authorization, and create the assessment.

    Ordering is deliberate: refusal first, persistence second.  Authorization is checked
    before any target is parsed, and every target is validated before any row is written,
    so a request with one denied target creates nothing at all.  The alternative -- writing
    rows as they validate -- would leave a half-scoped assessment whose target list did not
    match what the operator authorized.
    """
    principal.require(Permission.ASSESSMENT_CREATE)

    if not payload.authorization.confirmed:
        # Recorded independently: this raise rolls the caller's transaction back, and a
        # refused attestation is exactly the event FR-032 wants kept.
        await audit_service.record_independently(
            action=audit_service.AuditAction.TARGET_DENIED,
            principal=principal,
            resource_type="assessment",
            outcome=AuditOutcome.DENIED,
            reason="authorization was not confirmed",
            organization_id=principal.organization_id,
            settings=settings,
        )
        raise UnauthorizedTargetError(
            "assessment requested without a confirmed attestation",
            user_message=(
                "You must confirm you are authorized to test these targets before "
                "an assessment can start."
            ),
        )

    policy = await _policy_for(session, principal, settings)
    validated = _validate_targets(payload.targets, policy)

    now = _now()
    assessment = Assessment(
        organization_id=principal.organization_id,
        reference=await _next_reference(session, principal.organization_id),
        created_by_id=principal.user_id,
        title=payload.title or _title_for(validated),
        scope=payload.scope.value,
        depth=payload.depth.value,
        status=AssessmentStatus.CREATED.value,
        current_stage=AssessmentStage.QUEUED.value,
        progress_percent=0,
        request_interpretation={"objective": payload.objective} if payload.objective else {},
    )
    session.add(assessment)
    # Flushed so the child rows below have an ``assessment_id`` without relying on
    # SQLAlchemy's ordering across three different tables.
    await session.flush()

    for target in validated:
        session.add(
            AssessmentTarget(
                assessment_id=assessment.id,
                raw_value=target.raw[:2048],
                canonical_value=target.canonical[:2048],
                target_type=target.type.value,
                host=target.host[:512],
                port=target.port,
                host_count=target.host_count,
                target_metadata=dict(target.metadata),
            )
        )
        session.add(
            AuthorizationRecord(
                assessment_id=assessment.id,
                user_id=principal.user_id,
                target=target.canonical[:2048],
                confirmed=True,
                attestation_text=payload.authorization.attestation_text,
                method="explicit_ui",
                source_ip=principal.source_ip,
                user_agent=principal.user_agent[:512] if principal.user_agent else None,
                confirmed_at=now,
                evidence_reference=payload.authorization.evidence_reference,
            )
        )

    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSESSMENT_CREATE,
        principal=principal,
        resource_type="assessment",
        resource_id=assessment.id,
        detail={
            "reference": assessment.reference,
            "scope": assessment.scope,
            "depth": assessment.depth,
            "target_count": len(validated),
            "host_count": sum(t.host_count for t in validated),
            "notify_recipients": len(payload.notify),
        },
    )
    log.info(
        "assessment.created",
        assessment_id=str(assessment.id),
        reference=assessment.reference,
        target_count=len(validated),
        **principal.to_log_fields(),
    )
    return assessment


async def get_assessment(
    session: AsyncSession,
    principal: Principal,
    assessment_id: uuid.UUID,
    *,
    detail: bool = False,
) -> Assessment:
    """One assessment, scoped to the caller's organization.

    A cross-tenant id is a 404, not a 403 (SEC-003): confirming that an id exists in
    someone else's tenant is itself a disclosure.
    """
    principal.require(Permission.ASSESSMENT_READ)
    options = _DETAIL_OPTIONS if detail else _LIST_OPTIONS
    repo: TenantRepository[Assessment] = TenantRepository(
        session, Assessment, principal.organization_id
    )
    return await repo.get_or_404(assessment_id, *options)


async def list_assessments(
    session: AsyncSession,
    principal: Principal,
    *,
    filters: AssessmentFilter | None = None,
    pagination: PaginationParams | None = None,
) -> tuple[Sequence[Assessment], int]:
    """Newest first. Returns ``(rows, total)`` so the caller can build a ``Page``."""
    principal.require(Permission.ASSESSMENT_READ)
    filters = filters or AssessmentFilter()
    page = pagination or PaginationParams()

    conditions: list[Any] = []
    if filters.status is not None:
        conditions.append(Assessment.status == filters.status.value)
    if filters.scope is not None:
        conditions.append(Assessment.scope == filters.scope.value)
    if filters.active is not None:
        terminal = [s.value for s in AssessmentStatus if s.is_terminal]
        conditions.append(
            Assessment.status.notin_(terminal)
            if filters.active
            else Assessment.status.in_(terminal)
        )
    if filters.awaiting_approval is not None:
        waiting = Assessment.status == AssessmentStatus.WAITING_FOR_APPROVAL.value
        conditions.append(waiting if filters.awaiting_approval else ~waiting)
    if filters.q:
        term = f"%{_escape_like(filters.q)}%"
        conditions.append(
            or_(
                Assessment.title.ilike(term, escape="\\"),
                Assessment.targets.any(AssessmentTarget.host.ilike(term, escape="\\")),
            )
        )

    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Assessment)
                .where(Assessment.organization_id == principal.organization_id, *conditions)
            )
        ).scalar_one()
    )
    stmt = (
        tenant_select(Assessment, principal.organization_id, *_LIST_OPTIONS)
        .where(*conditions)
        # ``id`` breaks ties: two assessments created in the same transaction share
        # ``created_at``, and an unstable order makes paging skip rows.
        .order_by(Assessment.created_at.desc(), Assessment.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return rows, total


async def transition(
    session: AsyncSession,
    assessment: Assessment,
    to: AssessmentStatus,
    *,
    stage: AssessmentStage | None = None,
    reason: str | None = None,
) -> None:
    """Move an assessment to ``to``, refusing transitions the state machine forbids.

    Idempotent for a no-op (``to`` equal to the current status) so a node that re-runs
    after a checkpoint restore does not fail on its own previous work.  Anything else
    outside :data:`~app.db.enums.ALLOWED_TRANSITIONS` raises
    :class:`~app.core.errors.ConflictError`: a terminal assessment has an empty transition
    set, which is precisely how a cancellation resists a late-arriving scanner callback.

    Does not commit.  The caller owns the transaction, because a status change is only ever
    meaningful together with whatever produced it.
    """
    current = assessment.status_enum
    if current is to:
        if stage is not None:
            _set_stage(assessment, stage)
        return

    if to not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise ConflictError(
            f"cannot move assessment from {current.value} to {to.value}",
            user_message=f"This assessment is {current.value.lower()} and cannot be changed.",
            context={
                "assessment_id": str(assessment.id),
                "from_status": current.value,
                "to_status": to.value,
            },
        )

    assessment.status = to.value
    _set_stage(assessment, stage if stage is not None else stage_for_status(to))

    now = _now()
    if to is AssessmentStatus.PLANNING and assessment.started_at is None:
        assessment.started_at = now
    if to.is_terminal:
        assessment.completed_at = now
        if to is AssessmentStatus.COMPLETED:
            assessment.progress_percent = 100
    if reason and to in (AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
        assessment.failure_reason = reason[:4000]

    log.info(
        "assessment.transition",
        assessment_id=str(assessment.id),
        from_status=current.value,
        to_status=to.value,
        stage=assessment.current_stage,
    )


async def record_degradation(
    session: AsyncSession,
    assessment: Assessment,
    *,
    stage: AssessmentStage | str,
    component: str,
    reason: str,
    impact: str,
) -> None:
    """Append an FR-039 degradation entry.

    ``reason`` must already be user-safe -- it is rendered in the detail view and in the
    report appendix, so an internal provider message would leak there (SEC-002).  Callers
    pass ``CynuxError.user_message``, not ``str(exc)``.

    Reassigns the list rather than mutating it in place: SQLAlchemy tracks JSONB columns by
    identity, and an ``append`` on the loaded list is not seen as a change, so the row
    would commit unmodified.
    """
    entry = {
        "stage": str(getattr(stage, "value", stage)),
        "component": component[:120],
        "reason": reason[:600],
        "impact": impact[:600],
        "occurred_at": _now().isoformat(),
    }
    existing = list(assessment.degradations or [])
    if len(existing) >= _MAX_DEGRADATIONS:
        existing = existing[: _MAX_DEGRADATIONS - 1]
    assessment.degradations = [*existing, entry]

    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSESSMENT_DEGRADED,
        principal=None,
        organization_id=assessment.organization_id,
        resource_type="assessment",
        resource_id=assessment.id,
        detail={"stage": entry["stage"], "component": entry["component"]},
        reason=entry["reason"],
    )
    log.warning(
        "assessment.degraded",
        assessment_id=str(assessment.id),
        stage=entry["stage"],
        component=entry["component"],
    )


async def cancel_assessment(
    session: AsyncSession,
    principal: Principal,
    assessment_id: uuid.UUID,
    payload: CancelIn,
) -> Assessment:
    """Request cancellation (FR-037).

    Moves to ``CANCELLING``, not ``CANCELLED``: a scanner container may be mid-run and the
    worker is what stops it and records the outcome.  Claiming ``CANCELLED`` while a
    container is still executing would be a false statement about the state of the world --
    the one thing a security tool cannot afford in its own audit trail.

    Already-terminal assessments raise :class:`~app.core.errors.ConflictError` via
    :func:`transition`, which is the honest answer to "cancel something that finished".
    """
    principal.require(Permission.ASSESSMENT_CANCEL)
    assessment = await get_assessment(session, principal, assessment_id)
    from_status = assessment.status

    await transition(
        session,
        assessment,
        AssessmentStatus.CANCELLING,
        reason=payload.reason or "Cancelled by operator.",
    )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSESSMENT_CANCEL,
        principal=principal,
        resource_type="assessment",
        resource_id=assessment.id,
        reason=payload.reason,
        detail={"from_status": from_status},
    )
    return assessment


async def refresh_counters(session: AsyncSession, assessment: Assessment) -> None:
    """Recompute the cached finding counts from the ``findings`` table.

    The columns are a denormalization for the list view; this is the one function that
    writes them, so they cannot drift per call site.  Duplicates and false positives are
    excluded: DefectDojo owns deduplication (FR-018), and a total that counted its
    duplicates would contradict the number DefectDojo itself reports.
    """
    stmt = (
        select(Finding.severity, func.count())
        .where(
            Finding.assessment_id == assessment.id,
            Finding.is_duplicate.is_(False),
            Finding.is_false_positive.is_(False),
        )
        .group_by(Finding.severity)
    )
    counts = {str(severity): int(total) for severity, total in (await session.execute(stmt)).all()}

    assessment.findings_critical = counts.get(Severity.CRITICAL.value, 0)
    assessment.findings_high = counts.get(Severity.HIGH.value, 0)
    assessment.findings_medium = counts.get(Severity.MEDIUM.value, 0)
    assessment.findings_low = counts.get(Severity.LOW.value, 0)
    assessment.findings_info = counts.get(Severity.INFO.value, 0)
    assessment.findings_total = sum(counts.values())


def assessment_or_404(assessment: Assessment | None, assessment_id: uuid.UUID) -> Assessment:
    """Narrow an optional assessment for callers that queried it themselves.

    Used by the worker and the agent nodes, which load an assessment by id outside a
    repository because they hold a session and no principal.
    """
    if assessment is None:
        raise ResourceNotFoundError(
            "assessment not found",
            user_message="That assessment no longer exists.",
            context={"assessment_id": str(assessment_id)},
        )
    return assessment


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _policy_for(
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
) -> TargetPolicySettings:
    """The global target policy, narrowed by the organization's own deny list.

    ``denied_targets`` is additive on top of the global deny list and there is no
    allow-list counterpart, so an organization can only ever make the policy stricter
    (FR-006).  A missing organization row falls back to the global policy: refusing to
    validate at all would be a worse failure than validating against one of the two lists.
    """
    organization = await session.get(Organization, principal.organization_id)
    if organization is None:  # pragma: no cover - principal came from a validated token
        return settings.targets
    extra = load_policy(organization).denied_targets
    if not extra:
        return settings.targets
    return settings.targets.model_copy(update={"deny_list": [*settings.targets.deny_list, *extra]})


def _validate_targets(
    raw_targets: Sequence[str],
    policy: TargetPolicySettings,
) -> list[ValidatedTarget]:
    """Validate every target, rejecting duplicates by canonical form.

    De-duplication is on the *canonical* value, so ``https://example.com`` and
    ``https://example.com/`` are caught as the same target.  Left in, they would produce
    two ``assessment_targets`` rows that violate the unique constraint at commit -- an
    IntegrityError whose message says nothing useful to the operator.
    """
    validated: list[ValidatedTarget] = []
    seen: set[str] = set()
    for raw in raw_targets:
        target = validate_target(raw, policy)
        if target.canonical in seen:
            raise InvalidTargetError(
                f"duplicate target {target.canonical}",
                user_message=f"{target.canonical} is listed more than once.",
            )
        seen.add(target.canonical)
        validated.append(target)
    return validated


async def _next_reference(session: AsyncSession, organization_id: uuid.UUID) -> int:
    """The next per-organization assessment number.

    ``max + 1`` under the unique constraint on ``(organization_id, reference)``: two
    concurrent creates race, one loses at commit, and the caller retries.  A sequence would
    be per-database rather than per-tenant, which is precisely the property that makes the
    reference readable ("ASM-17" for the seventeenth assessment *this organization* ran).
    """
    current = (
        await session.execute(
            select(func.max(Assessment.reference)).where(
                Assessment.organization_id == organization_id
            )
        )
    ).scalar()
    return int(current or 0) + 1


def _title_for(targets: Sequence[ValidatedTarget]) -> str:
    """A default title naming the first target and how many others there are."""
    first = targets[0].canonical
    if len(targets) == 1:
        return f"Assessment of {first}"[:300]
    return f"Assessment of {first} and {len(targets) - 1} more"[:300]


def _set_stage(assessment: Assessment, stage: AssessmentStage) -> None:
    """Set the stage and the derived percentage together.

    One function so the two can never disagree -- a progress bar that contradicts the
    stage label is a bug an operator reads as "stuck".
    """
    assessment.current_stage = stage.value
    assessment.progress_percent = percent_for(stage)


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "assessment_or_404",
    "cancel_assessment",
    "create_assessment",
    "get_assessment",
    "list_assessments",
    "record_degradation",
    "refresh_counters",
    "transition",
]
