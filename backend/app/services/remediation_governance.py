"""Tenant-scoped exception approval and retest request workflows."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, TenantIsolationError
from app.db.base import utcnow
from app.db.enums import JobStatus, Permission
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.canonical import (
    AssessmentCanonicalFinding,
    CanonicalFinding,
    FindingHistory,
    FindingObservation,
    RetestRequest,
    RiskAcceptance,
)
from app.db.models.finding import Finding
from app.db.models.scanner import ScannerJob
from app.db.repository import tenant_select
from app.services import audit as audit_service
from app.services.canonical_work import remediation_group_key
from app.services.context import Principal
from app.services.risk_acceptance import validate_expiry


async def _finding_for_update(
    session: AsyncSession, principal: Principal, finding_id: uuid.UUID
) -> CanonicalFinding:
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
    if not rows or rows[0].organization_id != principal.organization_id:
        raise TenantIsolationError("canonical finding not found in organization")
    return rows[0]


async def request_risk_acceptance(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    *,
    rationale: str,
    expires_at: dt.datetime,
) -> RiskAcceptance:
    principal.require(Permission.FINDING_REMEDIATE)
    finding = await _finding_for_update(session, principal, finding_id)
    if finding.status in {"closed", "false_positive"}:
        raise ConflictError("inactive finding", user_message="Inactive findings cannot receive risk acceptance.")
    acceptance = RiskAcceptance(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        canonical_finding_id=finding.id,
        requested_by_id=principal.user_id,
        rationale=rationale.strip(),
        expires_at=validate_expiry(expires_at),
        status="pending",
    )
    session.add(acceptance)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.RISK_ACCEPTANCE_REQUEST,
        principal=principal,
        resource_type="risk_acceptance",
        resource_id=acceptance.id,
        detail={"finding_id": str(finding.id), "expires_at": acceptance.expires_at.isoformat()},
    )
    return acceptance


async def approve_risk_acceptance(
    session: AsyncSession, principal: Principal, acceptance_id: uuid.UUID
) -> RiskAcceptance:
    principal.require(Permission.FINDING_VALIDATE)
    acceptance = (
        await session.execute(
            tenant_select(RiskAcceptance, principal.organization_id)
            .where(RiskAcceptance.id == acceptance_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if acceptance is None:
        raise TenantIsolationError("risk acceptance not found in organization")
    if acceptance.requested_by_id == principal.user_id:
        raise ConflictError("self approval", user_message="A different authorized reviewer must approve risk acceptance.")
    if acceptance.status != "pending":
        raise ConflictError("risk acceptance already decided", user_message="This risk acceptance is no longer pending.")
    validate_expiry(acceptance.expires_at)
    finding = await _finding_for_update(session, principal, acceptance.canonical_finding_id)
    if finding.status in {"closed", "false_positive"}:
        raise ConflictError(
            "inactive finding",
            user_message="Inactive findings cannot receive a risk acceptance.",
        )
    acceptance.status = "approved"
    acceptance.approved_by_id = principal.user_id
    acceptance.approved_at = utcnow()
    finding_status_changed = False
    if finding.status != "accepted_risk":
        previous_status = finding.status
        finding.status = "accepted_risk"
        finding.status_version += 1
        finding_status_changed = True
        finding.disposition_reason = "Approved time-bound risk acceptance"
        finding.closed_at = None
        session.add(
            FindingHistory(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                canonical_finding_id=finding.id,
                previous_status=previous_status,
                new_status="accepted_risk",
                reason="Approved time-bound risk acceptance",
                actor_user_id=principal.user_id,
                occurred_at=acceptance.approved_at,
            )
        )
        await audit_service.record(
            session,
            action=audit_service.AuditAction.FINDING_STATUS_CHANGE,
            principal=principal,
            resource_type="canonical_finding",
            resource_id=finding.id,
            detail={
                "from": previous_status,
                "to": "accepted_risk",
                "reason": "risk_acceptance_approved",
                "risk_acceptance_id": str(acceptance.id),
            },
            reason="Approved time-bound risk acceptance",
        )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.RISK_ACCEPTANCE_APPROVE,
        principal=principal,
        resource_type="risk_acceptance",
        resource_id=acceptance.id,
        detail={"finding_id": str(acceptance.canonical_finding_id), "finding_status": finding.status},
    )
    if finding_status_changed:
        asset = (
            await session.execute(
                tenant_select(Asset, principal.organization_id).where(Asset.id == finding.asset_id)
            )
        ).scalar_one_or_none()
        if asset is not None:
            from app.services.automation import queue_finding_event

            await queue_finding_event(
                session,
                finding=finding,
                asset=asset,
                trigger="finding.updated",
                event_key_suffix=f":version:{finding.status_version}",
            )
    return acceptance


async def request_retest(
    session: AsyncSession, principal: Principal, finding_id: uuid.UUID, *, note: str | None
) -> RetestRequest:
    principal.require(Permission.FINDING_VALIDATE)
    finding = await _finding_for_update(session, principal, finding_id)
    if finding.status in {"closed", "false_positive"}:
        raise ConflictError("inactive finding", user_message="Inactive findings cannot be retested.")
    # Retest creation is used by both people and at-least-once automation.  Only one
    # unresolved verification may exist for a finding at a time; returning it makes a
    # recovered automation execution safe to replay without creating duplicate scans.
    existing = (
        await session.execute(
            tenant_select(RetestRequest, principal.organization_id)
            .where(
                RetestRequest.canonical_finding_id == finding.id,
                RetestRequest.status.in_(("requested", "scheduled", "running")),
            )
            .order_by(RetestRequest.created_at.desc(), RetestRequest.id.desc())
            .with_for_update()
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    request = RetestRequest(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        canonical_finding_id=finding.id,
        requested_by_id=principal.user_id,
        status="requested",
        request_note=note,
    )
    session.add(request)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.RETEST_REQUEST,
        principal=principal,
        resource_type="retest_request",
        resource_id=request.id,
        detail={"finding_id": str(finding.id)},
    )
    return request


async def request_remediation_group_retests(
    session: AsyncSession,
    principal: Principal,
    *,
    remediation_group: str,
    note: str | None,
) -> list[RetestRequest]:
    """Create or reuse verification requests for every active finding in one fix group.

    A common patch often resolves many normalized findings. This keeps the
    verification lifecycle per finding (and therefore preserves closure evidence)
    while giving the remediation owner one explicit group-level operation.
    """
    principal.require(Permission.FINDING_VALIDATE)
    normalized_group = remediation_group.strip()
    if not normalized_group:
        raise ValueError("remediation group cannot be blank")
    findings = list(
        (
            await session.execute(
                tenant_select(CanonicalFinding, principal.organization_id)
                .where(
                    CanonicalFinding.remediation_group_key == remediation_group_key(normalized_group),
                    CanonicalFinding.status.not_in(("closed", "false_positive")),
                )
                .order_by(CanonicalFinding.id)
                .limit(101)
            )
        )
        .scalars()
        .all()
    )
    if not findings:
        raise TenantIsolationError("no active canonical findings found for remediation group")
    if len(findings) > 100:
        raise ConflictError(
            "remediation group retest batch is too large",
            user_message="This remediation group has more than 100 active findings. Split it into smaller fix groups before requesting verification.",
        )
    requests: list[RetestRequest] = []
    for finding in findings:
        requests.append(await request_retest(session, principal, finding.id, note=note))
    return requests


async def schedule_retest(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    request_id: uuid.UUID,
    assessment_id: uuid.UUID,
) -> RetestRequest:
    """Link a requested retest to an already-authorized same-tenant assessment."""
    request = (
        await session.execute(
            tenant_select(RetestRequest, organization_id)
            .where(RetestRequest.id == request_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if request is None:
        raise TenantIsolationError("retest request not found in organization")
    if request.status != "requested":
        raise ConflictError("retest request is no longer schedulable")
    assessment = (
        await session.execute(
            tenant_select(Assessment, organization_id).where(Assessment.id == assessment_id)
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise TenantIsolationError("assessment not found in organization")
    request.assessment_id = assessment.id
    request.status = "scheduled"
    await audit_service.record(
        session,
        action=audit_service.AuditAction.RETEST_SCHEDULE,
        organization_id=organization_id,
        resource_type="retest_request",
        resource_id=request.id,
        detail={"assessment_id": str(assessment.id), "outcome": "scheduled"},
    )
    return request


async def complete_retest(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
    outcome: str,
    evidence: dict[str, object],
) -> RetestRequest | None:
    """Persist a terminal, scanner-derived retest result without deciding finding status."""
    if outcome not in {"confirmed", "not_confirmed", "failed", "cancelled"}:
        raise ValueError("invalid retest outcome")
    if not isinstance(evidence, dict):
        raise ValueError("retest evidence must be an object")
    request = (
        await session.execute(
            tenant_select(RetestRequest, organization_id)
            .where(RetestRequest.assessment_id == assessment_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if request is None:
        return None
    if request.status in {"confirmed", "not_confirmed", "failed", "cancelled"}:
        return request
    request.status = outcome
    request.evidence = dict(evidence)
    request.completed_at = utcnow()
    updated_finding: CanonicalFinding | None = None
    verification = evidence.get("verification")
    if (
        outcome == "not_confirmed"
        and isinstance(verification, dict)
        and verification.get("assessment_complete") is True
        and verification.get("coverage_complete") is True
        and verification.get("finding_present") is False
        and verification.get("uncovered_active_sources") == 0
    ):
        finding = (
            await session.execute(
                tenant_select(CanonicalFinding, organization_id)
                .where(CanonicalFinding.id == request.canonical_finding_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if finding is None:
            raise TenantIsolationError("canonical finding not found in organization")
        # Automated evidence cannot revoke a human-approved risk disposition.
        # The acceptance must expire or be revoked through its own workflow.
        if finding.status not in {"closed", "false_positive", "accepted_risk"}:
            previous_status = finding.status
            finding.status = "closed"
            finding.status_version += 1
            finding.closed_at = request.completed_at
            session.add(
                FindingHistory(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    canonical_finding_id=finding.id,
                    previous_status=previous_status,
                    new_status="closed",
                    reason="Verified retest found no matching finding",
                    occurred_at=request.completed_at,
                )
            )
            await audit_service.record(
                session,
                action=audit_service.AuditAction.FINDING_STATUS_CHANGE,
                organization_id=organization_id,
                resource_type="canonical_finding",
                resource_id=finding.id,
                detail={
                    "from": previous_status,
                    "to": "closed",
                    "reason": "verified_retest_absence",
                    "retest_request_id": str(request.id),
                },
            )
            updated_finding = finding
    await audit_service.record(
        session,
        action=audit_service.AuditAction.RETEST_COMPLETE,
        organization_id=organization_id,
        resource_type="retest_request",
        resource_id=request.id,
        detail={"assessment_id": str(assessment_id), "outcome": outcome},
    )
    if updated_finding is not None:
        asset = (
            await session.execute(
                tenant_select(Asset, organization_id).where(Asset.id == updated_finding.asset_id)
            )
        ).scalar_one_or_none()
        if asset is not None:
            from app.services.automation import queue_finding_event

            await queue_finding_event(
                session,
                finding=updated_finding,
                asset=asset,
                trigger="finding.updated",
                event_key_suffix=f":version:{updated_finding.status_version}",
            )
    # A completed retest is an operational signal in its own right. Rules can now escalate
    # a verified persistent finding or notify owners that evidence cleared it, without
    # abusing a generic status-change trigger.
    retest_trigger = {
        "confirmed": "retest.confirmed",
        "not_confirmed": "retest.cleared",
    }.get(outcome)
    if retest_trigger is not None:
        event_finding = updated_finding
        if event_finding is None:
            event_finding = (
                await session.execute(
                    tenant_select(CanonicalFinding, organization_id).where(
                        CanonicalFinding.id == request.canonical_finding_id
                    )
                )
            ).scalar_one_or_none()
        if event_finding is not None:
            asset = (
                await session.execute(
                    tenant_select(Asset, organization_id).where(Asset.id == event_finding.asset_id)
                )
            ).scalar_one_or_none()
            if asset is not None:
                from app.services.automation import queue_finding_event

                await queue_finding_event(
                    session,
                    finding=event_finding,
                    asset=asset,
                    trigger=retest_trigger,
                    event_key_suffix=f":retest:{request.id}:{outcome}",
                )
    return request


async def complete_assessment_retest(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
    run_id: uuid.UUID,
) -> RetestRequest | None:
    """Derive a retest decision solely from the same completed assessment's finding set."""
    request = (
        await session.execute(
            tenant_select(RetestRequest, organization_id)
            .where(RetestRequest.assessment_id == assessment_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if request is None or request.status in {"confirmed", "not_confirmed", "failed", "cancelled"}:
        return request
    jobs = list(
        (
            await session.execute(
                tenant_select(ScannerJob, organization_id)
                .where(ScannerJob.assessment_id == assessment_id)
                .order_by(ScannerJob.id)
            )
        )
        .scalars()
        .all()
    )
    verification_jobs = [job for job in jobs if job.scanner != "reconftw"]
    coverage_complete = bool(verification_jobs) and all(
        job.status == JobStatus.COMPLETED.value and job.imported_at is not None
        for job in verification_jobs
    )
    covered_scanners = {
        job.scanner
        for job in verification_jobs
        if job.status == JobStatus.COMPLETED.value and job.imported_at is not None
    }
    membership = (
        await session.execute(
            tenant_select(AssessmentCanonicalFinding, organization_id)
            .where(
                AssessmentCanonicalFinding.assessment_id == assessment_id,
                AssessmentCanonicalFinding.canonical_finding_id == request.canonical_finding_id,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    assessment_finding_present = membership is not None
    covered_observations: list[str] = []
    uncovered_active_sources = 0
    if not assessment_finding_present and coverage_complete:
        observation_rows = (
            await session.execute(
                select(FindingObservation, Finding.scanner)
                .outerjoin(
                    Finding,
                    and_(
                        FindingObservation.provider == "defectdojo",
                        Finding.id == FindingObservation.source_record_id,
                        Finding.organization_id == organization_id,
                    ),
                )
                .where(
                    FindingObservation.organization_id == organization_id,
                    FindingObservation.canonical_finding_id == request.canonical_finding_id,
                    FindingObservation.source_status.in_(("open", "active", "verified")),
                )
                .with_for_update(of=FindingObservation)
            )
        ).all()
        scanner_aliases = set(covered_scanners)
        scanner_aliases.update(scanner.split("_", 1)[0] for scanner in covered_scanners)
        now = utcnow()
        for observation, native_scanner in observation_rows:
            provider_covered = (
                native_scanner in covered_scanners
                if observation.provider == "defectdojo"
                else observation.provider in scanner_aliases
            )
            if not provider_covered:
                uncovered_active_sources += 1
                continue
            observation.source_status = "absent"
            observation.missing_sync_count = max(2, observation.missing_sync_count)
            observation.evidence = {
                **(observation.evidence or {}),
                "verified_absent_at": now.isoformat(),
                "retest_assessment_id": str(assessment_id),
                "retest_request_id": str(request.id),
            }
            covered_observations.append(str(observation.id))
    finding_present = assessment_finding_present or uncovered_active_sources > 0
    if assessment_finding_present:
        outcome = "confirmed"
    elif not coverage_complete:
        outcome = "failed"
    elif uncovered_active_sources:
        outcome = "confirmed"
    else:
        outcome = "not_confirmed"
    return await complete_retest(
        session,
        organization_id=organization_id,
        assessment_id=assessment_id,
        outcome=outcome,
        evidence={
            "run_id": str(run_id),
            "assessment_status": "completed",
            "scanner_jobs": [
                {
                    "id": str(job.id),
                    "scanner": job.scanner,
                    "status": job.status,
                    "imported": job.imported_at is not None,
                }
                for job in verification_jobs
            ],
            "covered_observation_ids": covered_observations,
            "verification": {
                "assessment_complete": True,
                "finding_present": finding_present,
                "assessment_finding_present": assessment_finding_present,
                "coverage_complete": coverage_complete,
                "uncovered_active_sources": uncovered_active_sources,
            },
        },
    )


async def expire_risk_acceptances(
    session: AsyncSession, *, now: dt.datetime | None = None, limit: int = 500
) -> int:
    """Expire approved exceptions and reopen only the finding state they held."""
    reference = now or utcnow()
    acceptances = (
        await session.execute(
            select(RiskAcceptance)
            .where(RiskAcceptance.status == "approved", RiskAcceptance.expires_at <= reference)
            .order_by(RiskAcceptance.expires_at, RiskAcceptance.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).scalars().all()
    if not acceptances:
        return 0
    finding_ids = {item.canonical_finding_id for item in acceptances}
    findings = (
        await session.execute(
            select(CanonicalFinding)
            .where(CanonicalFinding.id.in_(finding_ids))
            .with_for_update()
        )
    ).scalars().all()
    by_id = {item.id: item for item in findings}
    reopened_findings: list[CanonicalFinding] = []
    for acceptance in acceptances:
        acceptance.status = "expired"
        finding = by_id.get(acceptance.canonical_finding_id)
        if finding is None or finding.status != "accepted_risk":
            continue
        finding.status = "open"
        finding.status_version += 1
        session.add(
            FindingHistory(
                id=uuid.uuid4(),
                organization_id=finding.organization_id,
                canonical_finding_id=finding.id,
                previous_status="accepted_risk",
                new_status="open",
                reason="Approved risk acceptance expired",
                occurred_at=reference,
            )
        )
        await audit_service.record(
            session,
            action=audit_service.AuditAction.FINDING_STATUS_CHANGE,
            organization_id=finding.organization_id,
            resource_type="canonical_finding",
            resource_id=finding.id,
            detail={"from": "accepted_risk", "to": "open", "reason": "risk_acceptance_expired"},
        )
        reopened_findings.append(finding)
    if reopened_findings:
        asset_ids = {finding.asset_id for finding in reopened_findings}
        assets = (
            await session.execute(
                select(Asset).where(Asset.id.in_(asset_ids))
            )
        ).scalars().all()
        assets_by_id = {asset.id: asset for asset in assets}
        from app.services.automation import queue_finding_event

        for finding in reopened_findings:
            asset = assets_by_id.get(finding.asset_id)
            if asset is not None and asset.organization_id == finding.organization_id:
                await queue_finding_event(
                    session,
                    finding=finding,
                    asset=asset,
                    trigger="finding.updated",
                    event_key_suffix=f":version:{finding.status_version}",
                )
    return len(acceptances)


__all__ = [
    "approve_risk_acceptance",
    "complete_assessment_retest",
    "complete_retest",
    "expire_risk_acceptances",
    "request_retest",
    "schedule_retest",
    "request_risk_acceptance",
]
