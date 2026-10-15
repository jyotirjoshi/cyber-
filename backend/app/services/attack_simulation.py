"""Authorization-bound breach and attack simulation campaigns."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import select

from app.core.config import Settings
from app.core.errors import CynuxError, InvalidConfigurationError
from app.db.enums import (
    ApprovalDecision,
    AssessmentDepth,
    EngagementType,
    ExecutionMode,
    JobStatus,
    Permission,
    Role,
    Scope,
)
from app.db.models.assessment import Approval, Assessment
from app.db.models.canonical import (
    AttackSimulationCampaign,
    AttackSimulationRun,
    AttackSimulationTechniqueRun,
)
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.db.models.identity import Membership, Organization, User
from app.schemas.assessment import AssessmentCreateIn
from app.schemas.attack_simulation import AttackSimulationCampaignCreateIn
from app.services import assessment as assessment_service
from app.services import job as job_service
from app.services.bas_techniques import (
    CATALOG_VERSION,
    classify_control_result,
    compare_run_outcomes,
    get_technique,
    require_technique_approval,
)
from app.services.context import Principal
from app.services.recurring_scan import next_scan_time
from app.worker.dispatch import stage_assessment_run

SUPPORTED_SCENARIOS = frozenset(
    {
        "external_exposure",
        "web_attack_surface",
        "api_authorization",
        "credential_exposure",
        "cloud_misconfiguration",
    }
)


def _validate_scenario_targets(scenarios: list[str], targets: list[str]) -> None:
    unmatched = [
        scenario
        for scenario in scenarios
        if not any(_supports(scenario, target) for target in targets)
    ]
    if unmatched:
        raise InvalidConfigurationError(
            "Campaign scenarios have no compatible target",
            user_message=(
                "Each validation scenario needs a compatible target. "
                f"Review: {', '.join(sorted(unmatched))}."
            ),
        )


def _supports(scenario: str, target: str) -> bool:
    try:
        get_technique(scenario, target)
        return True
    except CynuxError:
        return False


async def create_campaign(
    session,
    principal: Principal,
    payload: AttackSimulationCampaignCreateIn,
    *,
    now: dt.datetime | None = None,
) -> AttackSimulationCampaign:
    """Persist a tenant-local schedule after validating its bounded declarative inputs."""
    principal.require(Permission.ASSESSMENT_CREATE)
    now = now or dt.datetime.now(dt.UTC)
    if payload.authorization_expires_at.tzinfo is None or payload.authorization_expires_at <= now:
        raise InvalidConfigurationError("Campaign authorization must expire in the future")
    unsupported = set(payload.scenarios).difference(SUPPORTED_SCENARIOS)
    if unsupported:
        raise InvalidConfigurationError("Campaign includes unsupported validation scenarios")
    _validate_scenario_targets(payload.scenarios, payload.targets)
    try:
        due_at = (
            next_scan_time(payload.cron_expression, payload.timezone, now)
            if payload.cron_expression
            else None
        )
    except ValueError as exc:
        raise InvalidConfigurationError(str(exc)) from exc
    campaign = AttackSimulationCampaign(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        authorization_text=payload.authorization.attestation_text,
        authorization_reference=payload.authorization.evidence_reference or "operator-attestation",
        authorization_expires_at=payload.authorization_expires_at,
        scenarios=payload.scenarios,
        targets=payload.targets,
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        next_run_at=due_at,
        status="active",
    )
    session.add(campaign)
    await session.flush()
    return campaign


async def _create_execution_run(
    session,
    campaign: AttackSimulationCampaign,
    assessment: Assessment,
    *,
    triggered_by_id: uuid.UUID | None,
) -> AttackSimulationRun:
    baseline_id = await session.scalar(
        select(AttackSimulationRun.id)
        .where(
            AttackSimulationRun.organization_id == campaign.organization_id,
            AttackSimulationRun.campaign_id == campaign.id,
            AttackSimulationRun.status == "completed",
        )
        .order_by(AttackSimulationRun.completed_at.desc())
        .limit(1)
    )
    run = AttackSimulationRun(
        organization_id=campaign.organization_id,
        campaign_id=campaign.id,
        assessment_id=assessment.id,
        baseline_run_id=baseline_id,
        status="awaiting_approval",
        catalog_version=CATALOG_VERSION,
        scenarios_snapshot=list(campaign.scenarios),
        targets_snapshot=list(campaign.targets),
        summary={},
        triggered_by_id=triggered_by_id,
    )
    session.add(run)
    await session.flush()
    technique_rows: list[AttackSimulationTechniqueRun] = []
    for scenario in campaign.scenarios:
        for target in campaign.targets:
            if not _supports(scenario, target):
                continue
            technique = get_technique(scenario, target)
            technique_rows.append(
                AttackSimulationTechniqueRun(
                    organization_id=campaign.organization_id,
                    run_id=run.id,
                    technique_key=technique.key,
                    scenario=scenario,
                    mitre_technique=technique.mitre_technique,
                    adapter=technique.adapter.value,
                    target=target,
                    risk_class=technique.risk_class,
                    status="awaiting_approval",
                    expected_evidence=list(technique.expected_evidence),
                    evidence_artifact_ids=[],
                    evidence_summary={"cleanup": technique.cleanup},
                )
            )
    if not technique_rows:
        raise InvalidConfigurationError("Campaign produced no executable validation techniques")
    session.add_all(technique_rows)
    await session.flush()
    return run


async def execute_due_campaign(
    session,
    campaign: AttackSimulationCampaign,
    principal: Principal,
    settings: Settings,
    *,
    now: dt.datetime,
) -> uuid.UUID | None:
    """Stage one supervised assessment only while the original authority remains valid."""
    if campaign.status != "active":
        return None
    if campaign.authorization_expires_at <= now:
        campaign.status = "paused"
        campaign.last_error_code = "authorization_expired"
        return None
    if principal.organization_id != campaign.organization_id:
        campaign.status = "paused"
        campaign.last_error_code = "operator_tenant_mismatch"
        return None
    try:
        principal.require(Permission.ASSESSMENT_CREATE)
    except CynuxError:
        campaign.status = "paused"
        campaign.last_error_code = "permission_revoked"
        return None
    try:
        next_due = next_scan_time(campaign.cron_expression, campaign.timezone, now)
    except ValueError:
        campaign.status = "paused"
        campaign.last_error_code = "invalid_schedule_config"
        return None

    payload = AssessmentCreateIn(
        targets=campaign.targets,
        title=campaign.name,
        scope=Scope.EXTERNAL,
        depth=AssessmentDepth.STANDARD,
        engagement_type=EngagementType.RED_TEAM,
        execution_mode=ExecutionMode.SUPERVISED,
        objective="Run approved attack-validation scenarios: " + ", ".join(campaign.scenarios),
        authorization={
            "confirmed": True,
            "attestation_text": campaign.authorization_text,
            "evidence_reference": campaign.authorization_reference,
        },
    )
    assessment = await assessment_service.create_assessment(
        session, principal, payload, settings, authorization_method="attack_simulation"
    )
    await session.flush()
    await _create_execution_run(
        session, campaign, assessment, triggered_by_id=principal.user_id
    )
    stage_assessment_run(session, principal, assessment)
    campaign.last_run_at = now
    campaign.next_run_at = next_due
    campaign.last_assessment_id = assessment.id
    campaign.last_error_code = None
    return assessment.id


async def run_due_campaigns(
    session,
    settings: Settings,
    *,
    now: dt.datetime | None = None,
    limit: int = 10,
) -> int:
    """Claim due campaigns and rehydrate their creator's current tenant authority."""
    now = now or dt.datetime.now(dt.UTC)
    # This is the worker's tenant-discovery sweep. Each selected row is subsequently
    # re-bound to its own tenant principal before it can create any assessment.
    campaigns = list(
        (
            await session.execute(
                select(AttackSimulationCampaign)
                .where(
                    AttackSimulationCampaign.status == "active",
                    AttackSimulationCampaign.next_run_at <= now,
                )
                .order_by(AttackSimulationCampaign.next_run_at, AttackSimulationCampaign.id)
                .limit(max(1, min(limit, 100)))
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()
    )
    created = 0
    for campaign in campaigns:
        role_raw = (
            await session.execute(
                select(Membership.role)
                .join(User, User.id == Membership.user_id)
                .join(Organization, Organization.id == Membership.organization_id)
                .where(
                    Membership.organization_id == campaign.organization_id,
                    Membership.user_id == campaign.created_by_id,
                    Membership.accepted_at.is_not(None),
                    User.is_active.is_(True),
                    Organization.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        try:
            role = Role(role_raw) if role_raw is not None else None
        except ValueError:
            role = None
        if role is None:
            campaign.status = "paused"
            campaign.last_error_code = "operator_inactive"
            continue
        principal = Principal.for_worker(
            organization_id=campaign.organization_id,
            user_id=campaign.created_by_id,
            role=role,
        )
        if await execute_due_campaign(session, campaign, principal, settings, now=now) is not None:
            created += 1
    return created


async def run_campaign_now(
    session,
    principal: Principal,
    campaign_id: uuid.UUID,
) -> AttackSimulationCampaign:
    """Trigger an immediate run for an active, authorized campaign.

    Enforces the same constraints as the scheduled path: active status, non-expired
    authorization, and the caller's current ASSESSMENT_APPROVE permission.
    """
    from app.core.errors import InvalidConfigurationError, ResourceNotFoundError
    from app.db.repository import tenant_select

    principal.require(Permission.ASSESSMENT_APPROVE)
    campaign = (
        await session.execute(
            tenant_select(AttackSimulationCampaign, principal.organization_id)
            .where(AttackSimulationCampaign.id == campaign_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if campaign is None or campaign.organization_id != principal.organization_id:
        raise ResourceNotFoundError("Attack simulation campaign not found")
    if campaign.status != "active":
        raise InvalidConfigurationError(
            "Only active campaigns can be run manually.",
            user_message="Only active campaigns can be run manually.",
        )
    now = dt.datetime.now(dt.UTC)
    if campaign.authorization_expires_at <= now:
        campaign.status = "paused"
        campaign.last_error_code = "authorization_expired"
        raise InvalidConfigurationError(
            "Campaign authorization has expired.",
            user_message="Campaign authorization has expired. Renew it before running.",
        )
    # Stage the assessment directly through the normal path so the approval gate applies
    payload = AssessmentCreateIn(
        targets=campaign.targets,
        title=campaign.name,
        scope=Scope.EXTERNAL,
        depth=AssessmentDepth.STANDARD,
        engagement_type=EngagementType.RED_TEAM,
        execution_mode=ExecutionMode.SUPERVISED,
        objective="Manual run of attack-validation scenarios: " + ", ".join(campaign.scenarios),
        authorization={
            "confirmed": True,
            "attestation_text": campaign.authorization_text,
            "evidence_reference": campaign.authorization_reference,
        },
    )
    from app.core.config import get_settings
    settings = get_settings()
    assessment = await assessment_service.create_assessment(
        session, principal, payload, settings, authorization_method="attack_simulation"
    )
    await session.flush()
    await _create_execution_run(
        session, campaign, assessment, triggered_by_id=principal.user_id
    )
    stage_assessment_run(session, principal, assessment)
    campaign.last_run_at = now
    campaign.last_assessment_id = assessment.id
    campaign.last_error_code = None
    return campaign


async def execute_pending_techniques(session, *, limit: int = 25) -> int:
    """Dispatch approved catalog techniques and reconcile terminal scanner evidence."""
    rows = list(
        (
            await session.scalars(
                select(AttackSimulationTechniqueRun)
                .where(
                    AttackSimulationTechniqueRun.status.in_(
                        ("queued", "awaiting_approval", "running")
                    )
                )
                .order_by(AttackSimulationTechniqueRun.created_at)
                .limit(max(1, min(limit, 100)))
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    settled = 0
    now = dt.datetime.now(dt.UTC)
    for row in rows:
        run = await session.get(AttackSimulationRun, row.run_id)
        if run is None:
            continue
        if row.scanner_job_id is None:
            assessment = await session.get(Assessment, run.assessment_id)
            if assessment is None:
                row.status = "failed"
                row.control_result = "error"
                row.error_code = "assessment_missing"
                settled += 1
                continue
            approval = await session.scalar(
                select(Approval)
                .where(
                    Approval.organization_id == row.organization_id,
                    Approval.assessment_id == run.assessment_id,
                    Approval.decision.in_(
                        (
                            ApprovalDecision.APPROVED.value,
                            ApprovalDecision.APPROVED_ALL.value,
                            ApprovalDecision.CUSTOMIZED.value,
                        )
                    ),
                )
                .order_by(Approval.resolved_at.desc())
                .limit(1)
            )
            technique = get_technique(row.scenario, row.target)
            try:
                require_technique_approval(technique, approval, now=now)
            except CynuxError:
                row.status = "awaiting_approval"
                run.status = "awaiting_approval"
                continue
            approved_scanners = set((approval.approved_payload or {}).get("scanners", []))
            if row.adapter not in approved_scanners:
                row.status = "awaiting_approval"
                row.error_code = "scanner_not_approved"
                continue
            job = await job_service.enqueue_job(
                session,
                assessment,
                scanner=row.adapter,
                targets=[row.target],
                timeout_seconds=technique.timeout_seconds,
                idempotency_key=f"bas:{row.id}",
            )
            row.approval_id = approval.id
            row.scanner_job_id = job.id
            row.status = "running"
            row.started_at = now
            row.error_code = None
            run.status = "running"
            run.started_at = run.started_at or now
            continue

        job = await session.get(ScannerJob, row.scanner_job_id)
        if job is None or job.status in (JobStatus.QUEUED.value, JobStatus.RUNNING.value):
            continue
        artifact_ids = list(
            (
                await session.scalars(
                    select(ScannerArtifact.id).where(
                        ScannerArtifact.organization_id == row.organization_id,
                        ScannerArtifact.job_id == job.id,
                    )
                )
            ).all()
        )
        row.exit_code = job.exit_code
        row.evidence_artifact_ids = [str(item) for item in artifact_ids]
        row.completed_at = now
        row.control_result = classify_control_result(
            exit_code=job.exit_code,
            artifact_ids=artifact_ids,
        )
        row.status = "completed" if row.control_result != "error" else "failed"
        row.error_code = job.failure_code
        row.evidence_summary = {
            **(row.evidence_summary or {}),
            "artifact_count": len(artifact_ids),
            "finding_count": job.imported_finding_count,
            "archived": job.artifacts_archived,
        }
        settled += 1

    run_ids = {row.run_id for row in rows}
    for run_id in run_ids:
        await _reconcile_run(session, run_id, now=now)
    return settled


async def _reconcile_run(session, run_id: uuid.UUID, *, now: dt.datetime) -> None:
    run = await session.get(AttackSimulationRun, run_id)
    if run is None:
        return
    techniques = list(
        (
            await session.scalars(
                select(AttackSimulationTechniqueRun).where(
                    AttackSimulationTechniqueRun.run_id == run_id
                )
            )
        ).all()
    )
    if not techniques or any(
        row.status in ("queued", "awaiting_approval", "running") for row in techniques
    ):
        return
    outcomes = {f"{row.scenario}:{row.target}": row.control_result or "inconclusive" for row in techniques}
    baseline_outcomes: dict[str, str] = {}
    if run.baseline_run_id is not None:
        baseline_rows = await session.scalars(
            select(AttackSimulationTechniqueRun).where(
                AttackSimulationTechniqueRun.run_id == run.baseline_run_id
            )
        )
        baseline_outcomes = {
            f"{row.scenario}:{row.target}": row.control_result or "inconclusive"
            for row in baseline_rows.all()
        }
    counts = {name: list(outcomes.values()).count(name) for name in ("detected", "prevented", "inconclusive", "error")}
    run.summary = {
        "counts": counts,
        "comparison": compare_run_outcomes(current=outcomes, baseline=baseline_outcomes),
        "evidence_complete": all(bool(row.evidence_artifact_ids) for row in techniques),
    }
    run.status = "failed" if counts["error"] == len(techniques) else "completed"
    run.completed_at = now


__all__ = [
    "SUPPORTED_SCENARIOS",
    "create_campaign",
    "execute_due_campaign",
    "run_campaign_now",
    "run_due_campaigns",
    "execute_pending_techniques",
]
