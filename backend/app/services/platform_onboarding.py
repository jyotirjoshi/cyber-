"""Evidence-derived first-value journey for a tenant."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import AgentRunStatus, AssessmentStatus, IntegrationStatus, Permission
from app.db.models.agent import AgentRun
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.finding import TicketLink
from app.db.models.identity import Membership
from app.db.models.integration import Integration
from app.db.models.report import ReportSchedule
from app.db.models.soc import DetectionRule
from app.db.repository import tenant_select
from app.schemas.platform import FirstValueAreaOut, OnboardingStepOut, PlatformOnboardingOut
from app.services.context import Principal
from app.services.platform_readiness import get_readiness


@dataclass(frozen=True, slots=True)
class _Milestone:
    key: str
    title: str
    description: str
    action_label: str
    action_path: str
    passed: bool
    evidence: str


def build_onboarding(
    *,
    member_count: int,
    verified_integrations: int,
    asset_count: int,
    completed_assessments: int,
    completed_agent_runs: int,
    remediation_tickets: int,
    active_detection_rules: int,
    scheduled_reports: int,
    backup_ready: bool,
    restore_ready: bool,
    now: dt.datetime | None = None,
) -> PlatformOnboardingOut:
    """Build an ordered journey whose completion comes only from product evidence."""

    milestones = [
        _Milestone(
            "team",
            "Invite your operating team",
            "Avoid a single-person operational and recovery dependency.",
            "Manage organization",
            "/settings/organization",
            member_count >= 2,
            f"{member_count} active members",
        ),
        _Milestone(
            "verified_connector",
            "Connect a security source",
            "Configure credentials and pass a live provider contract test.",
            "Open integrations",
            "/integrations",
            verified_integrations > 0,
            f"{verified_integrations} recently verified connectors",
        ),
        _Milestone(
            "asset_inventory",
            "Establish asset coverage",
            "Import or discover the first persistent asset before interpreting exposure.",
            "Open asset inventory",
            "/assets",
            asset_count > 0,
            f"{asset_count} tracked assets",
        ),
        _Milestone(
            "first_assessment",
            "Complete the first assessment",
            "Run an authorized assessment through discovery, validation, analysis, and reporting.",
            "Start assessment",
            "/assessments/new",
            completed_assessments > 0,
            f"{completed_assessments} completed assessments",
        ),
        _Milestone(
            "first_agent_run",
            "Complete an agent investigation",
            "Give the AI worker a measurable objective and review its evidence-linked result.",
            "Open AI worker",
            "/agent",
            completed_agent_runs > 0,
            f"{completed_agent_runs} completed agent runs",
        ),
        _Milestone(
            "first_remediation",
            "Route the first remediation",
            "Assign a finding to an external work item and verify two-way lifecycle ownership.",
            "Open remediation",
            "/remediation",
            remediation_tickets > 0,
            f"{remediation_tickets} linked remediation tickets",
        ),
        _Milestone(
            "continuous_operations",
            "Enable continuous operations",
            "Activate detection engineering and scheduled stakeholder reporting.",
            "Open control plane",
            "/control-plane",
            active_detection_rules > 0 and scheduled_reports > 0,
            f"{active_detection_rules} active rules; {scheduled_reports} report schedules",
        ),
        _Milestone(
            "recovery_evidence",
            "Prove service recovery",
            "Record a recent backup verification and a successful restore drill with RPO and RTO.",
            "Record recovery evidence",
            "/settings/organization",
            backup_ready and restore_ready,
            "Backup and restore evidence current"
            if backup_ready and restore_ready
            else "Recovery evidence incomplete",
        ),
    ]
    first_incomplete = next(
        (index for index, item in enumerate(milestones) if not item.passed), None
    )
    steps: list[OnboardingStepOut] = []
    for index, item in enumerate(milestones):
        status = "complete" if item.passed else "ready" if index == first_incomplete else "blocked"
        steps.append(
            OnboardingStepOut(
                key=item.key,
                title=item.title,
                description=item.description,
                status=status,
                action_label=item.action_label,
                action_path=item.action_path,
                evidence=item.evidence,
            )
        )
    completed = sum(item.passed for item in milestones)
    area_inputs = [
        (
            "sources",
            "Security sources",
            verified_integrations > 0,
            f"{verified_integrations} verified connectors",
            "Verify a live connector",
            "/integrations",
        ),
        (
            "inventory",
            "Asset inventory",
            asset_count > 0,
            f"{asset_count} tracked assets",
            "Discover or import the first asset",
            "/assets",
        ),
        (
            "exposure",
            "Exposure evidence",
            completed_assessments > 0,
            f"{completed_assessments} completed assessments",
            "Complete an authorized assessment",
            "/assessments/new",
        ),
        (
            "remediation",
            "Remediation loop",
            remediation_tickets > 0,
            f"{remediation_tickets} linked tickets",
            "Route a finding to its owner",
            "/remediation",
        ),
        (
            "continuous_operations",
            "Continuous operations",
            active_detection_rules > 0 and scheduled_reports > 0,
            f"{active_detection_rules} active rules; {scheduled_reports} scheduled reports",
            "Activate detection and scheduled reporting",
            "/control-plane",
        ),
        (
            "resilience",
            "Recovery readiness",
            backup_ready and restore_ready,
            "Backup and restore evidence current"
            if backup_ready and restore_ready
            else "Recovery evidence incomplete",
            "Verify backup and complete a restore drill",
            "/settings/organization",
        ),
    ]
    first_value_areas = [
        FirstValueAreaOut(
            key=key,
            label=label,
            achieved=achieved,
            evidence=evidence,
            gap=None if achieved else gap,
            action_path=action_path,
        )
        for key, label, achieved, evidence, gap, action_path in area_inputs
    ]
    return PlatformOnboardingOut(
        complete=completed == len(milestones),
        percent=round(completed / len(milestones) * 100),
        completed=completed,
        total=len(milestones),
        next_step=milestones[first_incomplete].key if first_incomplete is not None else None,
        steps=steps,
        first_value_score=round(
            sum(area.achieved for area in first_value_areas) / len(first_value_areas) * 100
        ),
        first_value_areas=first_value_areas,
        evaluated_at=now or utcnow(),
    )


async def _count(session: AsyncSession, statement: object) -> int:
    return int((await session.scalar(statement)) or 0)  # type: ignore[arg-type]


async def get_onboarding(session: AsyncSession, principal: Principal) -> PlatformOnboardingOut:
    principal.require(Permission.ORG_READ)
    now = utcnow()
    readiness = await get_readiness(session, principal)
    readiness_by_key = {item.key: item.status == "passed" for item in readiness.checks}
    org_id = principal.organization_id
    member_count = await _count(
        session,
        select(func.count())
        .select_from(Membership)
        .where(
            Membership.organization_id == org_id,
            Membership.accepted_at.is_not(None),
        ),
    )
    verified_integrations = await _count(
        session,
        tenant_select(Integration, org_id)
        .with_only_columns(func.count())
        .where(
            Integration.is_enabled.is_(True),
            Integration.status == IntegrationStatus.CONFIGURED.value,
            Integration.last_verified_at >= now - dt.timedelta(days=7),
        ),
    )
    asset_count = await _count(
        session, tenant_select(Asset, org_id).with_only_columns(func.count())
    )
    completed_assessments = await _count(
        session,
        tenant_select(Assessment, org_id)
        .with_only_columns(func.count())
        .where(Assessment.status == AssessmentStatus.COMPLETED.value),
    )
    completed_agent_runs = await _count(
        session,
        tenant_select(AgentRun, org_id)
        .with_only_columns(func.count())
        .where(AgentRun.status == AgentRunStatus.COMPLETED.value),
    )
    remediation_tickets = await _count(
        session, tenant_select(TicketLink, org_id).with_only_columns(func.count())
    )
    active_detection_rules = await _count(
        session,
        tenant_select(DetectionRule, org_id)
        .with_only_columns(func.count())
        .where(DetectionRule.status == "active"),
    )
    scheduled_reports = await _count(
        session,
        tenant_select(ReportSchedule, org_id)
        .with_only_columns(func.count())
        .where(ReportSchedule.is_enabled.is_(True)),
    )
    return build_onboarding(
        member_count=member_count,
        verified_integrations=verified_integrations,
        asset_count=asset_count,
        completed_assessments=completed_assessments,
        completed_agent_runs=completed_agent_runs,
        remediation_tickets=remediation_tickets,
        active_detection_rules=active_detection_rules,
        scheduled_reports=scheduled_reports,
        backup_ready=readiness_by_key.get("backup_freshness", False),
        restore_ready=readiness_by_key.get("restore_drill", False),
        now=now,
    )


__all__ = ["build_onboarding", "get_onboarding"]
