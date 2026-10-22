"""Evidence-based onboarding and disaster-recovery readiness."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import IntegrationStatus, Permission
from app.db.models.asset import Asset
from app.db.models.identity import Membership, Organization
from app.db.models.integration import Integration
from app.db.models.platform import PlatformApiKey
from app.db.models.report import ReportSchedule
from app.db.models.soc import DetectionRule
from app.db.repository import tenant_select
from app.schemas.platform import PlatformReadinessOut, ReadinessCheckOut
from app.services.context import Principal


@dataclass(frozen=True, slots=True)
class _Check:
    key: str
    category: str
    label: str
    passed: bool
    detail: str
    action_path: str | None


def _moment(value: object) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
        except ValueError:
            return None
    return None


def build_readiness(
    *,
    organization_active: bool,
    member_count: int,
    asset_count: int,
    configured_integrations: int,
    verified_integrations: int,
    active_api_keys: int,
    active_detection_rules: int,
    scheduled_reports: int,
    backup_verified_at: dt.datetime | None,
    restore_tested_at: dt.datetime | None,
    recovery_point_minutes: int | None,
    recovery_time_minutes: int | None,
    backup_evidence_ref: str | None,
    restore_evidence_ref: str | None,
    now: dt.datetime | None = None,
) -> PlatformReadinessOut:
    checked_at = now or utcnow()
    backup_current = bool(
        backup_verified_at and checked_at - backup_verified_at <= dt.timedelta(hours=24)
    )
    restore_current = bool(
        restore_tested_at and checked_at - restore_tested_at <= dt.timedelta(days=90)
    )
    raw = [
        _Check("organization", "onboarding", "Organization active", organization_active, "Organization can accept production workloads." if organization_active else "Activate the organization before onboarding workloads.", "/settings/organization"),
        _Check("team", "onboarding", "Operational team", member_count >= 2, f"{member_count} active member(s); at least two avoids a single-person recovery dependency.", "/settings/organization"),
        _Check("assets", "coverage", "Asset inventory", asset_count > 0, f"{asset_count} asset(s) are tracked.", "/assets"),
        _Check("connector_configuration", "coverage", "Connector configured", configured_integrations > 0, f"{configured_integrations} connector(s) configured.", "/integrations"),
        _Check("connector_verification", "coverage", "Connector verified", verified_integrations > 0, f"{verified_integrations} connector(s) passed a live test in the last seven days.", "/integrations"),
        _Check("api_automation", "automation", "Automation credential", active_api_keys > 0, f"{active_api_keys} active scoped API key(s).", "/settings/api-keys"),
        _Check("soc_detection", "operations", "Active detection", active_detection_rules > 0, f"{active_detection_rules} active detection rule(s).", "/control-plane"),
        _Check("scheduled_reporting", "operations", "Scheduled reporting", scheduled_reports > 0, f"{scheduled_reports} enabled report schedule(s).", "/reports"),
        _Check("backup_freshness", "resilience", "Backup evidence", backup_current and recovery_point_minutes is not None and bool(backup_evidence_ref), "Backup evidence is under 24 hours old and an RPO is declared." if backup_current and recovery_point_minutes is not None and backup_evidence_ref else "Record a successful backup verification from the last 24 hours, its evidence reference, and recovery_point_minutes in organization policy.", "/settings/organization"),
        _Check("restore_drill", "resilience", "Restore drill", restore_current and recovery_time_minutes is not None and bool(restore_evidence_ref), "A restore drill passed in the last 90 days and an RTO is declared." if restore_current and recovery_time_minutes is not None and restore_evidence_ref else "Complete a restore drill within 90 days and record its evidence reference and recovery_time_minutes in organization policy.", "/settings/organization"),
    ]
    checks = [
        ReadinessCheckOut(
            key=item.key,
            category=item.category,
            label=item.label,
            status="passed" if item.passed else "blocked",
            detail=item.detail,
            action_path=item.action_path,
        )
        for item in raw
    ]
    passed = sum(item.passed for item in raw)
    return PlatformReadinessOut(
        ready=passed == len(raw),
        score=round(passed / len(raw) * 100),
        passed=passed,
        total=len(raw),
        checks=checks,
        evaluated_at=checked_at,
    )


async def get_readiness(
    session: AsyncSession, principal: Principal
) -> PlatformReadinessOut:
    principal.require(Permission.ORG_READ)
    now = utcnow()
    org = await session.scalar(select(Organization).where(Organization.id == principal.organization_id))
    policy: Mapping[str, object] = org.policy if org else {}
    member_count = int((await session.scalar(select(func.count()).select_from(Membership).where(Membership.organization_id == principal.organization_id, Membership.accepted_at.is_not(None)))) or 0)
    asset_count = int((await session.scalar(tenant_select(Asset, principal.organization_id).with_only_columns(func.count()))) or 0)
    configured_integrations = int((await session.scalar(tenant_select(Integration, principal.organization_id).with_only_columns(func.count()).where(Integration.is_enabled.is_(True), Integration.status != IntegrationStatus.DISABLED.value))) or 0)
    verified_integrations = int((await session.scalar(tenant_select(Integration, principal.organization_id).with_only_columns(func.count()).where(Integration.is_enabled.is_(True), Integration.status == IntegrationStatus.CONFIGURED.value, Integration.last_verified_at >= now - dt.timedelta(days=7)))) or 0)
    active_api_keys = int((await session.scalar(tenant_select(PlatformApiKey, principal.organization_id).with_only_columns(func.count()).where(PlatformApiKey.revoked_at.is_(None), or_(PlatformApiKey.expires_at.is_(None), PlatformApiKey.expires_at > now)))) or 0)
    active_detection_rules = int((await session.scalar(tenant_select(DetectionRule, principal.organization_id).with_only_columns(func.count()).where(DetectionRule.status == "active"))) or 0)
    scheduled_reports = int((await session.scalar(tenant_select(ReportSchedule, principal.organization_id).with_only_columns(func.count()).where(ReportSchedule.is_enabled.is_(True)))) or 0)
    return build_readiness(
        organization_active=bool(org and org.is_active),
        member_count=member_count,
        asset_count=asset_count,
        configured_integrations=configured_integrations,
        verified_integrations=verified_integrations,
        active_api_keys=active_api_keys,
        active_detection_rules=active_detection_rules,
        scheduled_reports=scheduled_reports,
        backup_verified_at=_moment(policy.get("dr_backup_verified_at")),
        restore_tested_at=_moment(policy.get("dr_restore_tested_at")),
        recovery_point_minutes=policy.get("recovery_point_minutes") if isinstance(policy.get("recovery_point_minutes"), int) else None,
        recovery_time_minutes=policy.get("recovery_time_minutes") if isinstance(policy.get("recovery_time_minutes"), int) else None,
        backup_evidence_ref=policy.get("dr_backup_evidence_ref") if isinstance(policy.get("dr_backup_evidence_ref"), str) else None,
        restore_evidence_ref=policy.get("dr_restore_evidence_ref") if isinstance(policy.get("dr_restore_evidence_ref"), str) else None,
        now=now,
    )
