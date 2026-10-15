"""Tenant-owned recurring assessment scheduling."""

from __future__ import annotations

import datetime as dt
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter
from pydantic import ValidationError
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    CynuxError,
    InvalidConfigurationError,
    ResourceNotFoundError,
    UnauthorizedTargetError,
)
from app.db.enums import Permission, Role
from app.db.models.assessment import RecurringScan, ScanProfile
from app.db.models.identity import Membership, Organization, User
from app.db.repository import tenant_select
from app.schemas.assessment import AssessmentCreateIn, RecurringScanCreateIn, ScanProfileCreateIn
from app.services import assessment as assessment_service
from app.services.context import Principal
from app.worker.dispatch import stage_assessment_run


def next_scan_time(expression: str, timezone: str, after: dt.datetime) -> dt.datetime:
    """Resolve a five-field cron expression in local time, returning a UTC instant."""
    if after.tzinfo is None:
        raise ValueError("A timezone-aware reference time is required")
    if len(expression.split()) != 5 or not croniter.is_valid(expression):
        raise ValueError("A valid five-field cron expression is required")
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("A valid IANA timezone is required") from exc
    result = croniter(expression, after.astimezone(zone)).get_next(dt.datetime)
    return result.astimezone(dt.UTC)


async def create_scan_profile(
    session: AsyncSession, principal: Principal, payload: ScanProfileCreateIn
) -> ScanProfile:
    principal.require(Permission.ASSESSMENT_CREATE)
    profile = ScanProfile(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        config=payload.model_dump(mode="json", exclude={"name"}),
    )
    session.add(profile)
    await session.flush()
    return profile


async def deactivate_scan_profile(
    session: AsyncSession,
    principal: Principal,
    profile_id: uuid.UUID,
) -> tuple[ScanProfile, int]:
    """Retire a profile and safely stop every enabled schedule that references it."""
    principal.require(Permission.ASSESSMENT_CREATE)
    profile = (
        await session.execute(
            tenant_select(ScanProfile, principal.organization_id)
            .where(ScanProfile.id == profile_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if profile is None:
        raise ResourceNotFoundError("Scan profile not found")

    profile.is_active = False
    schedules = list(
        (
            await session.execute(
                tenant_select(RecurringScan, principal.organization_id)
                .where(
                    RecurringScan.profile_id == profile.id,
                    RecurringScan.enabled.is_(True),
                )
                .with_for_update()
            )
        ).scalars().all()
    )
    for schedule in schedules:
        schedule.enabled = False
        schedule.last_error_code = "profile_deactivated"
    await session.flush()
    return profile, len(schedules)


async def create_recurring_scan(
    session: AsyncSession,
    principal: Principal,
    payload: RecurringScanCreateIn,
    settings: Settings,
) -> RecurringScan:
    principal.require(Permission.ASSESSMENT_CREATE)
    if principal.user_id is None or not payload.authorization.confirmed:
        raise UnauthorizedTargetError("A current human authorization is required")
    now = dt.datetime.now(dt.UTC)
    expiry = payload.authorization_expires_at
    if expiry.tzinfo is None or expiry <= now or expiry > now + dt.timedelta(days=90):
        raise InvalidConfigurationError(
            "Authorization expiry must be timezone-aware and in the future, within 90 days",
            user_message="Authorization expiry must be in the future, within 90 days.",
        )
    try:
        first_run = next_scan_time(payload.cron_expression, payload.timezone, now)
        second_run = next_scan_time(payload.cron_expression, payload.timezone, first_run)
    except ValueError as exc:
        raise InvalidConfigurationError(str(exc), user_message=str(exc)) from exc
    if second_run - first_run < dt.timedelta(minutes=15):
        raise InvalidConfigurationError(
            "Recurring scans must be at least 15 minutes apart",
            user_message="Recurring scans must be at least 15 minutes apart.",
        )
    if first_run >= expiry:
        raise InvalidConfigurationError(
            "Authorization must remain valid for the first scheduled run",
            user_message="Authorization must remain valid for the first scheduled run.",
        )
    profile = (
        await session.execute(
            tenant_select(ScanProfile, principal.organization_id).where(
                ScanProfile.id == payload.profile_id,
                ScanProfile.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if profile is None:
        raise ResourceNotFoundError("Scan profile not found")
    policy = await assessment_service._policy_for(session, principal, settings)
    validated = assessment_service._validate_targets(payload.targets, policy)
    schedule = RecurringScan(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        profile_id=profile.id,
        targets=[target.canonical for target in validated],
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        authorization_text=payload.authorization.attestation_text,
        authorization_evidence=payload.authorization.evidence_reference,
        authorization_expires_at=expiry,
        next_run_at=first_run,
        enabled=True,
    )
    session.add(schedule)
    await session.flush()
    return schedule


async def execute_due_scan(
    session: AsyncSession,
    schedule: RecurringScan,
    profile: ScanProfile,
    principal: Principal,
    settings: Settings,
    *,
    now: dt.datetime,
) -> uuid.UUID | None:
    """Create one assessment through the normal validation and authorization path."""
    if (
        profile.organization_id != schedule.organization_id
        or principal.organization_id != schedule.organization_id
    ):
        schedule.enabled = False
        schedule.last_error_code = "profile_tenant_mismatch"
        return None
    if schedule.authorization_expires_at <= now:
        schedule.enabled = False
        schedule.last_error_code = "authorization_expired"
        return None
    if not profile.is_active or principal.user_id is None:
        schedule.enabled = False
        schedule.last_error_code = "profile_or_actor_inactive"
        return None
    try:
        principal.require(Permission.ASSESSMENT_CREATE)
    except CynuxError:
        schedule.enabled = False
        schedule.last_error_code = "permission_revoked"
        return None
    try:
        next_due = next_scan_time(schedule.cron_expression, schedule.timezone, now)
        payload = AssessmentCreateIn.model_validate(
            {
                **profile.config,
                "targets": schedule.targets,
                "title": schedule.name,
                "authorization": {
                    "confirmed": True,
                    "attestation_text": schedule.authorization_text,
                    "evidence_reference": schedule.authorization_evidence,
                },
            }
        )
    except (ValidationError, ValueError):
        schedule.enabled = False
        schedule.last_error_code = "invalid_schedule_config"
        return None
    try:
        async with session.begin_nested():
            assessment = await assessment_service.create_assessment(
                session, principal, payload, settings, authorization_method="scheduled"
            )
            await session.flush()
            stage_assessment_run(session, principal, assessment)
    except CynuxError as exc:
        schedule.next_run_at = next_due
        schedule.last_error_code = exc.code
        return None
    schedule.last_run_at = now
    schedule.last_assessment_id = assessment.id
    schedule.next_run_at = next_due
    schedule.last_error_code = None
    return assessment.id


async def run_due_scans(
    session: AsyncSession,
    settings: Settings,
    *,
    now: dt.datetime | None = None,
    limit: int = 10,
) -> int:
    """Claim due tenant schedules and use each operator's current membership."""
    now = now or dt.datetime.now(dt.UTC)
    ranked = (
        select(
            RecurringScan.id.label("schedule_id"),
            func.row_number()
            .over(
                partition_by=RecurringScan.organization_id,
                order_by=(RecurringScan.next_run_at, RecurringScan.id),
            )
            .label("tenant_rank"),
        )
        .where(RecurringScan.enabled.is_(True), RecurringScan.next_run_at <= now)
        .subquery()
    )
    statement = (
        select(RecurringScan, ScanProfile)
        .join(ranked, and_(ranked.c.schedule_id == RecurringScan.id, ranked.c.tenant_rank == 1))
        .join(
            ScanProfile,
            and_(
                ScanProfile.id == RecurringScan.profile_id,
                ScanProfile.organization_id == RecurringScan.organization_id,
            ),
        )
        .order_by(RecurringScan.next_run_at, RecurringScan.id)
        .limit(max(1, min(limit, 100)))
        .with_for_update(of=RecurringScan, skip_locked=True)
    )
    rows = (await session.execute(statement)).all()
    created = 0
    for schedule, profile in rows:
        role_raw = None
        if schedule.created_by_id is not None:
            role_raw = (
                await session.execute(
                    select(Membership.role)
                    .join(User, User.id == Membership.user_id)
                    .join(Organization, Organization.id == Membership.organization_id)
                    .where(
                        Membership.organization_id == schedule.organization_id,
                        Membership.user_id == schedule.created_by_id,
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
            schedule.enabled = False
            schedule.last_error_code = "operator_inactive"
            continue
        principal = Principal.for_worker(
            organization_id=schedule.organization_id,
            user_id=schedule.created_by_id,
            role=role,
        )
        assessment_id = await execute_due_scan(
            session, schedule, profile, principal, settings, now=now
        )
        if assessment_id is not None:
            created += 1
    return created


__all__ = [
    "create_recurring_scan",
    "create_scan_profile",
    "execute_due_scan",
    "next_scan_time",
    "run_due_scans",
]
