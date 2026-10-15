"""Report row lifecycle and read paths (FR-030, FR-039).

The rendering pipeline lives in :mod:`app.reporting`; this module owns the ``reports``
row it writes to and every path that reads one back.  The split is deliberate and
one-directional -- ``app.reporting`` depends on this service, never the reverse -- so the
pipeline never has to know how a row is tenant-scoped, audited or projected, and this
service never imports WeasyPrint.

Three things are load-bearing here:

**The row is created ``pending`` before any rendering starts.**  A report can take
seconds (PDF) and the operator is entitled to see that one is being produced, so
:func:`create_report` commits an intent the UI can poll.  :func:`begin_generation`,
:func:`complete_generation` and :func:`fail_generation` walk it through
``pending -> generating -> ready`` / ``failed``; a failed render leaves a row that
*records the failure* rather than vanishing, because a report that silently never
appears is indistinguishable from one nobody asked for.

**Downloads stream through the API, not a presigned URL.**  Per
:mod:`app.integrations.storage`, the MinIO endpoint in the Compose topology is not
reachable from a browser, so :func:`read_report_bytes` fetches the bytes (tenant-checked
by the key prefix) and the route streams them.  It records the ``report.download`` audit
row FR-032 requires -- a report leaving the system is an event, not a read.

**Reads are projections over columns only.**  Every field ``ReportOut`` needs is a
column on the row, so no relationship is eager-loaded and the ``lazy="raise_on_sql"``
guard is never tripped.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from collections.abc import Sequence
from html import escape

import structlog
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, CynuxError, PermissionDeniedError
from app.db.enums import NotificationChannel, NotificationEvent, Permission, ReportFormat, ReportStatus, Role
from app.db.models.assessment import Assessment
from app.db.models.identity import Membership, Organization, User
from app.db.models.notification import Notification
from app.db.models.report import Report, ReportDistribution, ReportSchedule, ReportTemplate
from app.db.repository import TenantRepository, tenant_select
from app.db.session import session_scope
from app.integrations.storage import ObjectStorage, StoredObject
from app.schemas.report import ReportDetailOut, ReportOut, ReportScheduleCreateIn
from app.services import audit as audit_service
from app.services.context import Principal
from app.services.notification import NotificationContent, dispatch
from app.services.scheduling import next_cron_time

log = structlog.get_logger(__name__)

#: Column width of ``reports.title``; restated so a long AI/derived title is trimmed here
#: rather than raising ``StringDataRightTruncation`` at the caller's commit.
_MAX_TITLE = 300

#: Column width of ``reports.failure_reason`` is ``Text`` (unbounded), but an unbounded
#: reason is still a way to bloat the row from one failed render.
_MAX_FAILURE_REASON = 2000


def report_schedule_download_url(public_base_url: str, report_id: uuid.UUID) -> str:
    """Return the authenticated report URL for in-product schedule references."""
    return f"{public_base_url.rstrip('/')}/api/v1/reports/{report_id}/download"


def report_schedule_share_url(public_base_url: str, token: str) -> str:
    """Return the unauthenticated but expiring/revocable URL used in recipient email."""
    return f"{public_base_url.rstrip('/')}/api/v1/shared/reports/{token}"


async def create_report_schedule(
    session: AsyncSession, principal: Principal, payload: ReportScheduleCreateIn
) -> ReportSchedule:
    """Create a tenant-owned cron schedule for future fresh report snapshots."""
    principal.require(Permission.REPORT_GENERATE)
    assessment = (
        await session.execute(
            tenant_select(Assessment, principal.organization_id).where(Assessment.id == payload.assessment_id)
        )
    ).scalar_one_or_none()
    if assessment is None:
        from app.core.errors import ResourceNotFoundError

        raise ResourceNotFoundError("Assessment not found")
    if payload.template_id is not None:
        template = await session.scalar(
            tenant_select(ReportTemplate, principal.organization_id).where(
                ReportTemplate.id == payload.template_id,
                ReportTemplate.is_active.is_(True),
            )
        )
        if template is None:
            from app.core.errors import ResourceNotFoundError

            raise ResourceNotFoundError("Report template not found")
    schedule = ReportSchedule(
        organization_id=principal.organization_id,
        assessment_id=assessment.id,
        created_by_id=principal.user_id,
        template_id=payload.template_id,
        name=payload.name.strip(),
        title=payload.title,
        format=payload.format.value,
        audience=payload.audience,
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        recipients=[str(email) for email in payload.recipients],
        next_run_at=next_cron_time(payload.cron_expression, payload.timezone, _now()),
    )
    session.add(schedule)
    await session.flush()
    return schedule


async def run_due_report_schedules(
    session: AsyncSession, settings, *, renderer, now: dt.datetime | None = None, limit: int = 10
) -> int:
    """Process bounded due occurrences without releasing claims during rendering.

    This worker-only service commits each schedule separately. Rendering has its
    own session because its progress commits must not release the schedule lock.
    The occurrence's deterministic report ID makes restart/delivery retries reuse
    an already stored report while cursor advancement and email staging are atomic.
    """
    current = now or _now()
    count = 0
    storage = ObjectStorage(settings)
    attempted: set[uuid.UUID] = set()
    for _ in range(max(1, min(limit, 100))):
        schedule = (
            await session.execute(
                select(ReportSchedule)
                .where(
                    ReportSchedule.is_enabled.is_(True),
                    ReportSchedule.next_run_at <= current,
                    ReportSchedule.id.not_in(attempted),
                )
                .order_by(ReportSchedule.next_run_at, ReportSchedule.id)
                .limit(1)
                .with_for_update(skip_locked=True)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if schedule is None:
            break
        attempted.add(schedule.id)
        membership = (
            await session.execute(
                select(Membership)
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
        assessment = await session.get(Assessment, schedule.assessment_id)
        if membership is None or assessment is None or assessment.organization_id != schedule.organization_id:
            schedule.is_enabled = False
            await session.commit()
            continue
        try:
            principal = Principal.for_worker(
                organization_id=schedule.organization_id,
                user_id=schedule.created_by_id,
                role=Role(membership.role),
            )
            principal.require(Permission.REPORT_GENERATE)
            # Coalesce missed intervals into one fresh snapshot, not a burst of
            # obsolete weekly reports after a long worker outage.
            next_cron_time(
                schedule.cron_expression, schedule.timezone, max(current, _now())
            )
            report = await _render_scheduled_occurrence(
                schedule, principal=principal, settings=settings, storage=storage, renderer=renderer
            )
            if schedule.recipients:
                # Recipients may be external executives without a Cynux session. A regular
                # report URL would always return 401 for them, so each dispatch receives a
                # short-lived opaque grant that can be revoked independently of the report.
                from app.services import report_sharing

                async with session.begin_nested():
                    issued = await report_sharing.issue_share_link(
                        session,
                        principal,
                        report_id=report.id,
                        expires_at=_now() + dt.timedelta(days=7),
                    )
                    link = report_schedule_share_url(settings.public_base_url, issued.token)
                    notifications = await dispatch(
                        session,
                        principal,
                        event=NotificationEvent.ASSESSMENT_COMPLETED,
                        content=NotificationContent(
                            subject=f"Scheduled Cynux report: {report.title}",
                            body="A scheduled report is ready for download.",
                            link=link,
                            html=f"<p>A scheduled report is ready.</p><p><a href=\"{escape(link)}\">Download report</a></p>",
                        ),
                        settings=settings,
                        resource_type="report",
                        resource_id=str(report.id),
                        channels=(NotificationChannel.EMAIL, NotificationChannel.WEBHOOK),
                        extra_emails=schedule.recipients,
                    )
                    for notification in notifications:
                        if notification.channel not in {
                            NotificationChannel.EMAIL.value,
                            NotificationChannel.WEBHOOK.value,
                        }:
                            continue
                        await session.execute(
                            insert(ReportDistribution)
                            .values(
                                id=uuid.uuid4(),
                                organization_id=schedule.organization_id,
                                report_id=report.id,
                                schedule_id=schedule.id,
                                channel=notification.channel,
                                destination=notification.recipient,
                                status="pending",
                                attempts=0,
                                created_at=_now(),
                                updated_at=_now(),
                            )
                            .on_conflict_do_nothing(
                                constraint="unique_report_distribution_destination"
                            )
                        )
            schedule.last_report_id = report.id
            schedule.last_run_at = _now()
            schedule.next_run_at = next_cron_time(
                schedule.cron_expression, schedule.timezone, max(current, _now())
            )
            count += 1
        except PermissionDeniedError:
            schedule.is_enabled = False
        except (CynuxError, TimeoutError) as exc:
            # Renderer/storage/provider outages are operationally retryable.  Do not
            # silently disable a tenant's weekly board report because one delivery
            # pulse happened during an outage; leaving its cursor due makes the worker
            # retry on the next bounded maintenance pass.
            log.warning(
                "report_schedule.render_retry_scheduled",
                schedule_id=str(schedule.id),
                error_code=exc.code if isinstance(exc, CynuxError) else "report_timeout",
            )
        except ValueError:
            # Invalid cron/timezone/render input cannot recover without an operator
            # fixing the schedule definition.
            schedule.is_enabled = False
        await session.commit()
    return count


async def _render_scheduled_occurrence(schedule, *, principal, settings, storage, renderer) -> Report:
    """Render under a separate session while the caller holds the schedule lock."""
    occurrence = json.dumps(
        [schedule.next_run_at.astimezone(dt.UTC).isoformat(), schedule.format, schedule.audience, schedule.title],
        separators=(",", ":"),
    )
    report_id = uuid.uuid5(schedule.id, occurrence)
    async with session_scope(settings) as rendering_session:
        assessment = (
            await rendering_session.execute(
                tenant_select(Assessment, principal.organization_id)
                .where(Assessment.id == schedule.assessment_id)
            )
        ).scalar_one()
        report = await rendering_session.get(Report, report_id)
        if report is not None:
            if (
                report.organization_id != principal.organization_id
                or report.assessment_id != assessment.id
                or report.audience != schedule.audience
            ):
                raise ValueError("scheduled report identity mismatch")
            if report.status_enum is ReportStatus.READY:
                return report
            # Owning the schedule lock proves no other schedule worker is still
            # rendering this occurrence; pending/generating rows are crash residue.
            if report.status_enum in {ReportStatus.PENDING, ReportStatus.GENERATING}:
                await fail_generation(rendering_session, report, reason="Scheduled render interrupted; retrying.")
        else:
            report = await create_report(
                rendering_session, principal, assessment,
                title=(schedule.title or f"Security assessment {assessment.reference}").strip(),
                audience=schedule.audience, fmt=ReportFormat(schedule.format), report_id=report_id,
                template_id=schedule.template_id,
            )
        # Keep the scheduler's claim bounded even if a provider never returns.
        # A timed-out row is recovered by the next owner of this occurrence.
        async with asyncio.timeout(600):
            return await renderer(
                rendering_session, assessment,
                fmt=ReportFormat(schedule.format), audience=schedule.audience,
                storage=storage, settings=settings, principal=principal, title=schedule.title, report=report,
            )


async def create_report(
    session: AsyncSession,
    principal: Principal,
    assessment: Assessment,
    *,
    title: str,
    audience: str,
    fmt: ReportFormat,
    requested_by_id: uuid.UUID | None = None,
    report_id: uuid.UUID | None = None,
    template_id: uuid.UUID | None = None,
) -> Report:
    """Stage a ``pending`` report row for ``assessment`` and return it.

    Requires ``report:generate``.  The row's tenant is stamped from the principal by the
    repository, not copied from the assessment, so a caller cannot file a report under an
    organization it does not belong to even with a mismatched assessment in hand.
    """
    principal.require(Permission.REPORT_GENERATE)
    repo: TenantRepository[Report] = TenantRepository(session, Report, principal.organization_id)
    template = None
    if template_id is not None:
        template = await session.scalar(
            tenant_select(ReportTemplate, principal.organization_id).where(
                ReportTemplate.id == template_id
            )
        )
        if template is None:
            from app.core.errors import ResourceNotFoundError

            raise ResourceNotFoundError("Report template not found")
    report = Report(
        id=report_id or uuid.uuid4(),
        assessment_id=assessment.id,
        requested_by_id=requested_by_id if requested_by_id is not None else principal.user_id,
        title=title[:_MAX_TITLE],
        format=fmt.value,
        audience=audience,
        status=ReportStatus.PENDING.value,
        template_id=template.id if template else None,
        template_version=template.version if template else None,
        template_snapshot=dict(template.definition) if template else {},
    )
    repo.add(report)
    await session.flush()
    log.info(
        "report.created",
        report_id=str(report.id),
        assessment_id=str(assessment.id),
        format=fmt.value,
        audience=audience,
        **principal.to_log_fields(),
    )
    return report


async def reconcile_report_distributions(
    session: AsyncSession, *, limit: int = 100
) -> int:
    """Mirror durable notification outcomes into report-specific delivery history."""
    rows = list(
        (
            await session.scalars(
                select(ReportDistribution)
                .where(ReportDistribution.status.in_(("pending", "failed")))
                .order_by(ReportDistribution.created_at)
                .limit(max(1, min(limit, 500)))
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    changed = 0
    for row in rows:
        notification = await session.scalar(
            select(Notification)
            .where(
                Notification.organization_id == row.organization_id,
                Notification.resource_type == "report",
                Notification.resource_id == str(row.report_id),
                Notification.channel == row.channel,
                Notification.recipient == row.destination,
            )
            .order_by(Notification.created_at.desc())
            .limit(1)
        )
        if notification is None:
            continue
        next_status = (
            "sent" if notification.status == "sent"
            else "failed" if notification.status == "failed"
            else "pending"
        )
        if (
            row.status != next_status
            or row.attempts != notification.attempts
            or row.next_retry_at != notification.next_retry_at
        ):
            row.status = next_status
            row.attempts = notification.attempts
            row.next_retry_at = notification.next_retry_at
            row.sent_at = notification.sent_at
            row.last_error = notification.last_error[:1000] if notification.last_error else None
            changed += 1
    return changed


async def begin_generation(session: AsyncSession, report: Report) -> None:
    """Move a report to ``generating``. Clears any prior failure so a retry is clean."""
    report.status = ReportStatus.GENERATING.value
    report.failure_reason = None
    await session.flush()
    log.info("report.generating", report_id=str(report.id))


async def complete_generation(
    session: AsyncSession,
    report: Report,
    *,
    stored: StoredObject,
    executive_summary: str | None,
    summary_ai_generated: bool,
    ai_model: str | None,
    content_digest: dict[str, object],
    degradations: list[dict[str, object]],
) -> None:
    """Record a successful render: the stored artifact, the snapshot and the summary."""
    report.status = ReportStatus.READY.value
    report.storage_key = stored.storage_key
    report.size_bytes = stored.size_bytes
    report.sha256 = stored.sha256
    report.executive_summary = executive_summary
    report.summary_ai_generated = summary_ai_generated
    report.ai_model = ai_model
    report.content_digest = content_digest
    report.degradations = degradations
    report.generated_at = _now()
    report.failure_reason = None
    await session.flush()
    log.info(
        "report.ready",
        report_id=str(report.id),
        size_bytes=stored.size_bytes,
        storage_key=stored.storage_key,
    )


async def fail_generation(session: AsyncSession, report: Report, *, reason: str) -> None:
    """Record a failed render. ``reason`` must already be user-safe (SEC-002)."""
    report.status = ReportStatus.FAILED.value
    report.failure_reason = (reason or "Report generation failed.")[:_MAX_FAILURE_REASON]
    await session.flush()
    log.warning("report.failed", report_id=str(report.id), reason=report.failure_reason)


async def get_report(session: AsyncSession, principal: Principal, report_id: uuid.UUID) -> Report:
    """One report, tenant-scoped. Requires ``report:read``."""
    principal.require(Permission.REPORT_READ)
    repo: TenantRepository[Report] = TenantRepository(session, Report, principal.organization_id)
    return await repo.get_or_404(report_id)


async def list_reports(
    session: AsyncSession,
    principal: Principal,
    assessment_id: uuid.UUID,
) -> Sequence[Report]:
    """Reports for one assessment, newest first. Requires ``report:read``."""
    principal.require(Permission.REPORT_READ)
    stmt = (
        tenant_select(Report, principal.organization_id)
        .where(Report.assessment_id == assessment_id)
        .order_by(Report.created_at.desc(), Report.id.desc())
    )
    return (await session.execute(stmt)).scalars().all()


async def list_recent_reports(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[Report], int]:
    """Return a tenant's latest generated artifacts across all assessments."""
    principal.require(Permission.REPORT_READ)
    bounded_limit = max(1, min(limit, 200))
    safe_offset = max(0, offset)
    base = tenant_select(Report, principal.organization_id)
    total = int((await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    rows = (
        await session.execute(
            base.order_by(Report.created_at.desc(), Report.id.desc())
            .limit(bounded_limit)
            .offset(safe_offset)
        )
    ).scalars().all()
    return rows, total


async def latest_report(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    organization_id: uuid.UUID,
    ready_only: bool = False,
    audience: str | None = None,
) -> Report | None:
    """The most recent report for an assessment, or ``None``.

    Takes no principal: the agent's report node and the ``force=false`` fast path call it
    to decide whether to reuse an existing render, and they scope by ``organization_id``
    directly.  ``ready_only`` restricts to a report that actually produced bytes.
    """
    stmt = tenant_select(Report, organization_id).where(Report.assessment_id == assessment_id)
    if ready_only:
        stmt = stmt.where(Report.status == ReportStatus.READY.value)
    if audience is not None:
        stmt = stmt.where(Report.audience == audience)
    stmt = stmt.order_by(Report.created_at.desc(), Report.id.desc()).limit(1)
    return (await session.execute(stmt)).scalars().first()


async def read_report_bytes(
    session: AsyncSession,
    principal: Principal,
    report_id: uuid.UUID,
    *,
    storage: ObjectStorage,
) -> tuple[Report, bytes]:
    """Fetch a ready report's bytes for streaming, recording the download (FR-032).

    Requires ``report:read``.  Refuses a report that is not ``ready`` -- there is nothing
    to stream, and a 409 tells the caller to wait rather than handing back an empty body
    that reads as a corrupt download.
    """
    report = await get_report(session, principal, report_id)
    if report.status_enum is not ReportStatus.READY or not report.storage_key:
        raise ConflictError(
            "report is not ready to download",
            user_message="This report is still being generated. Try again shortly.",
            context={"report_id": str(report.id), "status": report.status},
        )
    data = await storage.get_bytes(report.storage_key, organization_id=principal.organization_id)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.REPORT_DOWNLOAD,
        principal=principal,
        resource_type="report",
        resource_id=report.id,
        detail={
            "assessment_id": str(report.assessment_id),
            "format": report.format,
            "size_bytes": report.size_bytes,
        },
    )
    return report, data


def report_out(report: Report, *, download_url: str | None = None) -> ReportOut:
    """Project a report to its list/summary wire type."""
    out = ReportOut.model_validate(report)
    if download_url is not None:
        return out.model_copy(update={"download_url": download_url})
    return out


def report_detail_out(report: Report, *, download_url: str | None = None) -> ReportDetailOut:
    """Project a report to its detail wire type (adds digest, degradations, summary)."""
    out = ReportDetailOut.model_validate(report)
    if download_url is not None:
        return out.model_copy(update={"download_url": download_url})
    return out


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "begin_generation",
    "complete_generation",
    "create_report_schedule",
    "create_report",
    "fail_generation",
    "get_report",
    "latest_report",
    "list_recent_reports",
    "list_reports",
    "read_report_bytes",
    "reconcile_report_distributions",
    "run_due_report_schedules",
    "report_detail_out",
    "report_schedule_download_url",
    "report_schedule_share_url",
    "report_out",
]
