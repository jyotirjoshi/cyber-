"""Report endpoints (FR-030, FR-032, FR-024).

WHY generation is inline and downloads stream through the API: :func:`app.reporting.generate.
generate` owns the whole pipeline -- it creates the row, commits ``pending`` and ``generating``
so a polling UI can watch (FR-030), builds the context, guards the AI summary against invented
CVEs/CVSS (FR-024), renders, stores the bytes and commits ``ready`` -- so the endpoint simply
awaits it. Downloads go through :func:`app.services.report.read_report_bytes` rather than a
presigned link because every download is an audited event (FR-032); the route commits that audit
row before returning the bytes.

The ``download_url`` on the wire is therefore this API's own audited download route, not an
object-storage link (that pattern is reserved for scanner artifacts, which can be far larger and
carry no audit obligation).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from app.api.deps import DbSession, GatewayDep, PaginationDep, PrincipalDep, SettingsDep, StorageDep
from app.core.config import Settings
from app.db.enums import Permission, ReportFormat, ReportStatus
from app.db.models.report import Report
from app.reporting.generate import generate
from app.schemas.report import (
    ReportDetailOut,
    ReportGenerateIn,
    ReportOut,
    ReportScheduleCreateIn,
    ReportScheduleOut,
    ReportShareCreateIn,
    ReportShareIssuedOut,
    ReportShareLinkOut,
    ReportTemplateCreateIn,
    ReportTemplateOut,
)
from app.schemas.organization import ClientOrganizationPortfolioOut
from app.schemas.common import Page
from app.services import assessment as assessment_service
from app.services import report as report_service
from app.services import report_sharing
from app.services import report_template as report_template_service
from app.services.organization import list_client_portfolio
from app.services.audit import AuditAction, record

router = APIRouter(tags=["reports"])


@router.get("/report-templates", response_model=list[ReportTemplateOut])
async def list_report_templates(
    principal: PrincipalDep, session: DbSession
) -> list[ReportTemplateOut]:
    rows = await report_template_service.list_templates(session, principal)
    return [ReportTemplateOut.model_validate(row) for row in rows]


@router.post("/report-templates", response_model=ReportTemplateOut, status_code=status.HTTP_201_CREATED)
async def create_report_template(
    payload: ReportTemplateCreateIn, principal: PrincipalDep, session: DbSession
) -> ReportTemplateOut:
    row = await report_template_service.create_template(session, principal, payload)
    await session.commit()
    return ReportTemplateOut.model_validate(row)


@router.get("/reports/portfolio", response_model=list[ClientOrganizationPortfolioOut])
async def get_report_portfolio(
    principal: PrincipalDep, session: DbSession
) -> list[ClientOrganizationPortfolioOut]:
    """Return aggregate-only direct-client posture; raw child findings never cross tenants."""
    return await list_client_portfolio(session, principal)


@router.get("/reports", response_model=Page[ReportOut])
async def list_recent_reports(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    settings: SettingsDep,
) -> Page[ReportOut]:
    """List the organization's latest report artifacts across all assessments."""
    rows, total = await report_service.list_recent_reports(
        session, principal, limit=pagination.limit, offset=pagination.offset
    )
    items = [report_service.report_out(row, download_url=_download_url(settings, row)) for row in rows]
    return Page.build(items, total=total, limit=pagination.limit, offset=pagination.offset)


@router.get("/report-schedules", response_model=list[ReportScheduleOut])
async def list_report_schedules(principal: PrincipalDep, session: DbSession) -> list[ReportScheduleOut]:
    from app.db.models.report import ReportSchedule
    from app.db.repository import tenant_select

    principal.require(Permission.REPORT_READ)
    schedules = list(
        (await session.scalars(tenant_select(ReportSchedule, principal.organization_id))).all()
    )
    return [ReportScheduleOut.model_validate(schedule) for schedule in schedules]


@router.post("/report-schedules", response_model=ReportScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_report_schedule(
    payload: ReportScheduleCreateIn, principal: PrincipalDep, session: DbSession
) -> ReportScheduleOut:
    schedule = await report_service.create_report_schedule(session, principal, payload)
    await record(
        session,
        action=AuditAction.REPORT_SCHEDULE_CREATE,
        principal=principal,
        resource_type="report_schedule",
        resource_id=schedule.id,
        detail={"assessment_id": str(schedule.assessment_id), "cron_expression": schedule.cron_expression},
    )
    await session.commit()
    return ReportScheduleOut.model_validate(schedule)


@router.post("/reports/{report_id}/share-links", response_model=ReportShareIssuedOut, status_code=status.HTTP_201_CREATED)
async def create_report_share_link(
    report_id: uuid.UUID, payload: ReportShareCreateIn, principal: PrincipalDep, session: DbSession
) -> ReportShareIssuedOut:
    await report_service.get_report(session, principal, report_id)
    issued = await report_sharing.issue_share_link(
        session, principal, report_id=report_id, expires_at=payload.expires_at
    )
    await session.commit()
    return ReportShareIssuedOut(id=issued.link.id, token=issued.token, expires_at=issued.link.expires_at)


@router.get("/reports/{report_id}/share-links", response_model=list[ReportShareLinkOut])
async def list_report_share_links(
    report_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[ReportShareLinkOut]:
    await report_service.get_report(session, principal, report_id)
    return [
        ReportShareLinkOut.model_validate(link)
        for link in await report_sharing.list_share_links(session, principal, report_id=report_id)
    ]


@router.post("/reports/share-links/{share_link_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_report_share_link(
    share_link_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> Response:
    """Stop a leaked or no-longer-needed external report grant immediately."""
    link = await report_sharing.revoke_share_link(session, principal, share_link_id)
    await record(
        session,
        action=AuditAction.REPORT_SHARE_REVOKE,
        principal=principal,
        resource_type="report_share_link",
        resource_id=link.id,
        detail={"report_id": str(link.report_id)},
    )
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/shared/reports/{token}")
async def download_shared_report(token: str, session: DbSession, storage: StorageDep) -> Response:
    """Download a report through a revocable, expiring opaque external grant."""
    report, data = await report_sharing.read_shared_report_bytes(session, token, storage=storage)
    await session.commit()
    filename = _safe_filename(report.title, report.format)
    return Response(
        content=data,
        media_type=_media_type(report),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/report-schedules/{schedule_id}/pause", response_model=ReportScheduleOut)
async def pause_report_schedule(
    schedule_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> ReportScheduleOut:
    from app.core.errors import ResourceNotFoundError
    from app.db.models.report import ReportSchedule
    from app.db.repository import tenant_select

    principal.require(Permission.REPORT_GENERATE)
    schedule = (
        await session.execute(
            tenant_select(ReportSchedule, principal.organization_id)
            .where(ReportSchedule.id == schedule_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("Report schedule not found")
    schedule.is_enabled = False
    await record(
        session,
        action=AuditAction.REPORT_SCHEDULE_PAUSE,
        principal=principal,
        resource_type="report_schedule",
        resource_id=schedule.id,
        detail={"assessment_id": str(schedule.assessment_id)},
    )
    await session.commit()
    return ReportScheduleOut.model_validate(schedule)


@router.post("/report-schedules/{schedule_id}/resume", response_model=ReportScheduleOut)
async def resume_report_schedule(
    schedule_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> ReportScheduleOut:
    from app.core.errors import ResourceNotFoundError
    from app.db.models.report import ReportSchedule
    from app.db.repository import tenant_select
    from app.services.scheduling import next_cron_time

    principal.require(Permission.REPORT_GENERATE)
    schedule = (
        await session.execute(
            tenant_select(ReportSchedule, principal.organization_id)
            .where(ReportSchedule.id == schedule_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("Report schedule not found")
    from app.db.base import utcnow

    schedule.is_enabled = True
    schedule.next_run_at = next_cron_time(schedule.cron_expression, schedule.timezone, utcnow())
    await record(
        session,
        action=AuditAction.REPORT_SCHEDULE_RESUME,
        principal=principal,
        resource_type="report_schedule",
        resource_id=schedule.id,
        detail={"assessment_id": str(schedule.assessment_id)},
    )
    await session.commit()
    return ReportScheduleOut.model_validate(schedule)


def _download_url(settings: Settings, report: Report) -> str | None:
    """The audited API download route for a ready report, else ``None``.

    Not an object-storage presigned link: a report download is an FR-032 audit event, so it
    must pass back through the API. ``None`` until the report is ``ready`` -- there is nothing
    to download while it is still pending, generating or failed.
    """
    if report.status_enum is not ReportStatus.READY:
        return None
    return f"{settings.api_prefix}/reports/{report.id}/download"


def _media_type(report: Report) -> str:
    if report.format_enum is ReportFormat.PDF:
        return "application/pdf"
    if report.format_enum is ReportFormat.JSON:
        return "application/json"
    return "text/html; charset=utf-8"


def _safe_filename(title: str, ext: str) -> str:
    """A Content-Disposition-safe filename derived from the report title.

    Restricts to an alphanumeric-plus-separators set so an operator-authored title cannot inject
    a header line break or a quote into the response.
    """
    cleaned = "".join(char if (char.isalnum() or char in " -_.") else "_" for char in title).strip()
    return f"{(cleaned or 'report')[:120]}.{ext}"


@router.get("/assessments/{assessment_id}/reports", response_model=list[ReportOut])
async def list_reports(
    assessment_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> list[ReportOut]:
    """Every report generated for one assessment, newest first (FR-030).

    Tenant-scoped in the service: a report belonging to another organization is never returned,
    so a cross-tenant assessment id yields an empty list rather than a disclosure (SEC-003).
    """
    reports = await report_service.list_reports(session, principal, assessment_id)
    return [
        report_service.report_out(report, download_url=_download_url(settings, report))
        for report in reports
    ]


@router.post(
    "/assessments/{assessment_id}/reports",
    response_model=ReportDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def generate_report(
    assessment_id: uuid.UUID,
    payload: ReportGenerateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    storage: StorageDep,
    gateway: GatewayDep,
) -> ReportDetailOut:
    """Generate a report for an assessment (FR-030, FR-024), or return the latest ready one.

    Requires ``report:generate`` (enforced inside :func:`app.reporting.generate.generate`). Unless
    ``force`` is set, an existing ready report is returned rather than paying for a fresh render.
    Generation is inline: it can take several seconds (an LLM summary plus a PDF render), and it
    commits ``pending``/``generating``/``ready`` at each boundary, so a concurrent poll of this
    assessment's reports sees the progress even while this request is still in flight.
    """
    assessment = await assessment_service.get_assessment(session, principal, assessment_id)

    # A supplied title is an explicit request for a distinct deliverable. Reusing the latest
    # ready artifact in that case would return a differently titled report and make the UI's
    # title field appear to have been ignored.
    if not payload.force and payload.title is None:
        existing = await report_service.latest_report(
            session,
            assessment_id,
            organization_id=principal.organization_id,
            ready_only=True,
            audience=payload.audience,
        )
        if existing is not None:
            return report_service.report_detail_out(
                existing, download_url=_download_url(settings, existing)
            )

    report = await generate(
        session,
        assessment,
        fmt=payload.format,
        audience=payload.audience,
        storage=storage,
        settings=settings,
        principal=principal,
        gateway=gateway,
        title=payload.title,
        template_id=payload.template_id,
    )
    return report_service.report_detail_out(report, download_url=_download_url(settings, report))


@router.get("/reports/{report_id}", response_model=ReportDetailOut)
async def get_report(
    report_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> ReportDetailOut:
    """One report with its executive summary, content digest and degradation banner (FR-030)."""
    report = await report_service.get_report(session, principal, report_id)
    return report_service.report_detail_out(report, download_url=_download_url(settings, report))


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
) -> Response:
    """Stream a ready report's bytes (FR-032); records a download audit event.

    Refuses a report that is not ``ready`` with a 409 -- there are no bytes yet. The audit row
    the service stages is committed here before the bytes are returned, so a download that fails
    to reach the client is still one that was authorized and recorded.
    """
    report, data = await report_service.read_report_bytes(
        session, principal, report_id, storage=storage
    )
    await session.commit()
    filename = _safe_filename(report.title, report.format_enum.value)
    return Response(
        content=data,
        media_type=_media_type(report),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


__all__ = ["router"]
