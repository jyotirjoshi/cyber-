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

from app.api.deps import DbSession, GatewayDep, PrincipalDep, SettingsDep, StorageDep
from app.core.config import Settings
from app.db.enums import ReportFormat, ReportStatus
from app.db.models.report import Report
from app.reporting.generate import generate
from app.schemas.report import ReportDetailOut, ReportGenerateIn, ReportOut
from app.services import assessment as assessment_service
from app.services import report as report_service

router = APIRouter(tags=["reports"])


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

    if not payload.force:
        existing = await report_service.latest_report(
            session,
            assessment_id,
            organization_id=principal.organization_id,
            ready_only=True,
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
