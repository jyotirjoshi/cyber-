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

import datetime as dt
import uuid
from collections.abc import Sequence

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError
from app.db.enums import Permission, ReportFormat, ReportStatus
from app.db.models.assessment import Assessment
from app.db.models.report import Report
from app.db.repository import TenantRepository, tenant_select
from app.integrations.storage import ObjectStorage, StoredObject
from app.schemas.report import ReportDetailOut, ReportOut
from app.services import audit as audit_service
from app.services.context import Principal

log = structlog.get_logger(__name__)

#: Column width of ``reports.title``; restated so a long AI/derived title is trimmed here
#: rather than raising ``StringDataRightTruncation`` at the caller's commit.
_MAX_TITLE = 300

#: Column width of ``reports.failure_reason`` is ``Text`` (unbounded), but an unbounded
#: reason is still a way to bloat the row from one failed render.
_MAX_FAILURE_REASON = 2000


async def create_report(
    session: AsyncSession,
    principal: Principal,
    assessment: Assessment,
    *,
    title: str,
    audience: str,
    fmt: ReportFormat,
    requested_by_id: uuid.UUID | None = None,
) -> Report:
    """Stage a ``pending`` report row for ``assessment`` and return it.

    Requires ``report:generate``.  The row's tenant is stamped from the principal by the
    repository, not copied from the assessment, so a caller cannot file a report under an
    organization it does not belong to even with a mismatched assessment in hand.
    """
    principal.require(Permission.REPORT_GENERATE)
    repo: TenantRepository[Report] = TenantRepository(session, Report, principal.organization_id)
    report = Report(
        assessment_id=assessment.id,
        requested_by_id=requested_by_id if requested_by_id is not None else principal.user_id,
        title=title[:_MAX_TITLE],
        format=fmt.value,
        audience=audience,
        status=ReportStatus.PENDING.value,
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


async def latest_report(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    organization_id: uuid.UUID,
    ready_only: bool = False,
) -> Report | None:
    """The most recent report for an assessment, or ``None``.

    Takes no principal: the agent's report node and the ``force=false`` fast path call it
    to decide whether to reuse an existing render, and they scope by ``organization_id``
    directly.  ``ready_only`` restricts to a report that actually produced bytes.
    """
    stmt = tenant_select(Report, organization_id).where(Report.assessment_id == assessment_id)
    if ready_only:
        stmt = stmt.where(Report.status == ReportStatus.READY.value)
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
    "create_report",
    "fail_generation",
    "get_report",
    "latest_report",
    "list_reports",
    "read_report_bytes",
    "report_detail_out",
    "report_out",
]
