"""Opaque, revocable external grants for ready report artifacts."""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from dataclasses import dataclass

from sqlalchemy import select

from app.core.errors import ResourceNotFoundError
from app.core.security import hash_password, verify_password
from app.db.enums import Permission, ReportStatus
from app.db.models.report import Report, ReportShareLink
from app.integrations.storage import ObjectStorage
from app.services import audit as audit_service
from app.services.context import Principal


@dataclass(frozen=True, slots=True)
class IssuedReportShareLink:
    link: ReportShareLink
    token: str


async def issue_share_link(
    session, principal: Principal, *, report_id: uuid.UUID, expires_at: dt.datetime
) -> IssuedReportShareLink:
    """Issue a time-bounded opaque grant and reveal its secret exactly once."""
    principal.require(Permission.REPORT_GENERATE)
    if expires_at.tzinfo is None or expires_at <= dt.datetime.now(dt.UTC):
        raise ValueError("share link expiry must be in the future")
    token = f"cynux_share_{secrets.token_urlsafe(32)}"
    link = ReportShareLink(
        organization_id=principal.organization_id,
        report_id=report_id,
        created_by_id=principal.user_id,
        token_prefix=token[:32],
        token_hash=hash_password(token),
        expires_at=expires_at,
    )
    session.add(link)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.REPORT_SHARE_CREATE,
        principal=principal,
        resource_type="report_share_link",
        resource_id=link.id,
        detail={"report_id": str(report_id), "expires_at": expires_at.isoformat()},
    )
    return IssuedReportShareLink(link=link, token=token)


async def resolve_share_link(session, token: str) -> ReportShareLink:
    """Return an active share grant without revealing why an invalid grant failed.

    The prefix narrows the database lookup only; Argon2 verification of the complete
    opaque secret remains the authorization decision.  The uniform 404 avoids making
    this unauthenticated endpoint a report or tenant enumeration oracle.
    """
    if not token.startswith("cynux_share_"):
        raise ResourceNotFoundError("report share link not found")

    link = (
        await session.execute(
            select(ReportShareLink).where(ReportShareLink.token_prefix == token[:32])
        )
    ).scalar_one_or_none()
    now = dt.datetime.now(dt.UTC)
    if (
        link is None
        or link.revoked_at is not None
        or link.expires_at <= now
        or not verify_password(token, link.token_hash)
    ):
        raise ResourceNotFoundError("report share link not found")
    return link


async def read_shared_report_bytes(
    session, token: str, *, storage: ObjectStorage
) -> tuple[Report, bytes]:
    """Read the one ready artifact authorized by an externally shared opaque grant."""
    link = await resolve_share_link(session, token)
    report = (
        await session.execute(
            select(Report).where(
                Report.id == link.report_id,
                Report.organization_id == link.organization_id,
            )
        )
    ).scalar_one_or_none()
    if report is None or report.status != ReportStatus.READY.value or not report.storage_key:
        raise ResourceNotFoundError("report share link not found")

    data = await storage.get_bytes(report.storage_key, organization_id=link.organization_id)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.REPORT_SHARE_DOWNLOAD,
        resource_type="report_share_link",
        resource_id=link.id,
        organization_id=link.organization_id,
        detail={"report_id": str(report.id), "assessment_id": str(report.assessment_id)},
    )
    return report, data


async def revoke_share_link(
    session, principal: Principal, share_link_id: uuid.UUID
) -> ReportShareLink:
    """Revoke a tenant-owned share link; repeated calls are safely idempotent."""
    principal.require(Permission.REPORT_GENERATE)
    link = (
        await session.execute(
            select(ReportShareLink)
            .where(
                ReportShareLink.id == share_link_id,
                ReportShareLink.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if link is None:
        raise ResourceNotFoundError("report share link not found")
    if link.revoked_at is None:
        link.revoked_at = dt.datetime.now(dt.UTC)
        await session.flush()
    return link


async def list_share_links(session, principal: Principal, *, report_id: uuid.UUID) -> list[ReportShareLink]:
    """List governance metadata only; opaque share secrets are never re-exposed."""
    principal.require(Permission.REPORT_READ)
    return list((await session.scalars(
        select(ReportShareLink)
        .where(ReportShareLink.organization_id == principal.organization_id, ReportShareLink.report_id == report_id)
        .order_by(ReportShareLink.created_at.desc(), ReportShareLink.id.desc())
        .limit(200)
    )).all())


__all__ = [
    "IssuedReportShareLink",
    "issue_share_link",
    "list_share_links",
    "read_shared_report_bytes",
    "revoke_share_link",
    "resolve_share_link",
]
