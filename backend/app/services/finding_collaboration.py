"""Tenant-scoped collaboration attached to the canonical exposure record."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import Permission
from app.db.models.canonical import CanonicalFinding, FindingCollaborationComment
from app.db.repository import TenantRepository, tenant_select
from app.schemas.collaboration import FindingCollaborationCommentCreateIn
from app.services import audit as audit_service
from app.services.context import Principal


async def list_comments(
    session: AsyncSession, principal: Principal, finding_id: uuid.UUID
) -> list[FindingCollaborationComment]:
    """Return the internal team view of a finding's chronological discussion."""
    principal.require(Permission.FINDING_READ)
    await TenantRepository(session, CanonicalFinding, principal.organization_id).get_or_404(finding_id)
    return list(
        (
            await session.scalars(
                tenant_select(FindingCollaborationComment, principal.organization_id)
                .where(FindingCollaborationComment.canonical_finding_id == finding_id)
                .order_by(FindingCollaborationComment.created_at.asc(), FindingCollaborationComment.id.asc())
                .limit(500)
            )
        ).all()
    )


async def create_comment(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
    payload: FindingCollaborationCommentCreateIn,
) -> FindingCollaborationComment:
    """Add one auditable coordination entry without mutating the finding lifecycle."""
    principal.require(Permission.FINDING_REMEDIATE)
    finding = await TenantRepository(
        session, CanonicalFinding, principal.organization_id
    ).get_or_404(finding_id)
    comment = FindingCollaborationComment(
        organization_id=principal.organization_id,
        canonical_finding_id=finding.id,
        author_user_id=principal.user_id,
        kind=payload.kind,
        body=payload.body,
        evidence_reference=payload.evidence_reference,
        visible_to_client=payload.visible_to_client,
    )
    session.add(comment)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_COLLABORATION_COMMENT,
        principal=principal,
        resource_type="canonical_finding",
        resource_id=finding.id,
        detail={
            "comment_id": str(comment.id),
            "kind": comment.kind,
            "visible_to_client": comment.visible_to_client,
            "has_evidence_reference": comment.evidence_reference is not None,
        },
    )
    return comment


__all__ = ["create_comment", "list_comments"]
