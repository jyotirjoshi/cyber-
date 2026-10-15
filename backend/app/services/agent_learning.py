"""Evidence-backed memory proposals; only human review promotes facts into prompts."""
from __future__ import annotations

import uuid

from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, PermissionDeniedError, ResourceNotFoundError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.agent import AgentMemory, AgentRun
from app.db.models.agent_definition import AgentDefinitionVersion
from app.db.models.knowledge import (
    AgentMemoryCandidate,
    KnowledgeChunk,
    KnowledgeCollection,
    KnowledgeSource,
)
from app.db.repository import tenant_select
from app.schemas.agent_learning import (
    MemoryCandidateApproveIn,
    MemoryCandidateCreateIn,
    MemoryCandidateRejectIn,
    MemoryEvidence,
)
from app.schemas.agent_memory import AgentMemoryUpsertIn
from app.services import audit as audit_service
from app.services.context import Principal


def _reviewer(principal: Principal) -> None:
    principal.require(Permission.ORG_MANAGE)
    if principal.actor_type != "user" or principal.user_id is None:
        raise PermissionDeniedError(user_message="A signed-in organization manager must review learning proposals.")


async def _validate_evidence(session: AsyncSession, principal: Principal, evidence: list[MemoryEvidence]) -> None:
    for item in evidence:
        if item.kind == "run":
            query = select(AgentRun.id).where(AgentRun.organization_id == principal.organization_id,
                AgentRun.id == item.id, AgentRun.status == "completed")
        else:
            query = select(KnowledgeChunk.id).join(KnowledgeSource, and_(
                KnowledgeSource.current_version_id == KnowledgeChunk.source_version_id,
                KnowledgeSource.organization_id == KnowledgeChunk.organization_id,
            )).join(KnowledgeCollection, and_(
                KnowledgeCollection.id == KnowledgeSource.collection_id,
                KnowledgeCollection.organization_id == KnowledgeSource.organization_id,
            )).where(KnowledgeChunk.id == item.id, KnowledgeChunk.organization_id == principal.organization_id,
                KnowledgeSource.status == "ready", KnowledgeSource.tombstoned_at.is_(None),
                KnowledgeCollection.is_enabled.is_(True))
        if await session.scalar(query) is None:
            raise ResourceNotFoundError(user_message="The cited evidence is unavailable or not complete.")


async def propose_memory_candidate(session: AsyncSession, principal: Principal,
                                   payload: MemoryCandidateCreateIn) -> AgentMemoryCandidate:
    principal.require(Permission.AGENT_CHAT)
    await _validate_evidence(session, principal, payload.evidence)
    if payload.agent_version_id is not None:
        version = await session.scalar(select(AgentDefinitionVersion.id).where(
            AgentDefinitionVersion.organization_id == principal.organization_id,
            AgentDefinitionVersion.id == payload.agent_version_id))
        if version is None:
            raise ResourceNotFoundError("agent version not found")
    # Avoid flooding the review inbox with repeated proposals for an unchanged fact.
    existing = await session.scalar(tenant_select(AgentMemoryCandidate, principal.organization_id).where(
        AgentMemoryCandidate.key == payload.key, AgentMemoryCandidate.content == payload.content,
        AgentMemoryCandidate.status == "pending",
        (AgentMemoryCandidate.expires_at.is_(None) | (AgentMemoryCandidate.expires_at > utcnow())),
    ).order_by(AgentMemoryCandidate.created_at.desc()).limit(1))
    if existing is not None:
        return existing
    row = AgentMemoryCandidate(id=uuid.uuid4(), organization_id=principal.organization_id,
        proposed_by_id=principal.user_id, status="pending",
        **payload.model_dump(exclude={"evidence"}),
        evidence=[item.model_dump(mode="json") for item in payload.evidence])
    session.add(row)
    await session.flush()
    await audit_service.record(session, action="agent.memory.propose", principal=principal,
        resource_type="agent_memory_candidate", resource_id=row.id,
        detail={"key": row.key, "evidence_count": len(row.evidence)})
    return row


async def _pending(session: AsyncSession, principal: Principal, candidate_id: uuid.UUID) -> AgentMemoryCandidate:
    row = await session.scalar(tenant_select(AgentMemoryCandidate, principal.organization_id).where(
        AgentMemoryCandidate.id == candidate_id).with_for_update())
    if row is None:
        raise ResourceNotFoundError("memory candidate not found")
    if row.status != "pending":
        raise ConflictError(user_message="This proposal has already been reviewed.")
    if row.expires_at is not None and row.expires_at <= utcnow():
        raise ConflictError(user_message="This proposal has expired. Submit new evidence before approving it.")
    return row


async def approve_memory_candidate(session: AsyncSession, principal: Principal,
                                   candidate_id: uuid.UUID, payload: MemoryCandidateApproveIn) -> AgentMemoryCandidate:
    _reviewer(principal)
    row = await _pending(session, principal, candidate_id)
    # Recheck at review time: a deleted document must not become enduring truth.
    await _validate_evidence(session, principal, [MemoryEvidence.model_validate(item) for item in row.evidence])
    expiry = payload.expires_at if "expires_at" in payload.model_fields_set else row.expires_at
    memory = AgentMemoryUpsertIn(key=row.key, category=row.category,
        content=payload.content if payload.content is not None else row.content, expires_at=expiry)
    # Unlike a blind upsert, approval cannot replace a fact another reviewer or
    # administrator just curated. The unique tenant/key constraint resolves races.
    memory_id = await session.scalar(insert(AgentMemory).values(id=uuid.uuid4(),
        organization_id=principal.organization_id, created_by_id=principal.user_id,
        source="approved_agent", is_active=True, **memory.model_dump())
        .on_conflict_do_nothing(constraint="unique_agent_memory_key").returning(AgentMemory.id))
    if memory_id is None:
        raise ConflictError(user_message="This memory key already exists. Review the existing memory instead of overwriting it.")
    row.status, row.approved_memory_id = "approved", memory_id
    row.reviewed_by_id, row.decision_rationale = principal.user_id, payload.rationale
    await session.flush()
    await audit_service.record(session, action="agent.memory.approve", principal=principal,
        resource_type="agent_memory_candidate", resource_id=row.id,
        detail={"memory_id": str(memory_id), "edited": payload.content is not None})
    return row


async def reject_memory_candidate(session: AsyncSession, principal: Principal,
                                  candidate_id: uuid.UUID, payload: MemoryCandidateRejectIn) -> AgentMemoryCandidate:
    _reviewer(principal)
    row = await _pending(session, principal, candidate_id)
    row.status, row.reviewed_by_id, row.decision_rationale = "rejected", principal.user_id, payload.rationale
    await session.flush()
    await audit_service.record(session, action="agent.memory.reject", principal=principal,
        resource_type="agent_memory_candidate", resource_id=row.id, detail={"key": row.key})
    return row
