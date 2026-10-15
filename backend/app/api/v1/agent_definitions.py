"""Custom agent administration and explicit organizational-learning review."""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter
from sqlalchemy import and_, or_

from app.agent.tools.policy import OrganizationToolPolicy, resolve_effective_tools
from app.agent.tools.registry import default_tool_registry
from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.core.errors import ResourceNotFoundError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.agent_definition import (
    AgentDefinition,
    AgentDefinitionVersion,
    AgentVersionCollection,
    AgentVersionTool,
)
from app.db.models.knowledge import AgentMemoryCandidate
from app.db.repository import tenant_select
from app.schemas.agent_definition import (
    AgentDefinitionCreateIn,
    AgentDefinitionOut,
    AgentDefinitionVersionOut,
    AgentPolicyPreviewOut,
    AgentToolOut,
    AgentVersionConfigurationIn,
    AgentVersionCreateIn,
    EffectiveAgentToolOut,
)
from app.schemas.agent_learning import (
    MemoryCandidateApproveIn,
    MemoryCandidateCreateIn,
    MemoryCandidateOut,
    MemoryCandidateRejectIn,
)
from app.services import agent_definition as definitions
from app.services import agent_learning as learning

router = APIRouter(prefix="/agents", tags=["custom-agents"])


@router.get("/tools", response_model=list[AgentToolOut])
async def tool_catalog(principal: PrincipalDep):
    principal.require(Permission.AGENT_CHAT)
    return [AgentToolOut(name=tool.name, version=tool.version, permission=tool.permission.value,
        side_effect=tool.side_effect, approval=tool.approval, timeout_seconds=tool.timeout_seconds,
        permitted=principal.has(tool.permission), input_schema=tool.input_model.model_json_schema())
        for tool in sorted(default_tool_registry().specs.values(), key=lambda value: value.name)]


@router.post("/policy-preview", response_model=AgentPolicyPreviewOut)
async def preview_policy(payload: AgentVersionConfigurationIn, principal: PrincipalDep):
    principal.require(Permission.AGENT_CHAT)
    version = SimpleNamespace(**payload.model_dump(), tools=[SimpleNamespace(tool_name=name,
        tool_version=1, approval_mode="policy", timeout_seconds=60, per_run_call_limit=5)
        for name in payload.tool_names])
    policy = resolve_effective_tools(principal, version, OrganizationToolPolicy())
    return AgentPolicyPreviewOut(tools=[EffectiveAgentToolOut(name=name, approval=value.approval,
        timeout_seconds=value.timeout_seconds, per_run_call_limit=value.per_run_call_limit)
        for name, value in policy.tools.items()], rejected=dict(policy.rejected), max_tool_calls=policy.max_tool_calls)


@router.get("/definitions", response_model=list[AgentDefinitionOut])
async def list_definitions(principal: PrincipalDep, session: DbSession, page: PaginationDep):
    principal.require(Permission.AGENT_CHAT)
    return list((await session.scalars(tenant_select(AgentDefinition, principal.organization_id)
        .order_by(AgentDefinition.name, AgentDefinition.id).limit(page.limit).offset(page.offset))).all())


@router.post("/definitions", response_model=AgentDefinitionOut, status_code=201)
async def create_definition(payload: AgentDefinitionCreateIn, principal: PrincipalDep, session: DbSession):
    row = await definitions.create_agent(session, principal, payload)
    await session.commit()
    return row


@router.get("/definitions/{agent_id}", response_model=AgentDefinitionOut)
async def get_definition(agent_id: uuid.UUID, principal: PrincipalDep, session: DbSession):
    principal.require(Permission.AGENT_CHAT)
    row = await session.scalar(tenant_select(AgentDefinition, principal.organization_id)
        .where(AgentDefinition.id == agent_id))
    if row is None:
        raise ResourceNotFoundError("agent definition not found")
    return row


async def _project_versions(session, principal, rows):
    if not rows:
        return []
    ids = [row.id for row in rows]
    tools = list((await session.scalars(tenant_select(AgentVersionTool, principal.organization_id)
        .where(AgentVersionTool.agent_version_id.in_(ids)).order_by(AgentVersionTool.tool_name))).all())
    collections = list((await session.scalars(tenant_select(AgentVersionCollection, principal.organization_id)
        .where(AgentVersionCollection.agent_version_id.in_(ids)).order_by(AgentVersionCollection.collection_id))).all())
    return [AgentDefinitionVersionOut.model_validate(row).model_copy(update={
        "tool_names": [item.tool_name for item in tools if item.agent_version_id == row.id],
        "collection_ids": [item.collection_id for item in collections if item.agent_version_id == row.id],
    }) for row in rows]


@router.get("/definitions/{agent_id}/versions", response_model=list[AgentDefinitionVersionOut])
async def versions(agent_id: uuid.UUID, principal: PrincipalDep, session: DbSession, page: PaginationDep):
    await get_definition(agent_id, principal, session)
    rows = list((await session.scalars(tenant_select(AgentDefinitionVersion, principal.organization_id)
        .where(AgentDefinitionVersion.agent_definition_id == agent_id)
        .order_by(AgentDefinitionVersion.version.desc()).limit(page.limit).offset(page.offset))).all())
    return await _project_versions(session, principal, rows)


@router.post("/definitions/{agent_id}/versions", response_model=AgentDefinitionVersionOut, status_code=201)
async def create_version(agent_id: uuid.UUID, payload: AgentVersionCreateIn, principal: PrincipalDep, session: DbSession):
    row = await definitions.create_agent_version(session, principal, agent_id, payload)
    await session.commit()
    return (await _project_versions(session, principal, [row]))[0]


@router.post("/definitions/{agent_id}/disable", response_model=AgentDefinitionOut)
async def disable(agent_id: uuid.UUID, principal: PrincipalDep, session: DbSession):
    row = await definitions.disable_agent(session, principal, agent_id)
    await session.commit()
    return row


@router.get("/memory-candidates", response_model=list[MemoryCandidateOut])
async def candidates(principal: PrincipalDep, session: DbSession, page: PaginationDep,
                     status: Literal["pending", "approved", "rejected", "expired"] = "pending"):
    principal.require(Permission.ORG_MANAGE)
    now = utcnow()
    expired = and_(AgentMemoryCandidate.status == "pending", AgentMemoryCandidate.expires_at <= now)
    condition = or_(AgentMemoryCandidate.status == "expired", expired) if status == "expired" else AgentMemoryCandidate.status == status
    query = tenant_select(AgentMemoryCandidate, principal.organization_id).where(condition)
    if status == "pending":
        query = query.where(or_(AgentMemoryCandidate.expires_at.is_(None), AgentMemoryCandidate.expires_at > now))
    rows = list((await session.scalars(query.order_by(AgentMemoryCandidate.created_at.desc(), AgentMemoryCandidate.id)
        .limit(page.limit).offset(page.offset))).all())
    # Expiry is computed, not a write hidden in a GET. The decision service enforces it too.
    return [MemoryCandidateOut.model_validate(row).model_copy(update={"status": "expired"})
        if row.status == "pending" and row.expires_at is not None and row.expires_at <= now
        else MemoryCandidateOut.model_validate(row) for row in rows]


@router.post("/memory-candidates", response_model=MemoryCandidateOut, status_code=201)
async def propose_candidate(payload: MemoryCandidateCreateIn, principal: PrincipalDep, session: DbSession):
    row = await learning.propose_memory_candidate(session, principal, payload)
    await session.commit()
    return row


@router.post("/memory-candidates/{candidate_id}/approve", response_model=MemoryCandidateOut)
async def approve_candidate(candidate_id: uuid.UUID, payload: MemoryCandidateApproveIn, principal: PrincipalDep, session: DbSession):
    row = await learning.approve_memory_candidate(session, principal, candidate_id, payload)
    await session.commit()
    return row


@router.post("/memory-candidates/{candidate_id}/reject", response_model=MemoryCandidateOut)
async def reject_candidate(candidate_id: uuid.UUID, payload: MemoryCandidateRejectIn, principal: PrincipalDep, session: DbSession):
    row = await learning.reject_memory_candidate(session, principal, candidate_id, payload)
    await session.commit()
    return row
