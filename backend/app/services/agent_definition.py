"""Tenant-safe creation and immutable versioning for configurable agents."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.agent_definition import (
    AgentDefinition,
    AgentDefinitionVersion,
    AgentVersionCollection,
    AgentVersionTool,
)
from app.db.models.knowledge import KnowledgeCollection
from app.db.repository import tenant_select
from app.schemas.agent_definition import (
    AgentDefinitionCreateIn,
    AgentVersionConfigurationIn,
    AgentVersionCreateIn,
)
from app.services import audit as audit_service
from app.services.context import Principal


def normalize_agent_configuration(payload: AgentVersionConfigurationIn) -> dict[str, Any]:
    """Return the stable persisted subset used by both rows and configuration digests."""
    return {
        "role": payload.role.strip(),
        "instructions": payload.instructions.strip(),
        "provider": payload.provider,
        "model": payload.model.strip(),
        "autonomy_mode": payload.autonomy_mode,
        "temperature": payload.temperature,
        "max_output_tokens": payload.max_output_tokens,
        "max_parallel_tasks": payload.max_parallel_tasks,
        "max_runtime_seconds": payload.max_runtime_seconds,
        "max_tool_calls": payload.max_tool_calls,
        "max_input_tokens": payload.max_input_tokens,
        "max_estimated_spend_micros": payload.max_estimated_spend_micros,
        "scope_policy": payload.scope_policy,
        "retrieval_policy": payload.retrieval_policy,
        "tool_names": sorted(payload.tool_names),
        "collection_ids": sorted(str(value) for value in payload.collection_ids),
    }


def canonical_digest(configuration: dict[str, Any]) -> str:
    encoded = json.dumps(
        configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _version_columns(configuration: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in configuration.items()
        if key not in {"tool_names", "collection_ids"}
    }


async def _validate_collection_links(
    session: AsyncSession, principal: Principal, collection_ids: list[uuid.UUID]
) -> None:
    if not collection_ids:
        return
    statement = select(KnowledgeCollection.id).where(
        KnowledgeCollection.organization_id == principal.organization_id,
        KnowledgeCollection.id.in_(collection_ids),
        KnowledgeCollection.is_enabled.is_(True),
    )
    found = set((await session.execute(statement)).scalars().all())
    if found != set(collection_ids):
        raise ResourceNotFoundError("one or more knowledge collections were not found")


async def locked_tenant_agent(
    session: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID
) -> AgentDefinition:
    statement = (
        tenant_select(AgentDefinition, organization_id)
        .where(AgentDefinition.id == agent_id)
        .with_for_update()
    )
    agent = (await session.execute(statement)).scalar_one_or_none()
    if agent is None:
        raise ResourceNotFoundError("agent definition not found")
    return agent


async def _persist_version(
    session: AsyncSession,
    principal: Principal,
    agent: AgentDefinition,
    payload: AgentVersionConfigurationIn,
) -> AgentDefinitionVersion:
    await _validate_collection_links(session, principal, payload.collection_ids)
    configuration = normalize_agent_configuration(payload)
    version = AgentDefinitionVersion(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        agent_definition_id=agent.id,
        version=agent.version_count + 1,
        configuration_digest=canonical_digest(configuration),
        created_by_id=principal.user_id,
        **_version_columns(configuration),
    )
    session.add(version)
    await session.flush()
    for tool_name in configuration["tool_names"]:
        session.add(
            AgentVersionTool(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                agent_version_id=version.id,
                tool_name=tool_name,
                tool_version=1,
                approval_mode="policy",
            )
        )
    for collection_id in payload.collection_ids:
        session.add(
            AgentVersionCollection(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                agent_version_id=version.id,
                collection_id=collection_id,
            )
        )
    agent.active_version_id = version.id
    agent.version_count = version.version
    return version


async def create_agent(
    session: AsyncSession, principal: Principal, payload: AgentDefinitionCreateIn
) -> AgentDefinition:
    principal.require(Permission.ORG_MANAGE)
    name = payload.name.strip()
    duplicate = (
        await session.execute(
            tenant_select(AgentDefinition, principal.organization_id).where(
                func.lower(AgentDefinition.name) == name.casefold()
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise ConflictError("an agent definition with this name already exists")
    await _validate_collection_links(session, principal, payload.collection_ids)
    agent = AgentDefinition(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        name=name,
        description=payload.description,
        avatar_reference=payload.avatar_reference,
        is_enabled=True,
        version_count=0,
        created_by_id=principal.user_id,
    )
    session.add(agent)
    await session.flush()
    version = await _persist_version(session, principal, agent, payload)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AGENT_DEFINITION_CREATE,
        principal=principal,
        resource_type="agent_definition",
        resource_id=agent.id,
        detail={"version_id": str(version.id), "name": agent.name},
    )
    return agent


async def create_agent_version(
    session: AsyncSession,
    principal: Principal,
    agent_id: uuid.UUID,
    payload: AgentVersionCreateIn,
) -> AgentDefinitionVersion:
    principal.require(Permission.ORG_MANAGE)
    agent = await locked_tenant_agent(session, principal.organization_id, agent_id)
    if not agent.is_enabled:
        raise ConflictError("disabled agent definitions cannot be edited")
    if agent.active_version_id != payload.expected_active_version_id:
        raise ConflictError("stale active agent version")
    version = await _persist_version(session, principal, agent, payload)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AGENT_DEFINITION_VERSION_CREATE,
        principal=principal,
        resource_type="agent_definition",
        resource_id=agent.id,
        detail={"version": version.version, "version_id": str(version.id)},
    )
    return version


async def disable_agent(
    session: AsyncSession, principal: Principal, agent_id: uuid.UUID
) -> AgentDefinition:
    principal.require(Permission.ORG_MANAGE)
    agent = await locked_tenant_agent(session, principal.organization_id, agent_id)
    agent.is_enabled = False
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AGENT_DEFINITION_DISABLE,
        principal=principal,
        resource_type="agent_definition",
        resource_id=agent.id,
        detail={"active_version_id": str(agent.active_version_id)},
    )
    return agent


async def get_effective_agent_version(
    session: AsyncSession, principal: Principal, agent_id: uuid.UUID
) -> AgentDefinitionVersion:
    principal.require(Permission.AGENT_CHAT)
    agent = (
        await session.execute(
            tenant_select(AgentDefinition, principal.organization_id).where(
                AgentDefinition.id == agent_id,
                AgentDefinition.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if agent is None or agent.active_version_id is None:
        raise ResourceNotFoundError("agent definition not found")
    version = (
        await session.execute(
            tenant_select(AgentDefinitionVersion, principal.organization_id).where(
                AgentDefinitionVersion.id == agent.active_version_id,
                AgentDefinitionVersion.agent_definition_id == agent.id,
            )
        )
    ).scalar_one_or_none()
    if version is None:
        raise ResourceNotFoundError("active agent version not found")
    return version


__all__ = [
    "canonical_digest",
    "create_agent",
    "create_agent_version",
    "disable_agent",
    "get_effective_agent_version",
    "locked_tenant_agent",
    "normalize_agent_configuration",
]
