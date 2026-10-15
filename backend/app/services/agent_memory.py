"""Curated tenant memory used as bounded, non-executable AI reference context."""

from __future__ import annotations

import datetime as dt
import json
import uuid

from sqlalchemy import or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import Permission
from app.db.models.agent import AgentMemory
from app.db.repository import tenant_select
from app.core.logging_conf import redact_text
from app.schemas.agent_memory import AgentMemoryUpsertIn
from app.services import audit as audit_service
from app.services.context import Principal

_MAX_MEMORY_ITEMS = 20
_MAX_PROMPT_CHARS_PER_ITEM = 600


async def list_memories(session: AsyncSession, principal: Principal) -> list[AgentMemory]:
    principal.require(Permission.ORG_MANAGE)
    return list((await session.scalars(
        tenant_select(AgentMemory, principal.organization_id)
        .order_by(AgentMemory.category, AgentMemory.key)
        .limit(200)
    )).all())


async def upsert_memory(
    session: AsyncSession, principal: Principal, payload: AgentMemoryUpsertIn
) -> AgentMemory:
    principal.require(Permission.ORG_MANAGE)
    memory = (await session.execute(
        tenant_select(AgentMemory, principal.organization_id).where(AgentMemory.key == payload.key).with_for_update()
    )).scalar_one_or_none()
    if memory is None:
        memory = AgentMemory(
            organization_id=principal.organization_id, key=payload.key, created_by_id=principal.user_id,
            category=payload.category, content=payload.content, expires_at=payload.expires_at,
        )
        session.add(memory)
    else:
        memory.category, memory.content, memory.expires_at, memory.is_active = (
            payload.category, payload.content, payload.expires_at, True,
        )
    await session.flush()
    await audit_service.record(
        session, action=audit_service.AuditAction.AGENT_MEMORY_UPSERT, principal=principal,
        resource_type="agent_memory", resource_id=memory.id,
        detail={"key": memory.key, "category": memory.category, "has_expiry": memory.expires_at is not None},
    )
    return memory


async def disable_memory(session: AsyncSession, principal: Principal, memory_id: uuid.UUID) -> AgentMemory:
    principal.require(Permission.ORG_MANAGE)
    memory = (await session.execute(
        tenant_select(AgentMemory, principal.organization_id).where(AgentMemory.id == memory_id).with_for_update()
    )).scalar_one_or_none()
    if memory is None:
        from app.core.errors import ResourceNotFoundError
        raise ResourceNotFoundError("Agent memory not found")
    memory.is_active = False
    await audit_service.record(
        session, action=audit_service.AuditAction.AGENT_MEMORY_DISABLE, principal=principal,
        resource_type="agent_memory", resource_id=memory.id, detail={"key": memory.key},
    )
    return memory


async def prompt_context(session: AsyncSession, principal: Principal) -> str | None:
    """Produce a bounded data-only reference block for an authorized tenant agent."""
    now = dt.datetime.now(dt.UTC)
    rows = list((await session.scalars(
        tenant_select(AgentMemory, principal.organization_id)
        .where(AgentMemory.is_active.is_(True), or_(AgentMemory.expires_at.is_(None), AgentMemory.expires_at > now))
        .order_by(AgentMemory.category, AgentMemory.key)
        .limit(_MAX_MEMORY_ITEMS)
    )).all())
    if not rows:
        return None
    return json.dumps([
        {
            "key": row.key,
            "category": row.category,
            # The durable record remains intact for an authorized administrator,
            # while the model sees only a bounded, secret-redacted representation.
            "content": redact_text(row.content[:_MAX_PROMPT_CHARS_PER_ITEM]),
        }
        for row in rows
    ], ensure_ascii=True, separators=(",", ":"))


__all__ = ["disable_memory", "list_memories", "prompt_context", "upsert_memory"]
