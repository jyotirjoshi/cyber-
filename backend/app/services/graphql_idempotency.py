"""Transaction-local reservation and replay for GraphQL mutation effects."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError
from app.db.models.graphql import GraphQLMutationReceipt
from app.db.repository import tenant_select
from app.services.context import Principal


def input_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _actor_key(principal: Principal) -> str:
    identity = principal.user_id or principal.credential_id
    if identity is None:
        raise ConflictError("mutation actor identity is unavailable")
    identifier = str(identity)
    return f"{principal.actor_type}:{identifier}"


async def reserve(
    session: AsyncSession,
    principal: Principal,
    *,
    operation: str,
    idempotency_key: str,
    digest: str,
) -> tuple[GraphQLMutationReceipt, bool]:
    """Reserve a key or return its committed receipt after validating its digest."""
    if not idempotency_key or len(idempotency_key) > 160:
        raise ConflictError("idempotency key must contain 1 to 160 characters")
    actor_key = _actor_key(principal)
    lookup = tenant_select(GraphQLMutationReceipt, principal.organization_id).where(
        GraphQLMutationReceipt.actor_key == actor_key,
        GraphQLMutationReceipt.operation == operation,
        GraphQLMutationReceipt.idempotency_key == idempotency_key,
    )
    existing = await session.scalar(lookup)
    if existing is not None:
        _validate(existing, digest)
        return existing, True

    receipt = GraphQLMutationReceipt(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        actor_key=actor_key,
        operation=operation,
        idempotency_key=idempotency_key,
        input_digest=digest,
    )
    try:
        async with session.begin_nested():
            session.add(receipt)
            await session.flush()
    except IntegrityError:
        existing = await session.scalar(lookup)
        if existing is None:  # pragma: no cover - defensive database anomaly
            raise
        _validate(existing, digest)
        return existing, True
    return receipt, False


def _validate(receipt: GraphQLMutationReceipt, digest: str) -> None:
    if receipt.input_digest != digest:
        raise ConflictError("idempotency key was reused for different input")
    if receipt.resource_id is None:
        raise ConflictError("idempotent mutation has not completed")


__all__ = ["input_digest", "reserve"]
