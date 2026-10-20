"""Deterministic, approval-bound change-control transactions."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from typing import TYPE_CHECKING, Any

from app.core.errors import ConflictError, ResourceNotFoundError
from app.core.logging_conf import redact_mapping
from app.db.enums import IntegrationKind, Permission
from app.db.models.assurance import EnforcementTransaction
from app.db.models.control_plane import SecurityRecommendation, SecurityResource
from app.db.models.integration import Integration
from app.db.repository import tenant_select
from app.integrations.control_enforcement import (
    ControlEnforcementAdapter,
    EnforcementCommand,
    execute_enforcement,
)
from app.services.audit import record
from app.services.context import Principal

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.config import Settings


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _pointer(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def deterministic_diff(
    current: dict[str, Any], desired: dict[str, Any], *, prefix: str = ""
) -> list[dict[str, Any]]:
    """Return a stable and reversible JSON-object diff."""

    changes: list[dict[str, Any]] = []
    for key in sorted(set(current) | set(desired)):
        path = f"{prefix}/{_pointer(key)}"
        if key not in current:
            changes.append({"op": "add", "path": path, "after": desired[key]})
        elif key not in desired:
            changes.append({"op": "remove", "path": path, "before": current[key]})
        elif isinstance(current[key], dict) and isinstance(desired[key], dict):
            changes.extend(deterministic_diff(current[key], desired[key], prefix=path))
        elif current[key] != desired[key]:
            changes.append(
                {"op": "replace", "path": path, "before": current[key], "after": desired[key]}
            )
    return changes


def simulate_blast_radius(snapshot: dict[str, Any], diff: list[dict[str, Any]]) -> dict[str, Any]:
    """Project conservative impact from provider inventory metadata."""

    identities = snapshot.get("identities") or snapshot.get("users") or []
    applications = snapshot.get("applications") or snapshot.get("applicationSegments") or []
    services = snapshot.get("business_services") or []
    identity_count = len(identities) if isinstance(identities, list) else int(identities or 0)
    application_count = (
        len(applications) if isinstance(applications, list) else int(applications or 0)
    )
    service_count = len(services) if isinstance(services, list) else int(services or 0)
    destructive = any(change["op"] == "remove" for change in diff)
    score = min(
        100,
        len(diff) * 5
        + min(identity_count, 1000) // 10
        + application_count * 5
        + service_count * 10
        + (20 if destructive else 0),
    )
    return {
        "identity_count": identity_count,
        "application_count": application_count,
        "business_service_count": service_count,
        "change_count": len(diff),
        "destructive": destructive,
        "score": score,
        "level": (
            "critical"
            if score >= 80
            else "high"
            if score >= 50
            else "medium"
            if score >= 20
            else "low"
        ),
    }


def approve_transaction(
    transaction: EnforcementTransaction | Any,
    *,
    actor_user_id: uuid.UUID,
    expected_diff_digest: str,
    now: dt.datetime | None = None,
) -> None:
    if transaction.status not in {"simulated", "pending_approval"}:
        raise ConflictError(f"Cannot approve a {transaction.status} transaction")
    if expected_diff_digest != transaction.diff_digest:
        raise ConflictError("Transaction diff changed after review")
    transaction.status = "approved"
    transaction.approved_by_id = actor_user_id
    transaction.approved_at = now or dt.datetime.now(dt.UTC)


async def execute_transaction(
    transaction: EnforcementTransaction | Any,
    adapter: ControlEnforcementAdapter,
    *,
    target_external_id: str,
    observation_seconds: int,
    now: dt.datetime | None = None,
) -> None:
    if transaction.status in {"observing", "verifying", "succeeded"} and transaction.mutation_receipt:
        return
    if transaction.status != "approved":
        raise ConflictError(f"Cannot execute a {transaction.status} transaction")
    current_time = now or dt.datetime.now(dt.UTC)
    command = EnforcementCommand(
        action=transaction.operation,
        target_external_id=target_external_id,
        desired_state=dict(transaction.desired_state),
        idempotency_key=transaction.idempotency_key,
        dry_run=False,
    )
    transaction.status = "applying"
    receipt = await execute_enforcement(adapter, command)
    transaction.mutation_receipt = {
        "provider": receipt.provider,
        "action": receipt.action,
        "idempotency_key": receipt.idempotency_key,
        **receipt.provider_receipt,
    }
    transaction.executed_at = current_time
    transaction.confirmation = redact_mapping(await adapter.confirm(command))
    if transaction.confirmation.get("matches") is not True:
        transaction.status = "failed"
        transaction.last_error = "Provider confirmation did not match desired state"
        return
    transaction.status = "observing"
    transaction.observation_ends_at = current_time + dt.timedelta(seconds=observation_seconds)


def begin_verification(
    transaction: EnforcementTransaction | Any, *, now: dt.datetime | None = None
) -> None:
    current_time = now or dt.datetime.now(dt.UTC)
    if transaction.status != "observing":
        raise ConflictError(f"Cannot verify a {transaction.status} transaction")
    if transaction.observation_ends_at and current_time < transaction.observation_ends_at:
        raise ConflictError("Transaction observation window is still active")
    transaction.status = "verifying"


def record_verification(
    transaction: EnforcementTransaction | Any,
    *,
    success: bool,
    evidence: dict[str, Any],
    now: dt.datetime | None = None,
) -> None:
    if transaction.status != "verifying":
        raise ConflictError(f"Cannot record verification for a {transaction.status} transaction")
    transaction.verification = {"success": success, **redact_mapping(evidence)}
    transaction.verified_at = now or dt.datetime.now(dt.UTC)
    transaction.status = "succeeded" if success else "rollback_pending"


async def rollback_transaction(
    transaction: EnforcementTransaction | Any,
    adapter: ControlEnforcementAdapter,
    *,
    now: dt.datetime | None = None,
) -> None:
    if transaction.status not in {"rollback_pending", "failed"}:
        raise ConflictError(f"Cannot roll back a {transaction.status} transaction")
    plan = dict(transaction.rollback_plan)
    transaction.status = "rolling_back"
    receipt = await execute_enforcement(
        adapter,
        EnforcementCommand(
            action=str(plan["action"]),
            target_external_id=str(plan["target_external_id"]),
            desired_state=dict(plan["desired_state"]),
            idempotency_key=f"{transaction.idempotency_key}:rollback",
            dry_run=False,
        ),
    )
    transaction.verification = {
        **transaction.verification,
        "rollback_receipt": redact_mapping(receipt.provider_receipt),
    }
    transaction.verified_at = now or dt.datetime.now(dt.UTC)
    transaction.status = "rolled_back"


async def _zscaler_adapter(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Redis | None,
) -> ControlEnforcementAdapter:
    from app.integrations.zscaler import ZscalerClient
    from app.services.integration import resolve_settings

    scoped = await resolve_settings(
        session, principal, IntegrationKind.ZSCALER, settings=settings, require=True
    )
    return ZscalerClient(scoped, redis)


async def prepare_transaction(
    session: AsyncSession,
    principal: Principal,
    recommendation_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Redis | None,
    observation_seconds: int,
) -> EnforcementTransaction:
    principal.require(Permission.INTEGRATION_MANAGE)
    recommendation = await session.scalar(
        tenant_select(SecurityRecommendation, principal.organization_id).where(
            SecurityRecommendation.id == recommendation_id
        )
    )
    if recommendation is None:
        raise ResourceNotFoundError("Recommendation not found")
    if recommendation.integration_id is None:
        raise ConflictError("Recommendation has no enforcement integration")
    integration = await session.scalar(
        tenant_select(Integration, principal.organization_id).where(
            Integration.id == recommendation.integration_id
        )
    )
    if integration is None:
        raise ResourceNotFoundError("Enforcement integration not found")
    if integration.kind != IntegrationKind.ZSCALER.value:
        raise ConflictError("Unsupported enforcement provider")
    resource = None
    if recommendation.resource_id:
        resource = await session.scalar(
            tenant_select(SecurityResource, principal.organization_id).where(
                SecurityResource.id == recommendation.resource_id
            )
        )
    desired = redact_mapping(dict(recommendation.desired_state))
    target = str(desired.pop("target_external_id", "") or (resource.external_id if resource else ""))
    if not target:
        raise ConflictError("Recommendation has no provider target identifier")
    adapter = await _zscaler_adapter(session, principal, settings=settings, redis=redis)
    command = EnforcementCommand(
        action=recommendation.action,
        target_external_id=target,
        desired_state=desired,
        idempotency_key=recommendation.idempotency_key,
        dry_run=True,
    )
    try:
        snapshot = redact_mapping(await adapter.snapshot(command))
    finally:
        close = getattr(adapter, "aclose", None)
        if close is not None:
            await close()
    diff = deterministic_diff(snapshot, desired)
    diff_digest = canonical_digest(diff)
    transaction_key = canonical_digest(
        {"recommendation_id": str(recommendation.id), "diff_digest": diff_digest}
    )
    existing = await session.scalar(
        tenant_select(EnforcementTransaction, principal.organization_id).where(
            EnforcementTransaction.transaction_key == transaction_key
        )
    )
    if existing is not None:
        return existing
    transaction = EnforcementTransaction(
        organization_id=principal.organization_id,
        recommendation_id=recommendation.id,
        integration_id=integration.id,
        provider="zscaler",
        operation=recommendation.action,
        transaction_key=transaction_key,
        idempotency_key=f"{recommendation.idempotency_key}:{diff_digest[:16]}",
        status="simulated",
        provider_snapshot=snapshot,
        snapshot_digest=canonical_digest(snapshot),
        desired_state=desired,
        diff=diff,
        diff_digest=diff_digest,
        blast_radius=simulate_blast_radius(snapshot, diff),
        rollback_plan={
            "action": recommendation.action,
            "target_external_id": target,
            "desired_state": snapshot,
        },
        observation_seconds=observation_seconds,
    )
    session.add(transaction)
    await session.flush()
    await record(
        session,
        action="control_plane.transaction.prepare",
        principal=principal,
        resource_type="enforcement_transaction",
        resource_id=transaction.id,
        detail={
            "provider": "zscaler",
            "operation": transaction.operation,
            "diff_digest": diff_digest,
            "observation_seconds": observation_seconds,
        },
    )
    return transaction


async def list_transactions(
    session: AsyncSession, principal: Principal, *, status: str | None = None
) -> list[EnforcementTransaction]:
    principal.require(Permission.INTEGRATION_READ)
    query = tenant_select(EnforcementTransaction, principal.organization_id)
    if status:
        query = query.where(EnforcementTransaction.status == status)
    rows = await session.scalars(
        query.order_by(EnforcementTransaction.created_at.desc()).limit(500)
    )
    return list(rows.all())


async def transition_transaction(
    session: AsyncSession,
    principal: Principal,
    transaction_id: uuid.UUID,
    *,
    action: str,
    settings: Settings,
    redis: Redis | None,
    approval_id: uuid.UUID | None = None,
    expected_diff_digest: str | None = None,
    verification: dict[str, Any] | None = None,
) -> EnforcementTransaction:
    """Advance one transaction by exactly one authorized lifecycle action."""

    principal.require(Permission.INTEGRATION_MANAGE)
    transaction = await session.scalar(
        tenant_select(EnforcementTransaction, principal.organization_id)
        .where(EnforcementTransaction.id == transaction_id)
        .with_for_update()
    )
    if transaction is None:
        raise ResourceNotFoundError("Enforcement transaction not found")
    if action == "approve":
        if principal.user_id is None:
            raise ConflictError("A human user must approve enforcement transactions")
        if not expected_diff_digest:
            raise ConflictError("The reviewed diff digest is required")
        approve_transaction(
            transaction,
            actor_user_id=principal.user_id,
            expected_diff_digest=expected_diff_digest,
        )
        transaction.approval_id = approval_id
    elif action == "begin_verification":
        begin_verification(transaction)
    elif action == "verify":
        details = verification or {}
        if not isinstance(details.get("success"), bool):
            raise ConflictError("Verification requires a boolean success result")
        record_verification(
            transaction,
            success=bool(details["success"]),
            evidence={key: value for key, value in details.items() if key != "success"},
        )
    elif action in {"execute", "rollback"}:
        adapter = await _zscaler_adapter(session, principal, settings=settings, redis=redis)
        try:
            if action == "execute":
                target = str(transaction.rollback_plan.get("target_external_id") or "")
                await execute_transaction(
                    transaction,
                    adapter,
                    target_external_id=target,
                    observation_seconds=transaction.observation_seconds,
                )
            else:
                await rollback_transaction(transaction, adapter)
        finally:
            close = getattr(adapter, "aclose", None)
            if close is not None:
                await close()
    elif action == "cancel":
        if transaction.status not in {"draft", "simulated", "pending_approval", "approved"}:
            raise ConflictError(f"Cannot cancel a {transaction.status} transaction")
        transaction.status = "cancelled"
    else:
        raise ConflictError("Unsupported transaction action")
    await session.flush()
    await record(
        session,
        action=f"control_plane.transaction.{action}",
        principal=principal,
        resource_type="enforcement_transaction",
        resource_id=transaction.id,
        detail={
            "status": transaction.status,
            "provider": transaction.provider,
            "diff_digest": transaction.diff_digest,
        },
    )
    return transaction


__all__ = [
    "approve_transaction",
    "begin_verification",
    "canonical_digest",
    "deterministic_diff",
    "execute_transaction",
    "list_transactions",
    "prepare_transaction",
    "record_verification",
    "rollback_transaction",
    "simulate_blast_radius",
    "transition_transaction",
]
