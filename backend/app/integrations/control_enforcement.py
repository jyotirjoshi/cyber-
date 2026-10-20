"""Provider-neutral, approval-gated control enforcement contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import uuid
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Protocol

from app.core.config import Settings
from app.core.errors import ConflictError, ResourceNotFoundError
from app.core.logging_conf import redact_mapping
from app.db.enums import IntegrationKind, Permission
from app.db.models.control_plane import SecurityRecommendation, SecurityResource
from app.db.models.integration import Integration
from app.db.repository import tenant_select
from app.schemas.control_plane import SecurityResourceUpsertIn
from app.services.audit import record
from app.services.context import Principal

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class EnforcementCommand:
    action: str
    target_external_id: str
    desired_state: dict[str, Any]
    idempotency_key: str
    dry_run: bool = True

    def __post_init__(self) -> None:
        if not self.action or not self.target_external_id or not self.idempotency_key:
            raise ValueError("action, target_external_id, and idempotency_key are required")


@dataclass(frozen=True, slots=True)
class EnforcementReceipt:
    provider: str
    action: str
    idempotency_key: str
    status: str
    provider_receipt: dict[str, Any] = field(default_factory=dict)


class ControlEnforcementAdapter(Protocol):
    provider: str

    async def preview(self, command: EnforcementCommand) -> dict[str, Any]: ...

    async def apply(self, command: EnforcementCommand) -> dict[str, Any]: ...


async def execute_enforcement(
    adapter: ControlEnforcementAdapter,
    command: EnforcementCommand,
    *,
    existing_receipt: EnforcementReceipt | None = None,
) -> EnforcementReceipt:
    """Execute at most once and return a credential-safe durable receipt."""

    if (
        existing_receipt is not None
        and existing_receipt.status == "applied"
        and existing_receipt.provider == adapter.provider
        and existing_receipt.action == command.action
        and existing_receipt.idempotency_key == command.idempotency_key
    ):
        return existing_receipt
    payload = await (adapter.preview(command) if command.dry_run else adapter.apply(command))
    safe = redact_mapping(payload)
    return EnforcementReceipt(
        provider=adapter.provider,
        action=command.action,
        idempotency_key=command.idempotency_key,
        status=str(safe.get("status") or ("previewed" if command.dry_run else "applied")),
        provider_receipt=safe,
    )


async def apply_recommendation(
    session: AsyncSession,
    principal: Principal,
    recommendation_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Redis | None = None,
    dry_run: bool = False,
) -> SecurityRecommendation:
    """Apply one approved recommendation through its tenant-owned connector."""

    # Local import avoids a module cycle: integration service imports provider clients.
    from app.services.integration import resolve_settings
    from app.integrations.zscaler import ZscalerClient

    principal.require(Permission.INTEGRATION_MANAGE)
    recommendation = await session.scalar(
        tenant_select(SecurityRecommendation, principal.organization_id)
        .where(SecurityRecommendation.id == recommendation_id)
        .with_for_update()
    )
    if recommendation is None:
        raise ResourceNotFoundError("Recommendation not found")
    if recommendation.status == "applied" and not dry_run:
        return recommendation
    allowed_statuses = {"proposed", "approved", "failed"} if dry_run else {"approved", "failed"}
    if recommendation.status not in allowed_statuses:
        raise ConflictError(f"Cannot apply a {recommendation.status} recommendation")
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
        raise ConflictError("This recommendation does not use a supported enforcement provider")
    resource = None
    if recommendation.resource_id is not None:
        resource = await session.scalar(
            tenant_select(SecurityResource, principal.organization_id).where(
                SecurityResource.id == recommendation.resource_id
            )
        )
    desired = dict(recommendation.desired_state)
    target = str(desired.pop("target_external_id", "") or (resource.external_id if resource else ""))
    if not target:
        raise ConflictError("Recommendation has no provider target identifier")
    scoped = await resolve_settings(
        session, principal, IntegrationKind.ZSCALER, settings=settings, require=True
    )
    client = ZscalerClient(scoped, redis)
    try:
        existing = None
        if recommendation.status == "applied" and recommendation.provider_receipt:
            existing = EnforcementReceipt(
                provider="zscaler",
                action=recommendation.action,
                idempotency_key=recommendation.idempotency_key,
                status="applied",
                provider_receipt=recommendation.provider_receipt,
            )
        if not dry_run:
            recommendation.status = "applying"
            await session.flush()
        receipt = await execute_enforcement(
            client,
            EnforcementCommand(
                action=recommendation.action,
                target_external_id=target,
                desired_state=desired,
                idempotency_key=recommendation.idempotency_key,
                dry_run=dry_run,
            ),
            existing_receipt=existing,
        )
    finally:
        await client.aclose()
    recommendation.provider_receipt = {
        "provider": receipt.provider,
        "action": receipt.action,
        "idempotency_key": receipt.idempotency_key,
        **receipt.provider_receipt,
    }
    if not dry_run:
        recommendation.status = "applied"
        recommendation.applied_by_id = principal.user_id
        recommendation.applied_at = dt.datetime.now(dt.UTC)
    await session.flush()
    await record(
        session,
        action="control_plane.recommendation.preview" if dry_run else "control_plane.recommendation.apply",
        principal=principal,
        resource_type="security_recommendation",
        resource_id=recommendation.id,
        detail={"provider": "zscaler", "action": recommendation.action, "dry_run": dry_run},
    )
    return recommendation


async def sync_zscaler_inventory(
    session: AsyncSession,
    principal: Principal,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> int:
    """Reconcile ZPA/ZIA inventory into the canonical resource graph."""

    from app.services import control_plane
    from app.services.integration import find_integration, resolve_settings
    from app.integrations.zscaler import ZscalerClient

    principal.require(Permission.INTEGRATION_MANAGE)
    integration = await find_integration(session, principal, IntegrationKind.ZSCALER)
    if integration is None:
        raise ResourceNotFoundError("Zscaler integration not found")
    scoped = await resolve_settings(
        session, principal, IntegrationKind.ZSCALER, settings=settings, require=True
    )
    client = ZscalerClient(scoped, redis)
    try:
        items = await client.list_inventory()
    finally:
        await client.aclose()
    observed_at = dt.datetime.now(dt.UTC)
    for item in items:
        await control_plane.upsert_resource(
            session,
            principal,
            SecurityResourceUpsertIn(
                **item,
                source_kind=item["provenance"]["source"],
                source_key=item["external_id"],
                integration_id=integration.id,
                observed_at=observed_at,
                confidence=Decimal("0.950"),
            ),
        )
    return len(items)


__all__ = [
    "ControlEnforcementAdapter",
    "EnforcementCommand",
    "EnforcementReceipt",
    "apply_recommendation",
    "execute_enforcement",
    "sync_zscaler_inventory",
]
