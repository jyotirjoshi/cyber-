"""Durable continuous ingestion for configured security-provider feeds."""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    CynuxError,
    InvalidConfigurationError,
    ResourceNotFoundError,
)
from app.db.base import utcnow
from app.db.enums import IntegrationKind
from app.db.models.integration import Integration, IntegrationSyncRun
from app.services import audit as audit_service
from app.services import external_alert as external_alert_service
from app.services.audit import AuditAction
from app.services.context import Principal
from app.services.integration import CONTINUOUS_SYNC_KINDS

SyncCallable = Callable[..., Awaitable[Any]]

_SYNC_HANDLERS: dict[IntegrationKind, SyncCallable] = {
    IntegrationKind.GITHUB: external_alert_service.sync_github_alerts,
    IntegrationKind.GITLAB: external_alert_service.sync_gitlab_alerts,
    IntegrationKind.WAZUH: external_alert_service.sync_wazuh_alerts,
    IntegrationKind.SONARQUBE: external_alert_service.sync_sonarqube_alerts,
    IntegrationKind.SNYK: external_alert_service.sync_snyk_issues,
    IntegrationKind.TENABLE: external_alert_service.sync_tenable_vulnerabilities,
    IntegrationKind.QUALYS: external_alert_service.sync_qualys_host_detections,
    IntegrationKind.RAPID7: external_alert_service.sync_rapid7_vulnerabilities,
    IntegrationKind.WIZ: external_alert_service.sync_wiz_issues,
    IntegrationKind.PRISMA_CLOUD: external_alert_service.sync_prisma_cloud_alerts,
    IntegrationKind.CROWDSTRIKE: external_alert_service.sync_crowdstrike_vulnerabilities,
    IntegrationKind.AWS_SECURITY_HUB: external_alert_service.sync_aws_security_hub_findings,
    IntegrationKind.AWS_INSPECTOR: external_alert_service.sync_aws_inspector_findings,
    IntegrationKind.HACKERONE: external_alert_service.sync_hackerone_reports,
    IntegrationKind.BUGCROWD: external_alert_service.sync_bugcrowd_submissions,
    IntegrationKind.CHECKMARX: external_alert_service.sync_checkmarx_results,
    IntegrationKind.FORTIFY: external_alert_service.sync_fortify_issues,
    IntegrationKind.AZURE_DEFENDER: external_alert_service.sync_azure_defender_alerts,
    IntegrationKind.GCP_SCC: external_alert_service.sync_gcp_scc_findings,
    IntegrationKind.BURP_DAST: external_alert_service.sync_burp_dast_findings,
}

if frozenset(_SYNC_HANDLERS) != CONTINUOUS_SYNC_KINDS:  # pragma: no cover - import invariant
    raise RuntimeError("continuous integration sync registry is incomplete")


def _retry_minutes(interval: int, failures: int) -> int:
    """Retry quickly, then cap backoff at the connector's normal cadence."""
    return min(interval, 5 * (2 ** min(max(failures - 1, 0), 10)))


def new_sync_run(
    integration: Integration,
    *,
    mode: str,
    started_at: dt.datetime,
    replay_of_id: uuid.UUID | None = None,
) -> IntegrationSyncRun:
    """Create a bounded execution receipt without copying provider payloads or secrets."""
    checkpoint = {
        "last_completed_at": (
            integration.last_sync_at.isoformat() if integration.last_sync_at else None
        ),
        "failure_count": int(integration.sync_failure_count or 0),
    }
    if replay_of_id is not None:
        checkpoint["replay_of_id"] = str(replay_of_id)
    return IntegrationSyncRun(
        organization_id=integration.organization_id,
        integration_id=integration.id,
        run_key=(f"{mode}:{integration.id}:{started_at.isoformat()}:{uuid.uuid4().hex[:12]}"),
        mode=mode,
        status="running",
        started_at=started_at,
        checkpoint_before=checkpoint,
        checkpoint_after={},
    )


def settle_sync_run(
    row: IntegrationSyncRun,
    *,
    status: str,
    completed_at: dt.datetime,
    items_seen: int = 0,
    items_staged: int = 0,
    absence_candidates: int = 0,
    error_code: str | None = None,
    error_summary: str | None = None,
) -> None:
    """Settle a receipt with bounded operational evidence, never provider payloads."""

    row.status = status
    row.completed_at = completed_at
    row.duration_ms = max(0, int((completed_at - row.started_at).total_seconds() * 1000))
    row.items_seen = max(0, int(items_seen))
    row.items_staged = max(0, int(items_staged))
    row.absence_candidates = max(0, int(absence_candidates))
    row.error_code = error_code[:80] if error_code else None
    row.error_summary = error_summary[:500] if error_summary else None
    row.checkpoint_after = (
        {"completed_at": completed_at.isoformat()} if status == "succeeded" else {}
    )


async def run_due_integration_syncs(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Any | None,
    limit: int = 3,
) -> int:
    """Claim and synchronize due feeds once across any number of worker replicas.

    The row locks span provider access and canonical ingestion. This intentionally
    favors one authoritative complete snapshot over concurrent pulls that could
    produce contradictory absence evidence. Each provider runs in a savepoint so
    one malformed response cannot retain partial source or canonical writes.
    """
    started_at = utcnow()
    due = list(
        (
            await session.scalars(
                select(Integration)
                .where(
                    Integration.is_enabled.is_(True),
                    Integration.sync_interval_minutes.is_not(None),
                    Integration.next_sync_at.is_not(None),
                    Integration.next_sync_at <= started_at,
                    Integration.kind.in_(kind.value for kind in CONTINUOUS_SYNC_KINDS),
                )
                .order_by(Integration.next_sync_at, Integration.id)
                .limit(max(1, min(limit, 20)))
                .with_for_update(skip_locked=True)
            )
        ).all()
    )

    for integration in due:
        interval = max(5, min(int(integration.sync_interval_minutes or 60), 10080))
        principal = Principal.for_system(organization_id=integration.organization_id)
        kind = IntegrationKind(integration.kind)
        handler = _SYNC_HANDLERS[kind]
        receipt = new_sync_run(integration, mode="scheduled", started_at=started_at)
        session.add(receipt)
        await session.flush()
        # Move the due time before opening the savepoint. A rollback of provider
        # writes must not immediately hot-loop the same broken connection.
        integration.next_sync_at = started_at + dt.timedelta(minutes=interval)
        try:
            async with session.begin_nested():
                result = await handler(
                    session,
                    principal,
                    settings=settings,
                    redis=redis,
                )
            completed_at = utcnow()
            integration.last_sync_at = completed_at
            integration.last_sync_status = "succeeded"
            integration.last_sync_error = None
            integration.sync_failure_count = 0
            integration.next_sync_at = completed_at + dt.timedelta(minutes=interval)
        except Exception as exc:
            failures = integration.sync_failure_count + 1
            integration.last_sync_at = utcnow()
            integration.last_sync_status = "failed"
            integration.sync_failure_count = failures
            integration.last_sync_error = (
                exc.user_message
                if isinstance(exc, CynuxError)
                else "The provider sync failed unexpectedly. Review worker logs."
            )
            integration.next_sync_at = integration.last_sync_at + dt.timedelta(
                minutes=_retry_minutes(interval, failures)
            )
            settle_sync_run(
                receipt,
                status="failed",
                completed_at=integration.last_sync_at,
                error_code=exc.code if isinstance(exc, CynuxError) else "unexpected_error",
                error_summary="Provider sync failed; retry scheduled.",
            )
            await audit_service.record(
                session,
                action=AuditAction.INTEGRATION_SYNC,
                principal=principal,
                resource_type="integration",
                resource_id=integration.id,
                detail={
                    "provider": kind.value,
                    "outcome": "failed",
                    "error_code": exc.code if isinstance(exc, CynuxError) else "unexpected_error",
                    "attempt": failures,
                },
            )
            from app.services.automation import queue_rule_event

            await queue_rule_event(
                session,
                organization_id=integration.organization_id,
                trigger="integration.error",
                event_key=f"integration.error:{integration.id}:{failures}",
                context={
                    "integration_id": str(integration.id),
                    "source": kind.value,
                    "status": "failed",
                    "attempt": failures,
                    "error_code": (exc.code if isinstance(exc, CynuxError) else "unexpected_error"),
                },
            )
            continue

        # Provider-specific sync functions record detailed ingestion counts. This
        # additional durable state makes schedule health visible without log access.
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration_schedule",
            resource_id=integration.id,
            detail={
                "provider": kind.value,
                "outcome": "succeeded",
                "alerts_staged": int(getattr(result, "total", 0)),
                "continuous": True,
            },
        )
        total = int(getattr(result, "total", 0))
        settle_sync_run(
            receipt,
            status="succeeded",
            completed_at=integration.last_sync_at or utcnow(),
            items_seen=total,
            items_staged=total,
            absence_candidates=int(getattr(result, "absence_candidates", 0)),
        )

    return len(due)


async def run_manual_integration_sync(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    *,
    settings: Settings,
    redis: Any | None,
    replay_of_id: uuid.UUID | None = None,
) -> Any:
    """Run one connector under the same durable receipt boundary as the scheduler.

    Provider writes live in a savepoint. A failure rolls those writes back while retaining
    the redacted execution receipt and connector health transition for the route to commit.
    """
    from app.db.enums import Permission

    principal.require(Permission.INTEGRATION_MANAGE)
    handler = _SYNC_HANDLERS.get(kind)
    if handler is None:
        raise InvalidConfigurationError(
            "continuous sync is unavailable for this integration",
            user_message=f"{kind.value} does not provide a synchronized finding feed.",
        )
    integration = await session.scalar(
        select(Integration)
        .where(
            Integration.organization_id == principal.organization_id,
            Integration.kind == kind.value,
            Integration.is_enabled.is_(True),
        )
        .with_for_update()
    )
    if integration is None:
        raise ResourceNotFoundError(
            "integration not found",
            user_message=f"Configure and enable the {kind.value} integration first.",
        )

    started_at = utcnow()
    receipt = new_sync_run(
        integration,
        mode="manual",
        started_at=started_at,
        replay_of_id=replay_of_id,
    )
    session.add(receipt)
    await session.flush()
    prior_failures = int(integration.sync_failure_count or 0)
    sync_interval = integration.sync_interval_minutes
    try:
        async with session.begin_nested():
            result = await handler(session, principal, settings=settings, redis=redis)
    except Exception as exc:
        completed_at = utcnow()
        integration = await session.scalar(
            select(Integration)
            .where(
                Integration.id == receipt.integration_id,
                Integration.organization_id == principal.organization_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if integration is None:  # pragma: no cover - protected by the receipt FK
            raise ResourceNotFoundError("integration disappeared during synchronization") from exc
        failures = prior_failures + 1
        integration.last_sync_at = completed_at
        integration.last_sync_status = "failed"
        integration.last_sync_error = (
            exc.user_message
            if isinstance(exc, CynuxError)
            else "The provider sync failed unexpectedly. Review the execution receipt."
        )
        integration.sync_failure_count = failures
        if sync_interval is not None:
            interval = max(5, min(int(sync_interval), 10080))
            integration.next_sync_at = completed_at + dt.timedelta(
                minutes=_retry_minutes(interval, failures)
            )
        settle_sync_run(
            receipt,
            status="failed",
            completed_at=completed_at,
            error_code=exc.code if isinstance(exc, CynuxError) else "unexpected_error",
            error_summary="Provider sync failed; the failed attempt can be replayed.",
        )
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SYNC,
            principal=principal,
            resource_type="integration_sync_run",
            resource_id=receipt.id,
            outcome=audit_service.AuditOutcome.FAILURE,
            detail={
                "provider": kind.value,
                "mode": "manual",
                "replay_of_id": str(replay_of_id) if replay_of_id else None,
                "error_code": exc.code if isinstance(exc, CynuxError) else "unexpected_error",
            },
            reason=integration.last_sync_error,
        )
        raise

    completed_at = utcnow()
    total = int(getattr(result, "total", 0))
    settle_sync_run(
        receipt,
        status="succeeded",
        completed_at=completed_at,
        items_seen=total,
        items_staged=total,
        absence_candidates=int(getattr(result, "absence_candidates", 0)),
    )
    return result


async def replay_failed_sync(
    session: AsyncSession,
    principal: Principal,
    run_id: uuid.UUID,
    *,
    settings: Settings,
    redis: Any | None,
) -> tuple[IntegrationKind, Any]:
    """Replay a failed tenant-owned attempt against the provider's current source state."""
    from app.db.enums import Permission

    principal.require(Permission.INTEGRATION_MANAGE)
    previous = await session.scalar(
        select(IntegrationSyncRun).where(
            IntegrationSyncRun.id == run_id,
            IntegrationSyncRun.organization_id == principal.organization_id,
        )
    )
    if previous is None:
        raise ResourceNotFoundError("integration sync run not found")
    if previous.status != "failed":
        raise ConflictError(
            "only failed connector runs can be replayed",
            user_message="Only a failed connector execution can be replayed.",
        )
    integration = await session.scalar(
        select(Integration).where(
            Integration.id == previous.integration_id,
            Integration.organization_id == principal.organization_id,
        )
    )
    if integration is None:
        raise ResourceNotFoundError("integration for sync run not found")
    kind = IntegrationKind(integration.kind)
    result = await run_manual_integration_sync(
        session,
        principal,
        kind,
        settings=settings,
        redis=redis,
        replay_of_id=previous.id,
    )
    return kind, result


__all__ = [
    "new_sync_run",
    "replay_failed_sync",
    "run_due_integration_syncs",
    "run_manual_integration_sync",
    "settle_sync_run",
]
