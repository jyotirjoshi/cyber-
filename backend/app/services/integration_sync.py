"""Durable continuous ingestion for configured security-provider feeds."""

from __future__ import annotations

import datetime as dt
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import CynuxError
from app.db.base import utcnow
from app.db.enums import IntegrationKind
from app.db.models.integration import Integration
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
                    "error_code": (
                        exc.code if isinstance(exc, CynuxError) else "unexpected_error"
                    ),
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

    return len(due)


__all__ = ["run_due_integration_syncs"]
