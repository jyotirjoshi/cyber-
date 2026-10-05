"""Tenant-scoped external alert inbox, local triage, and related findings."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PaginationDep, PrincipalDep, RedisDep, SettingsDep
from app.schemas.common import Page
from app.schemas.external_alert import (
    ExternalAlertDetailOut,
    ExternalAlertOut,
    ExternalAlertSourceActionIn,
    ExternalAlertTriageIn,
    RelatedFindingOut,
)
from app.services.external_alert import (
    get_external_alert,
    list_external_alerts,
    related_external_alerts_for_alert,
    related_findings_for_alert,
    set_github_alert_state,
    triage_external_alert,
)

router = APIRouter(prefix="/external-alerts", tags=["findings"])


@router.get("", response_model=Page[ExternalAlertOut])
async def external_alert_inbox(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    provider: Annotated[Literal["github", "gitlab", "wazuh", "sonarqube", "snyk", "tenable"] | None, Query()] = None,
    severity: Annotated[Literal["critical", "high", "medium", "low", "info"] | None, Query()] = None,
    status: Annotated[Literal["open", "resolved", "dismissed", "fixed"] | None, Query()] = None,
    triage_status: Annotated[
        Literal["new", "investigating", "risk_accepted", "false_positive", "closed"] | None,
        Query(),
    ] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[ExternalAlertOut]:
    rows, total = await list_external_alerts(
        session,
        principal,
        provider=provider,
        severity=severity,
        status=status,
        triage_status=triage_status,
        q=q,
        pagination=pagination,
    )
    return Page.build(
        [ExternalAlertOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/{alert_id}", response_model=ExternalAlertDetailOut)
async def external_alert_detail(
    alert_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> ExternalAlertDetailOut:
    alert = await get_external_alert(session, principal, alert_id)
    return ExternalAlertDetailOut.model_validate(alert)


@router.get("/{alert_id}/related-findings", response_model=list[RelatedFindingOut])
async def external_alert_related_findings(
    alert_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> list[RelatedFindingOut]:
    findings = await related_findings_for_alert(session, principal, alert_id)
    return [RelatedFindingOut.model_validate(finding) for finding in findings]


@router.get("/{alert_id}/related-alerts", response_model=list[ExternalAlertOut])
async def external_alert_related_alerts(
    alert_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> list[ExternalAlertOut]:
    alerts = await related_external_alerts_for_alert(session, principal, alert_id)
    return [ExternalAlertOut.model_validate(alert) for alert in alerts]


@router.patch("/{alert_id}/triage", response_model=ExternalAlertDetailOut)
async def update_external_alert_triage(
    alert_id: uuid.UUID,
    payload: ExternalAlertTriageIn,
    principal: PrincipalDep,
    session: DbSession,
) -> ExternalAlertDetailOut:
    await triage_external_alert(
        session,
        principal,
        alert_id,
        status=payload.status,
        note=payload.note,
        expected_version=payload.expected_version,
    )
    await session.commit()
    alert = await get_external_alert(session, principal, alert_id)
    return ExternalAlertDetailOut.model_validate(alert)


@router.patch("/{alert_id}/github", response_model=ExternalAlertDetailOut)
async def update_github_alert_source(
    alert_id: uuid.UUID,
    payload: ExternalAlertSourceActionIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> ExternalAlertDetailOut:
    """Apply an explicit GitHub alert decision and return confirmed source status."""
    row = await set_github_alert_state(
        session, principal, alert_id, decision=payload.decision,
        reason=payload.reason, comment=payload.comment,
        settings=settings, redis=redis,
    )
    await session.commit()
    return ExternalAlertDetailOut.model_validate(row)
