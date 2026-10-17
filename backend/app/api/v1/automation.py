"""Tenant automation-rule management."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Header, Request, Response

from app.api.deps import DbSession, PaginationDep, PrincipalDep, SettingsDep
from app.core.errors import AuthenticationError
from app.db.enums import Permission
from app.schemas.automation import (
    AutomationExecutionOut,
    AutomationInboundSecretOut,
    AutomationManualRunIn,
    AutomationRuleIn,
    AutomationRuleOut,
)
from app.schemas.common import Page
from app.services import automation as automation_service

router = APIRouter(prefix="/automation", tags=["automation"])


@router.get("/catalog")
async def get_automation_catalog(principal: PrincipalDep) -> dict[str, object]:
    principal.require(Permission.ORG_READ)
    return automation_service.automation_catalog()


@router.get("/rules", response_model=Page[AutomationRuleOut])
async def list_automation_rules(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
) -> Page[AutomationRuleOut]:
    rows, total = await automation_service.list_rules_paged(
        session, principal, limit=pagination.limit, offset=pagination.offset
    )
    return Page.build(
        [AutomationRuleOut.model_validate(r) for r in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("/rules", response_model=AutomationRuleOut, status_code=201)
async def create_automation_rule(
    body: AutomationRuleIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AutomationRuleOut:
    rule = await automation_service.create_rule(session, principal, body)
    await session.commit()
    await session.refresh(rule)
    return AutomationRuleOut.model_validate(rule)


@router.get("/rules/{rule_id}", response_model=AutomationRuleOut)
async def get_automation_rule(
    rule_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AutomationRuleOut:
    rule = await automation_service.get_rule(session, principal, rule_id)
    return AutomationRuleOut.model_validate(rule)


@router.patch("/rules/{rule_id}", response_model=AutomationRuleOut)
async def update_automation_rule(
    rule_id: uuid.UUID,
    body: AutomationRuleIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AutomationRuleOut:
    rule = await automation_service.update_rule(session, principal, rule_id, body)
    await session.commit()
    await session.refresh(rule)
    return AutomationRuleOut.model_validate(rule)


@router.delete("/rules/{rule_id}", status_code=204, response_class=Response)
async def delete_automation_rule(
    rule_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> Response:
    await automation_service.delete_rule(session, principal, rule_id)
    await session.commit()
    return Response(status_code=204)


@router.post("/rules/{rule_id}/run", response_model=AutomationExecutionOut, status_code=202)
async def run_automation_rule(
    rule_id: uuid.UUID,
    body: AutomationManualRunIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AutomationExecutionOut:
    execution = await automation_service.queue_manual_run(session, principal, rule_id, body)
    await session.commit()
    await session.refresh(execution)
    return AutomationExecutionOut.model_validate(execution)


@router.post(
    "/rules/{rule_id}/inbound-secret/rotate",
    response_model=AutomationInboundSecretOut,
)
async def rotate_automation_inbound_secret(
    rule_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> AutomationInboundSecretOut:
    secret, rotated_at = await automation_service.rotate_inbound_secret(
        session, principal, rule_id, settings
    )
    await session.commit()
    return AutomationInboundSecretOut(rule_id=rule_id, secret=secret, rotated_at=rotated_at)


@router.post("/inbound/{rule_id}", status_code=202)
async def receive_automation_webhook(
    rule_id: uuid.UUID,
    request: Request,
    session: DbSession,
    settings: SettingsDep,
    x_cynux_timestamp: int = Header(alias="X-Cynux-Timestamp"),
    x_cynux_signature: str = Header(alias="X-Cynux-Signature"),
    x_cynux_event_id: str = Header(alias="X-Cynux-Event-Id"),
) -> dict[str, object]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 32_768:
            raise AuthenticationError("Invalid automation webhook")
        chunks.append(chunk)
    body = b"".join(chunks)
    queued = await automation_service.queue_inbound_webhook(
        session,
        rule_id=rule_id,
        settings=settings,
        timestamp=x_cynux_timestamp,
        signature=x_cynux_signature,
        event_id=x_cynux_event_id,
        body=body,
    )
    await session.commit()
    return {"accepted": True, "queued": len(queued)}


@router.get("/rules/{rule_id}/executions", response_model=Page[AutomationExecutionOut])
async def list_rule_executions(
    rule_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
) -> Page[AutomationExecutionOut]:
    rows, total = await automation_service.list_executions_for_rule(
        session, principal, rule_id, limit=pagination.limit, offset=pagination.offset
    )
    return Page.build(
        [AutomationExecutionOut.model_validate(r) for r in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/executions", response_model=Page[AutomationExecutionOut])
async def list_all_executions(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
) -> Page[AutomationExecutionOut]:
    rows, total = await automation_service.list_executions_paged(
        session, principal, limit=pagination.limit, offset=pagination.offset
    )
    return Page.build(
        [AutomationExecutionOut.model_validate(r) for r in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )
