"""Tenant-scoped visual workflow definitions and durable executions."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import DbSession, PaginationDep, PrincipalDep, RedisDep, SettingsDep
from app.schemas.common import Page
from app.schemas.workflow import (
    WorkflowDefinitionIn,
    WorkflowDefinitionOut,
    WorkflowRunDetailOut,
    WorkflowRunOut,
    WorkflowStartIn,
    WorkflowStepOut,
)
from app.services import automation as automation_service
from app.services import workflow as workflow_service

router = APIRouter(prefix="/workflows", tags=["workflows"])


@router.get("", response_model=Page[WorkflowDefinitionOut])
async def list_workflows(
    principal: PrincipalDep, session: DbSession, pagination: PaginationDep
) -> Page[WorkflowDefinitionOut]:
    rows, total = await workflow_service.list_workflows(
        session, principal, limit=pagination.limit, offset=pagination.offset
    )
    return Page.build(
        [WorkflowDefinitionOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("", response_model=WorkflowDefinitionOut, status_code=201)
async def create_workflow(
    body: WorkflowDefinitionIn, principal: PrincipalDep, session: DbSession
) -> WorkflowDefinitionOut:
    row = await workflow_service.create_workflow(session, principal, body)
    await session.commit()
    await session.refresh(row)
    return WorkflowDefinitionOut.model_validate(row)


@router.get("/{workflow_id}", response_model=WorkflowDefinitionOut)
async def get_workflow(
    workflow_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> WorkflowDefinitionOut:
    return WorkflowDefinitionOut.model_validate(
        await workflow_service.get_workflow(session, principal, workflow_id)
    )


@router.put("/{workflow_id}", response_model=WorkflowDefinitionOut)
async def update_workflow(
    workflow_id: uuid.UUID,
    body: WorkflowDefinitionIn,
    principal: PrincipalDep,
    session: DbSession,
) -> WorkflowDefinitionOut:
    row = await workflow_service.update_workflow(session, principal, workflow_id, body)
    await session.commit()
    await session.refresh(row)
    return WorkflowDefinitionOut.model_validate(row)


@router.delete("/{workflow_id}", status_code=204, response_class=Response)
async def delete_workflow(
    workflow_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> Response:
    await workflow_service.delete_workflow(session, principal, workflow_id)
    await session.commit()
    return Response(status_code=204)


@router.post("/{workflow_id}/runs", response_model=WorkflowRunOut, status_code=202)
async def start_workflow(
    workflow_id: uuid.UUID,
    body: WorkflowStartIn,
    principal: PrincipalDep,
    session: DbSession,
) -> WorkflowRunOut:
    row = await workflow_service.start_workflow(
        session,
        principal,
        workflow_id,
        event_key=body.event_key,
        context=body.context,
        dry_run=body.dry_run,
    )
    await session.commit()
    await session.refresh(row)
    return WorkflowRunOut.model_validate(row)


@router.get("/{workflow_id}/runs", response_model=Page[WorkflowRunOut])
async def list_workflow_runs(
    workflow_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
) -> Page[WorkflowRunOut]:
    await workflow_service.get_workflow(session, principal, workflow_id)
    rows, total = await workflow_service.list_workflow_runs(
        session,
        principal,
        workflow_id=workflow_id,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return Page.build(
        [WorkflowRunOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/runs/{run_id}", response_model=WorkflowRunDetailOut)
async def get_workflow_run(
    run_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> WorkflowRunDetailOut:
    row = await workflow_service.get_workflow_run(session, principal, run_id)
    payload = WorkflowRunOut.model_validate(row).model_dump()
    return WorkflowRunDetailOut(
        **payload,
        steps=[WorkflowStepOut.model_validate(step) for step in row.steps],
    )


@router.post("/runs/{run_id}/resume", response_model=WorkflowRunOut)
async def resume_workflow(
    run_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> WorkflowRunOut:
    async def execute_action(
        action: str, config: dict, context: dict, idempotency_key: str
    ) -> dict:
        raw_finding_id = context.get("finding_id")
        finding_id = uuid.UUID(str(raw_finding_id)) if raw_finding_id else None
        payload = {
            "type": action,
            **{key: value for key, value in config.items() if key != "action"},
        }
        return await automation_service.execute_declarative_action(
            session,
            principal,
            finding_id=finding_id,
            action=payload,
            settings=settings,
            redis=redis,
            idempotency_key=idempotency_key,
        )

    row = await workflow_service.resume_workflow(
        session, principal, run_id, action_executor=execute_action
    )
    await session.commit()
    return WorkflowRunOut.model_validate(row)


@router.post("/runs/{run_id}/steps/{node_id}/approve", response_model=WorkflowStepOut)
async def approve_workflow_step(
    run_id: uuid.UUID,
    node_id: str,
    principal: PrincipalDep,
    session: DbSession,
) -> WorkflowStepOut:
    row = await workflow_service.approve_workflow_step(session, principal, run_id, node_id)
    await session.commit()
    return WorkflowStepOut.model_validate(row)


__all__ = ["router"]
