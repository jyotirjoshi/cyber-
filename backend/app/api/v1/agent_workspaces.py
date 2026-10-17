"""Durable evidence workspaces for governed multi-agent runs."""

from __future__ import annotations

import uuid
from contextlib import suppress
from typing import Annotated, Literal

from fastapi import APIRouter, File, Form, UploadFile, status

from app.api.deps import DbSession, PaginationDep, PrincipalDep, StorageDep
from app.core.errors import ConflictError, InvalidConfigurationError
from app.schemas.agent_workspace import (
    AgentWorkspaceCreateIn,
    AgentWorkspaceOut,
    AgentWorkspaceStatusUpdateIn,
    WorkspaceArtifactOut,
    WorkspaceCredentialReferenceCreateIn,
    WorkspaceCredentialReferenceOut,
    WorkspaceExecutionCreateIn,
    WorkspaceExecutionOut,
    WorkspaceRecordOut,
    WorkspaceRecordPutIn,
)
from app.schemas.common import Page
from app.services import agent_workspace as workspace_service

router = APIRouter(prefix="/agent-workspaces", tags=["agent-workspaces"])
_MAX_ARTIFACT_BYTES = 25 * 1024 * 1024


@router.get("", response_model=Page[AgentWorkspaceOut])
async def list_workspaces(
    principal: PrincipalDep, session: DbSession, pagination: PaginationDep
) -> Page[AgentWorkspaceOut]:
    rows, total = await workspace_service.list_workspaces(
        session, principal, limit=pagination.limit, offset=pagination.offset
    )
    return Page.build(
        [AgentWorkspaceOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("", response_model=AgentWorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    payload: AgentWorkspaceCreateIn, principal: PrincipalDep, session: DbSession
) -> AgentWorkspaceOut:
    row = await workspace_service.create_workspace(session, principal, payload)
    await session.commit()
    await session.refresh(row)
    return AgentWorkspaceOut.model_validate(row)


@router.get("/{workspace_id}", response_model=AgentWorkspaceOut)
async def get_workspace(
    workspace_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> AgentWorkspaceOut:
    row = await workspace_service.get_workspace(session, principal, workspace_id)
    return AgentWorkspaceOut.model_validate(row)


@router.patch("/{workspace_id}/status", response_model=AgentWorkspaceOut)
async def update_workspace_status(
    workspace_id: uuid.UUID,
    payload: AgentWorkspaceStatusUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AgentWorkspaceOut:
    row = await workspace_service.update_workspace_status(
        session,
        principal,
        workspace_id,
        status=payload.status,
        expected_version=payload.expected_version,
    )
    await session.commit()
    await session.refresh(row)
    return AgentWorkspaceOut.model_validate(row)


@router.post(
    "/{workspace_id}/credential-references",
    response_model=WorkspaceCredentialReferenceOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_credential_reference(
    workspace_id: uuid.UUID,
    payload: WorkspaceCredentialReferenceCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> WorkspaceCredentialReferenceOut:
    row = await workspace_service.add_credential_reference(
        session, principal, workspace_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return WorkspaceCredentialReferenceOut.model_validate(row)


@router.put("/{workspace_id}/records", response_model=WorkspaceRecordOut)
async def put_record(
    workspace_id: uuid.UUID,
    payload: WorkspaceRecordPutIn,
    principal: PrincipalDep,
    session: DbSession,
) -> WorkspaceRecordOut:
    row = await workspace_service.put_record(session, principal, workspace_id, payload)
    await session.commit()
    await session.refresh(row)
    return WorkspaceRecordOut.model_validate(row)


@router.post(
    "/{workspace_id}/executions",
    response_model=WorkspaceExecutionOut,
    status_code=status.HTTP_201_CREATED,
)
async def bind_execution(
    workspace_id: uuid.UUID,
    payload: WorkspaceExecutionCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> WorkspaceExecutionOut:
    row = await workspace_service.create_execution_record(
        session, principal, workspace_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return WorkspaceExecutionOut.model_validate(row)


@router.post(
    "/{workspace_id}/artifacts/upload",
    response_model=WorkspaceArtifactOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_artifact(
    workspace_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
    file: Annotated[UploadFile, File()],
    kind: Annotated[
        Literal["input", "output", "screenshot", "har", "console", "report", "evidence", "archive"],
        Form(),
    ] = "evidence",
    task_id: Annotated[uuid.UUID | None, Form()] = None,
    is_evidence: Annotated[bool, Form()] = True,
) -> WorkspaceArtifactOut:
    # Fail before reading/uploading if the workspace is inaccessible or inactive.
    workspace = await workspace_service.get_workspace(session, principal, workspace_id)
    if workspace.status != "active":
        raise ConflictError("Agent workspace is not active")
    artifact_id = uuid.uuid4()
    key = workspace_service.workspace_artifact_key(
        principal.organization_id,
        workspace_id,
        artifact_id,
        file.filename or "artifact",
    )
    stored = None
    try:
        data = await file.read(_MAX_ARTIFACT_BYTES + 1)
        if len(data) > _MAX_ARTIFACT_BYTES:
            raise InvalidConfigurationError(
                "agent workspace artifact exceeds 25 MiB",
                user_message="The artifact is larger than the 25 MiB upload limit.",
            )
        try:
            workspace_service.ensure_quota(
                used_bytes=workspace.used_bytes,
                incoming_bytes=len(data),
                maximum_bytes=workspace.max_bytes,
            )
        except ValueError as exc:
            raise ConflictError(str(exc)) from exc
        stored = await storage.put_bytes(
            key,
            data,
            content_type=file.content_type or "application/octet-stream",
            organization_id=principal.organization_id,
            metadata={"workspace_id": str(workspace_id), "kind": kind},
        )
        try:
            row = await workspace_service.add_artifact(
                session,
                principal,
                workspace_id,
                artifact_id=artifact_id,
                task_id=task_id,
                kind=kind,
                filename=file.filename or "artifact",
                storage_key=stored.storage_key,
                content_type=stored.content_type,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                is_evidence=is_evidence,
            )
        except ValueError as exc:
            raise ConflictError(str(exc)) from exc
        await session.commit()
        await session.refresh(row)
        return WorkspaceArtifactOut.model_validate(row)
    except BaseException:
        if stored is not None:
            with suppress(Exception):
                await storage.delete(key, organization_id=principal.organization_id)
        raise
    finally:
        await file.close()


@router.get("/{workspace_id}/evidence-export")
async def export_evidence(
    workspace_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> dict[str, object]:
    """Export a reproducibility manifest without object keys or credential material."""
    return await workspace_service.workspace_manifest(
        session, principal, workspace_id
    )


__all__ = ["router"]
