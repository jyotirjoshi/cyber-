"""Tenant-safe durable workspaces attached to governed agent runs.

Workspace executions are provenance records for an existing ``AgentTask``.  They do
not provide an alternative command runner: the task scheduler remains the only path
that can dispatch a tool and the referenced approval remains its authority.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import AgentTaskStatus, ApprovalDecision, Permission
from app.db.models.agent import AgentRun
from app.db.models.agent_task import AgentTask
from app.db.models.agent_workspace import (
    AgentWorkspace,
    AgentWorkspaceArtifact,
    AgentWorkspaceCredentialReference,
    AgentWorkspaceExecution,
    AgentWorkspaceRecord,
)
from app.db.models.assessment import Approval
from app.db.models.integration import Integration
from app.db.repository import tenant_select
from app.integrations.storage import MAX_KEY_LENGTH, sanitize_segment, tenant_prefix
from app.schemas.agent_workspace import (
    AgentWorkspaceCreateIn,
    WorkspaceCredentialReferenceCreateIn,
    WorkspaceExecutionCreateIn,
    WorkspaceRecordPutIn,
)
from app.services import audit as audit_service
from app.services.context import Principal

_GRANTED = {
    ApprovalDecision.APPROVED.value,
    ApprovalDecision.APPROVED_ALL.value,
    ApprovalDecision.CUSTOMIZED.value,
}
_ACTIVE_TASKS = {
    AgentTaskStatus.READY.value,
    AgentTaskStatus.QUEUED.value,
    AgentTaskStatus.RUNNING.value,
    AgentTaskStatus.COMPLETED.value,
}


def workspace_artifact_key(
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID,
    artifact_id: uuid.UUID,
    filename: str,
) -> str:
    """Return an immutable key contained by both tenant and workspace."""
    return (
        f"{tenant_prefix(organization_id)}agent-workspaces/{workspace_id}/"
        f"artifacts/{artifact_id}/{sanitize_segment(filename)}"
    )[:MAX_KEY_LENGTH]


def ensure_quota(*, used_bytes: int, incoming_bytes: int, maximum_bytes: int) -> None:
    if used_bytes < 0 or incoming_bytes < 0 or maximum_bytes <= 0:
        raise ValueError("workspace quota values must be non-negative")
    if incoming_bytes > maximum_bytes or used_bytes + incoming_bytes > maximum_bytes:
        raise ValueError("workspace storage quota exceeded")


def command_digest(
    *,
    execution_kind: str,
    executable: str,
    arguments: Sequence[str],
    environment_names: Sequence[str],
) -> str:
    """Fingerprint an execution deterministically without returning command text."""
    canonical = json.dumps(
        {
            "execution_kind": execution_kind,
            "executable": executable,
            "arguments": list(arguments),
            "environment_names": sorted(set(environment_names)),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


async def get_workspace(
    session: AsyncSession,
    principal: Principal,
    workspace_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> AgentWorkspace:
    principal.require(Permission.AGENT_CHAT)
    query = tenant_select(AgentWorkspace, principal.organization_id).where(
        AgentWorkspace.id == workspace_id
    )
    if for_update:
        query = query.with_for_update()
    row = await session.scalar(query)
    if row is None:
        raise ResourceNotFoundError("Agent workspace not found")
    return row


async def list_workspaces(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[AgentWorkspace], int]:
    principal.require(Permission.AGENT_CHAT)
    scope = AgentWorkspace.organization_id == principal.organization_id
    total = await session.scalar(select(func.count()).select_from(AgentWorkspace).where(scope))
    rows = list(
        (
            await session.scalars(
                select(AgentWorkspace)
                .where(scope)
                .order_by(AgentWorkspace.created_at.desc(), AgentWorkspace.id.desc())
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        ).all()
    )
    return rows, int(total or 0)


async def create_workspace(
    session: AsyncSession, principal: Principal, payload: AgentWorkspaceCreateIn
) -> AgentWorkspace:
    principal.require(Permission.AGENT_CHAT)
    run = await session.scalar(
        tenant_select(AgentRun, principal.organization_id).where(AgentRun.id == payload.run_id)
    )
    if run is None:
        raise ResourceNotFoundError("Agent run not found")
    existing = await session.scalar(
        tenant_select(AgentWorkspace, principal.organization_id).where(
            AgentWorkspace.run_id == payload.run_id
        )
    )
    if existing is not None:
        raise ConflictError("The agent run already has a workspace")
    row = AgentWorkspace(
        organization_id=principal.organization_id,
        run_id=run.id,
        name=payload.name,
        max_bytes=payload.max_bytes,
        manifest={"schema_version": "v1", "run_thread_id": run.thread_id},
        expires_at=_now() + dt.timedelta(hours=payload.ttl_hours),
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="agent_workspace.create",
        principal=principal,
        resource_type="agent_workspace",
        resource_id=row.id,
        detail={"run_id": str(row.run_id), "max_bytes": row.max_bytes},
    )
    return row


def _assert_active(workspace: AgentWorkspace) -> None:
    if workspace.status != "active" or workspace.expires_at <= _now():
        raise ConflictError("Agent workspace is not active")


async def add_credential_reference(
    session: AsyncSession,
    principal: Principal,
    workspace_id: uuid.UUID,
    payload: WorkspaceCredentialReferenceCreateIn,
) -> AgentWorkspaceCredentialReference:
    principal.require(Permission.AGENT_CHAT, Permission.INTEGRATION_READ)
    workspace = await get_workspace(session, principal, workspace_id)
    _assert_active(workspace)
    integration = await session.scalar(
        tenant_select(Integration, principal.organization_id).where(
            Integration.id == payload.integration_id,
            Integration.is_enabled.is_(True),
        )
    )
    if integration is None:
        raise ResourceNotFoundError("Integration not found")
    row = AgentWorkspaceCredentialReference(
        organization_id=principal.organization_id,
        workspace_id=workspace.id,
        integration_id=integration.id,
        label=payload.label,
        allowed_tools=payload.allowed_tools,
        expires_at=payload.expires_at,
    )
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="agent_workspace.credential_reference.add",
        principal=principal,
        resource_type="agent_workspace_credential_reference",
        resource_id=row.id,
        detail={"workspace_id": str(workspace.id), "integration_id": str(integration.id)},
    )
    return row


async def update_workspace_status(
    session: AsyncSession,
    principal: Principal,
    workspace_id: uuid.UUID,
    *,
    status: str,
    expected_version: int,
) -> AgentWorkspace:
    workspace = await get_workspace(session, principal, workspace_id, for_update=True)
    if workspace.version != expected_version:
        raise ConflictError("Agent workspace changed; reload before retrying")
    allowed = {
        "active": {"suspended", "closed"},
        "suspended": {"active", "closed"},
        "closed": set(),
        "expired": set(),
    }
    if status != workspace.status and status not in allowed.get(workspace.status, set()):
        raise ConflictError(
            f"Invalid agent workspace transition from {workspace.status} to {status}"
        )
    if status != workspace.status:
        previous = workspace.status
        workspace.status = status
        workspace.version += 1
        if status == "closed":
            workspace.closed_at = _now()
        await audit_service.record(
            session,
            action="agent_workspace.status.change",
            principal=principal,
            resource_type="agent_workspace",
            resource_id=workspace.id,
            detail={"from": previous, "to": status},
        )
    return workspace


async def put_record(
    session: AsyncSession,
    principal: Principal,
    workspace_id: uuid.UUID,
    payload: WorkspaceRecordPutIn,
) -> AgentWorkspaceRecord:
    workspace = await get_workspace(session, principal, workspace_id, for_update=True)
    _assert_active(workspace)
    if payload.updated_by_task_id is not None:
        task = await session.scalar(
            tenant_select(AgentTask, principal.organization_id).where(
                AgentTask.id == payload.updated_by_task_id,
                AgentTask.run_id == workspace.run_id,
            )
        )
        if task is None:
            raise ResourceNotFoundError("Agent task not found")
    row = await session.scalar(
        tenant_select(AgentWorkspaceRecord, principal.organization_id)
        .where(
            AgentWorkspaceRecord.workspace_id == workspace.id,
            AgentWorkspaceRecord.namespace == payload.namespace,
            AgentWorkspaceRecord.key == payload.key,
        )
        .with_for_update()
    )
    if row is None:
        if payload.expected_version is not None:
            raise ConflictError("Workspace record does not exist")
        row = AgentWorkspaceRecord(
            organization_id=principal.organization_id,
            workspace_id=workspace.id,
            namespace=payload.namespace,
            key=payload.key,
            value=payload.value,
            updated_by_task_id=payload.updated_by_task_id,
        )
        session.add(row)
    else:
        if payload.expected_version is not None and row.version != payload.expected_version:
            raise ConflictError("Workspace record changed; reload before retrying")
        row.value = payload.value
        row.updated_by_task_id = payload.updated_by_task_id
        row.version += 1
    workspace.version += 1
    await session.flush()
    return row


async def create_execution_record(
    session: AsyncSession,
    principal: Principal,
    workspace_id: uuid.UUID,
    payload: WorkspaceExecutionCreateIn,
) -> AgentWorkspaceExecution:
    """Bind reproducibility metadata to a scheduler-owned, human-approved task."""
    workspace = await get_workspace(session, principal, workspace_id, for_update=True)
    _assert_active(workspace)
    task = await session.scalar(
        tenant_select(AgentTask, principal.organization_id).where(
            AgentTask.id == payload.task_id,
            AgentTask.run_id == workspace.run_id,
        )
    )
    if task is None:
        raise ResourceNotFoundError("Agent task not found")
    if task.status not in _ACTIVE_TASKS:
        raise ConflictError("Agent task is not approved for execution")
    approval = await session.scalar(
        tenant_select(Approval, principal.organization_id).where(
            Approval.id == payload.approval_id,
            Approval.agent_task_id == task.id,
            Approval.agent_run_id == workspace.run_id,
        )
    )
    if approval is None or approval.decision not in _GRANTED or approval.resolved_by_id is None:
        raise ConflictError("A human-granted task approval is required")
    if approval.expires_at is not None and approval.expires_at <= _now():
        raise ConflictError("The task approval has expired")
    # Preserve only option names; values can contain targets, tokens, or customer data.
    argument_names = [item for item in payload.arguments if item.startswith("-")][:100]
    environment_names = sorted(set(payload.environment_names))
    row = AgentWorkspaceExecution(
        organization_id=principal.organization_id,
        workspace_id=workspace.id,
        task_id=task.id,
        approval_id=approval.id,
        execution_kind=payload.execution_kind,
        status="completed" if task.status == AgentTaskStatus.COMPLETED.value else "queued",
        executable=payload.executable,
        argument_names=argument_names,
        environment_names=environment_names,
        command_digest=command_digest(
            execution_kind=payload.execution_kind,
            executable=payload.executable,
            arguments=payload.arguments,
            environment_names=environment_names,
        ),
        result_summary=dict(task.output_summary),
        started_at=task.started_at,
        completed_at=task.settled_at,
    )
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="agent_workspace.execution.bind",
        principal=principal,
        resource_type="agent_workspace_execution",
        resource_id=row.id,
        detail={"workspace_id": str(workspace.id), "task_id": str(task.id)},
    )
    return row


async def add_artifact(
    session: AsyncSession,
    principal: Principal,
    workspace_id: uuid.UUID,
    *,
    artifact_id: uuid.UUID,
    task_id: uuid.UUID | None,
    kind: str,
    filename: str,
    storage_key: str,
    content_type: str,
    size_bytes: int,
    sha256: str,
    is_evidence: bool,
) -> AgentWorkspaceArtifact:
    workspace = await get_workspace(session, principal, workspace_id, for_update=True)
    _assert_active(workspace)
    ensure_quota(
        used_bytes=workspace.used_bytes,
        incoming_bytes=size_bytes,
        maximum_bytes=workspace.max_bytes,
    )
    expected = f"{tenant_prefix(principal.organization_id)}agent-workspaces/{workspace.id}/"
    if not storage_key.startswith(expected):
        raise ConflictError("Artifact storage reference is outside this workspace")
    if task_id is not None:
        task = await session.scalar(
            tenant_select(AgentTask, principal.organization_id).where(
                AgentTask.id == task_id, AgentTask.run_id == workspace.run_id
            )
        )
        if task is None:
            raise ResourceNotFoundError("Agent task not found")
    row = AgentWorkspaceArtifact(
        id=artifact_id,
        organization_id=principal.organization_id,
        workspace_id=workspace.id,
        task_id=task_id,
        kind=kind,
        filename=filename,
        storage_key=storage_key,
        content_type=content_type,
        size_bytes=size_bytes,
        sha256=sha256,
        is_evidence=is_evidence,
    )
    session.add(row)
    workspace.used_bytes += size_bytes
    workspace.version += 1
    await session.flush()
    await audit_service.record(
        session,
        action="agent_workspace.artifact.add",
        principal=principal,
        resource_type="agent_workspace_artifact",
        resource_id=row.id,
        detail={"workspace_id": str(workspace.id), "kind": kind, "size_bytes": size_bytes},
    )
    return row


async def workspace_manifest(
    session: AsyncSession, principal: Principal, workspace_id: uuid.UUID
) -> dict[str, object]:
    workspace = await get_workspace(session, principal, workspace_id)
    artifacts = list(
        (
            await session.scalars(
                tenant_select(AgentWorkspaceArtifact, principal.organization_id)
                .where(AgentWorkspaceArtifact.workspace_id == workspace.id)
                .order_by(AgentWorkspaceArtifact.created_at, AgentWorkspaceArtifact.id)
            )
        ).all()
    )
    records = list(
        (
            await session.scalars(
                tenant_select(AgentWorkspaceRecord, principal.organization_id)
                .where(AgentWorkspaceRecord.workspace_id == workspace.id)
                .order_by(AgentWorkspaceRecord.namespace, AgentWorkspaceRecord.key)
            )
        ).all()
    )
    executions = list(
        (
            await session.scalars(
                tenant_select(AgentWorkspaceExecution, principal.organization_id)
                .where(AgentWorkspaceExecution.workspace_id == workspace.id)
                .order_by(AgentWorkspaceExecution.created_at, AgentWorkspaceExecution.id)
            )
        ).all()
    )
    return {
        "schema_version": "v1",
        "workspace": {
            "id": str(workspace.id),
            "run_id": str(workspace.run_id),
            "name": workspace.name,
            "status": workspace.status,
            "used_bytes": workspace.used_bytes,
            "max_bytes": workspace.max_bytes,
            "expires_at": workspace.expires_at.isoformat(),
        },
        "artifacts": [
            {
                "id": str(item.id),
                "task_id": str(item.task_id) if item.task_id else None,
                "kind": item.kind,
                "filename": item.filename,
                "content_type": item.content_type,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
                "is_evidence": item.is_evidence,
            }
            for item in artifacts
        ],
        "records": [
            {
                "namespace": item.namespace,
                "key": item.key,
                "value": item.value,
                "version": item.version,
            }
            for item in records
        ],
        "executions": [
            {
                "id": str(item.id),
                "task_id": str(item.task_id),
                "approval_id": str(item.approval_id),
                "kind": item.execution_kind,
                "status": item.status,
                "executable": item.executable,
                "argument_names": item.argument_names,
                "environment_names": item.environment_names,
                "command_digest": item.command_digest,
                "result_summary": item.result_summary,
            }
            for item in executions
        ],
    }


__all__ = [
    "add_artifact",
    "add_credential_reference",
    "command_digest",
    "create_execution_record",
    "create_workspace",
    "ensure_quota",
    "get_workspace",
    "list_workspaces",
    "put_record",
    "update_workspace_status",
    "workspace_artifact_key",
    "workspace_manifest",
]
