"""Durable agent workspaces preserve quotas and reproducibility without secrets."""

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.agent_workspace import (
    WorkspaceCredentialReferenceCreateIn,
    WorkspaceExecutionCreateIn,
    WorkspaceRecordPutIn,
)
from app.services.agent_workspace import (
    command_digest,
    ensure_quota,
    workspace_artifact_key,
)


def test_workspace_artifact_key_is_tenant_and_workspace_scoped() -> None:
    organization_id = uuid.UUID(int=1)
    workspace_id = uuid.UUID(int=2)
    artifact_id = uuid.UUID(int=3)
    assert workspace_artifact_key(
        organization_id, workspace_id, artifact_id, "../console output.json"
    ) == (
        f"org/{organization_id}/agent-workspaces/{workspace_id}/artifacts/"
        f"{artifact_id}/console_output.json"
    )


def test_quota_rejects_single_and_cumulative_overflow() -> None:
    ensure_quota(used_bytes=10, incoming_bytes=20, maximum_bytes=30)
    with pytest.raises(ValueError, match="quota"):
        ensure_quota(used_bytes=11, incoming_bytes=20, maximum_bytes=30)
    with pytest.raises(ValueError, match="quota"):
        ensure_quota(used_bytes=0, incoming_bytes=31, maximum_bytes=30)


def test_command_digest_is_canonical_and_does_not_store_command_text() -> None:
    first = command_digest(
        execution_kind="shell",
        executable="nuclei",
        arguments=["-u", "https://example.com"],
        environment_names=["TOKEN", "REGION"],
    )
    second = command_digest(
        execution_kind="shell",
        executable="nuclei",
        arguments=["-u", "https://example.com"],
        environment_names=["REGION", "TOKEN"],
    )
    assert first == second
    assert len(first) == 64
    assert "example" not in first


def test_credential_references_never_accept_secret_material() -> None:
    with pytest.raises(ValidationError):
        WorkspaceCredentialReferenceCreateIn(
            integration_id=uuid.uuid4(),
            label="Scanner token",
            allowed_tools=["nuclei"],
            secret="do-not-store",
        )


def test_shared_workspace_records_are_bounded() -> None:
    record = WorkspaceRecordPutIn(namespace="targets", key="primary", value={"host": "api.example.com"})
    assert record.key == "primary"
    with pytest.raises(ValidationError):
        WorkspaceRecordPutIn(namespace="targets", key="x", value={"blob": "x" * 70_000})


def test_execution_environment_accepts_names_not_secret_assignments() -> None:
    valid = WorkspaceExecutionCreateIn(
        task_id=uuid.uuid4(),
        approval_id=uuid.uuid4(),
        execution_kind="shell",
        executable="nuclei",
        environment_names=["TOKEN", "AWS_REGION"],
    )
    assert valid.environment_names == ["AWS_REGION", "TOKEN"]
    with pytest.raises(ValidationError):
        WorkspaceExecutionCreateIn(
            task_id=uuid.uuid4(),
            approval_id=uuid.uuid4(),
            execution_kind="shell",
            executable="nuclei --unsafe",
            environment_names=["TOKEN=secret"],
        )
