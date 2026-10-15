"""The runtime tool surface is a strict, typed intersection of three authorities."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission, Role
from app.services.context import Principal


class _Input(BaseModel):
    value: str


class _Output(BaseModel):
    value: str


async def _executor(_context: Any, arguments: BaseModel) -> BaseModel:
    return _Output(value=str(arguments.model_dump()["value"]))


def _principal(*permissions: Permission) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=Role.VIEWER,
        permission_override=frozenset(permissions),
    )


def _assignment(
    name: str,
    *,
    version: int = 1,
    approval: str = "never",
    timeout: int = 90,
    calls: int = 8,
) -> SimpleNamespace:
    return SimpleNamespace(
        tool_name=name,
        tool_version=version,
        approval_mode=approval,
        timeout_seconds=timeout,
        per_run_call_limit=calls,
    )


def _version(*assignments: SimpleNamespace, mode: str = "bounded") -> SimpleNamespace:
    return SimpleNamespace(
        tools=list(assignments),
        autonomy_mode=mode,
        max_runtime_seconds=300,
        max_tool_calls=20,
    )


def test_registry_rejects_duplicate_name_and_version() -> None:
    from app.agent.tools.registry import ToolRegistry, ToolSpec

    registry = ToolRegistry()
    spec = ToolSpec(
        name="read_test",
        version=1,
        input_model=_Input,
        output_model=_Output,
        permission=Permission.FINDING_READ,
        side_effect="read",
        approval="never",
        timeout_seconds=30,
        idempotent=True,
        executor=_executor,
    )
    registry.register(spec)

    with pytest.raises(ValueError, match="already registered"):
        registry.register(spec)


def test_default_registry_adapts_existing_actions_and_read_tools() -> None:
    from app.agent.tools.registry import default_tool_registry

    registry = default_tool_registry()

    assert registry.get("read_findings").side_effect == "read"
    assert registry.get("create_jira_ticket").permission == Permission.TICKET_CREATE
    assert registry.get("start_assessment").side_effect == "active_security"


def test_effective_tools_are_permission_agent_and_org_intersection() -> None:
    from app.agent.tools.policy import OrganizationToolPolicy, resolve_effective_tools

    reader = _principal(Permission.FINDING_READ, Permission.ASSET_READ)
    version = _version(
        _assignment("read_findings"),
        _assignment("create_jira_ticket"),
        _assignment("read_assets"),
    )
    policy = resolve_effective_tools(
        reader,
        version,
        OrganizationToolPolicy(disabled_tools=frozenset({"read_assets"})),
    )

    assert set(policy.tools) == {"read_findings"}
    assert policy.rejected["create_jira_ticket"] == "permission"
    assert policy.rejected["read_assets"] == "organization_policy"


def test_limits_only_tighten_and_external_writes_always_require_approval() -> None:
    from app.agent.tools.policy import OrganizationToolPolicy, resolve_effective_tools

    principal = _principal(Permission.TICKET_CREATE)
    version = _version(
        _assignment("create_jira_ticket", approval="never", timeout=240, calls=12)
    )
    policy = resolve_effective_tools(
        principal,
        version,
        OrganizationToolPolicy(max_timeout_seconds=45, max_calls_per_tool=3),
    )
    effective = policy.tools["create_jira_ticket"]

    assert effective.approval == "always"
    assert effective.timeout_seconds == 45
    assert effective.per_run_call_limit == 3


def test_manual_agents_keep_write_capability_but_force_human_approval() -> None:
    from app.agent.tools.policy import OrganizationToolPolicy, resolve_effective_tools

    principal = _principal(Permission.FINDING_REMEDIATE)
    policy = resolve_effective_tools(
        principal,
        _version(_assignment("update_canonical_work"), mode="manual"),
        OrganizationToolPolicy(),
    )

    assert policy.tools["update_canonical_work"].approval == "always"


def test_unknown_tool_versions_are_not_exposed_to_the_model() -> None:
    from app.agent.tools.policy import OrganizationToolPolicy, resolve_effective_tools

    policy = resolve_effective_tools(
        _principal(Permission.FINDING_READ),
        _version(_assignment("read_findings", version=99), _assignment("does_not_exist")),
        OrganizationToolPolicy(),
    )

    assert policy.tools == {}
    assert policy.rejected == {
        "read_findings": "unavailable",
        "does_not_exist": "unavailable",
    }


@pytest.mark.asyncio
async def test_foreign_collection_and_unknown_tool_links_fail_without_disclosure() -> None:
    from app.services.agent_definition import validate_agent_links

    owner = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER
    )

    class _Result:
        def scalars(self) -> _Result:
            return self

        def all(self) -> list[uuid.UUID]:
            return []

    class _Session:
        async def execute(self, _statement: Any) -> _Result:
            return _Result()

    with pytest.raises(ResourceNotFoundError, match="links were not found"):
        await validate_agent_links(
            _Session(),
            owner,
            tool_names=["read_findings"],
            collection_ids=[uuid.uuid4()],
        )
    with pytest.raises(ResourceNotFoundError, match="links were not found"):
        await validate_agent_links(
            _Session(), owner, tool_names=["foreign_tool"], collection_ids=[]
        )
