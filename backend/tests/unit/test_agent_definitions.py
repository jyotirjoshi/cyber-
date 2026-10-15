"""Immutable, tenant-scoped custom agent definition behavior."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Role
from app.db.models.agent_definition import AgentDefinition, AgentDefinitionVersion
from app.schemas.agent_definition import AgentDefinitionCreateIn, AgentVersionCreateIn
from app.services import agent_definition as service
from app.services.context import Principal


class _Result:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        if self.value is None:
            return []
        if isinstance(self.value, list):
            return self.value
        return [self.value]


class _Session:
    def __init__(self, results: Iterable[Any] = ()) -> None:
        self.results = [_Result(value) for value in results]
        self.added: list[Any] = []
        self.statements: list[Any] = []
        self.flush_count = 0

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return self.results.pop(0) if self.results else _Result()

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flush_count += 1


@pytest.fixture
def owner() -> Principal:
    return Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)


@pytest.fixture(autouse=True)
def _disable_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    async def record(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(service.audit_service, "record", record)


def _create_payload(name: str = "Tina") -> AgentDefinitionCreateIn:
    return AgentDefinitionCreateIn(
        name=name,
        role="Vulnerability triager",
        instructions="Use cited evidence and never claim unverified remediation.",
        provider="openai",
        model="gpt-5-mini",
    )


def _version_payload(active: uuid.UUID, instructions: str = "New rules") -> AgentVersionCreateIn:
    return AgentVersionCreateIn(
        expected_active_version_id=active,
        role="Vulnerability triager",
        instructions=instructions,
        provider="openai",
        model="gpt-5-mini",
    )


@pytest.mark.asyncio
async def test_create_agent_persists_identity_and_first_immutable_version(owner: Principal) -> None:
    """Dropping the initial version link would leave a configurable agent unexecutable."""
    session = _Session(results=[None])

    agent = await service.create_agent(session, owner, _create_payload())

    version = next(row for row in session.added if isinstance(row, AgentDefinitionVersion))
    assert agent.organization_id == owner.organization_id
    assert version.organization_id == owner.organization_id
    assert agent.active_version_id == version.id
    assert agent.version_count == 1
    assert len(version.configuration_digest) == 64


@pytest.mark.asyncio
async def test_edit_creates_new_version_without_mutating_previous(owner: Principal) -> None:
    """Updating the old row would rewrite the behavior recorded in historical runs."""
    first_id = uuid.uuid4()
    agent = AgentDefinition(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        name="Tina",
        active_version_id=first_id,
        version_count=1,
        is_enabled=True,
    )
    session = _Session(results=[agent])

    second = await service.create_agent_version(
        session, owner, agent.id, _version_payload(first_id)
    )

    assert second.id != first_id
    assert second.version == 2
    assert second.instructions == "New rules"
    assert agent.active_version_id == second.id
    assert agent.version_count == 2


def test_invalid_budget_is_rejected_before_database_work() -> None:
    """A zero parallel-task budget would produce runs that can never make progress."""
    with pytest.raises(ValidationError):
        AgentVersionCreateIn(
            expected_active_version_id=uuid.uuid4(),
            role="Triager",
            instructions="Triage",
            provider="openai",
            model="gpt-5-mini",
            max_parallel_tasks=0,
        )


@pytest.mark.asyncio
async def test_duplicate_name_returns_conflict(owner: Principal) -> None:
    """Relying only on an IntegrityError would leak persistence details to the API."""
    session = _Session(results=[AgentDefinition(id=uuid.uuid4(), organization_id=owner.organization_id, name="Tina")])

    with pytest.raises(ConflictError):
        await service.create_agent(session, owner, _create_payload())

    assert session.added == []


@pytest.mark.asyncio
async def test_stale_expected_active_version_cannot_overwrite_newer_edit(owner: Principal) -> None:
    """Concurrent editors must not silently replace each other's active version."""
    agent = AgentDefinition(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        name="Tina",
        active_version_id=uuid.uuid4(),
        version_count=2,
        is_enabled=True,
    )
    session = _Session(results=[agent])

    with pytest.raises(ConflictError, match="stale"):
        await service.create_agent_version(
            session, owner, agent.id, _version_payload(uuid.uuid4())
        )

    assert session.added == []


@pytest.mark.asyncio
async def test_disabled_agent_cannot_receive_a_new_version(owner: Principal) -> None:
    """Editing a disabled identity must not reactivate it indirectly."""
    active = uuid.uuid4()
    agent = AgentDefinition(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        name="Tina",
        active_version_id=active,
        version_count=1,
        is_enabled=False,
    )
    session = _Session(results=[agent])

    with pytest.raises(ConflictError, match="disabled"):
        await service.create_agent_version(session, owner, agent.id, _version_payload(active))


@pytest.mark.asyncio
async def test_disable_agent_preserves_active_version_history(owner: Principal) -> None:
    """Disabling an identity must not delete or rewrite its active version reference."""
    active = uuid.uuid4()
    agent = AgentDefinition(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        name="Tina",
        active_version_id=active,
        version_count=1,
        is_enabled=True,
    )
    session = _Session(results=[agent])

    disabled = await service.disable_agent(session, owner, agent.id)

    assert disabled.is_enabled is False
    assert disabled.active_version_id == active


@pytest.mark.asyncio
async def test_foreign_agent_id_is_indistinguishable_from_missing(owner: Principal) -> None:
    """Removing the organization predicate would turn IDs into a cross-tenant oracle."""
    session = _Session(results=[None])

    with pytest.raises(ResourceNotFoundError):
        await service.create_agent_version(
            session, owner, uuid.uuid4(), _version_payload(uuid.uuid4())
        )

    assert "organization_id" in str(session.statements[0])


@pytest.mark.asyncio
async def test_foreign_collection_link_is_rejected_without_disclosure(owner: Principal) -> None:
    """A version must not attach a collection merely because its UUID is valid."""
    foreign_collection = uuid.uuid4()
    payload = _create_payload().model_copy(update={"collection_ids": [foreign_collection]})
    session = _Session(results=[None, []])

    with pytest.raises(ResourceNotFoundError):
        await service.create_agent(session, owner, payload)

    assert all(not isinstance(row, AgentDefinitionVersion) for row in session.added)


@pytest.mark.asyncio
async def test_effective_version_is_pinned_to_active_id(owner: Principal) -> None:
    """Selecting the highest version instead of active_version_id breaks rollback."""
    active_id = uuid.uuid4()
    agent = AgentDefinition(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        name="Tina",
        active_version_id=active_id,
        version_count=3,
        is_enabled=True,
    )
    version = AgentDefinitionVersion(
        id=active_id,
        organization_id=owner.organization_id,
        agent_definition_id=agent.id,
        version=2,
        role="Triager",
        instructions="Pinned",
        provider="openai",
        model="gpt-5-mini",
        configuration_digest="a" * 64,
    )
    session = _Session(results=[agent, version])

    selected = await service.get_effective_agent_version(session, owner, agent.id)

    assert selected.id == active_id
