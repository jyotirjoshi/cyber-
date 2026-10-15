"""Rollout controls for custom agents and first-party knowledge."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.api.deps import require_custom_agents, require_internal_knowledge
from app.core.config import Settings
from app.core.errors import ResourceNotFoundError


@pytest.mark.asyncio
async def test_disabled_custom_agents_cannot_resume_pinned_conversation() -> None:
    from app.db.enums import Role
    from app.services.agent_chat import create_custom_reply
    from app.services.context import Principal

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    with pytest.raises(ResourceNotFoundError):
        await create_custom_reply(
            None,
            organization_id=principal.organization_id,
            conversation_id=uuid.uuid4(),
            agent_version_id=uuid.uuid4(),
            gateway=None,
            principal=principal,
            settings=Settings(_env_file=None, features={"custom_agents": False}),
        )


def test_rollout_settings_are_bounded_and_enabled_by_default() -> None:
    settings = Settings(_env_file=None)

    assert settings.features.custom_agents is True
    assert settings.features.internal_knowledge is True
    assert settings.knowledge.embedding_dimensions == 1536
    assert 1 <= settings.knowledge.indexing_concurrency <= 16


@pytest.mark.asyncio
async def test_disabled_pinned_session_rejects_message_before_any_write(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.api.v1 import agent as route
    from app.db.enums import Role
    from app.schemas.agent import AgentMessageIn
    from app.services.context import Principal

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session_id = uuid.uuid4()

    async def resolve(*args):
        return SimpleNamespace(id=session_id, agent_version_id=uuid.uuid4()), False

    monkeypatch.setattr(route, "_resolve_conversation", resolve)
    with pytest.raises(ResourceNotFoundError):
        await route.post_message(
            AgentMessageIn(session_id=session_id, content="Continue triage"),
            principal, None, None, None,
            Settings(_env_file=None, features={"custom_agents": False}), None,
        )


def test_feature_guards_hide_disabled_surfaces() -> None:
    settings = Settings(
        _env_file=None,
        features={"custom_agents": False, "internal_knowledge": False},
    )

    with pytest.raises(ResourceNotFoundError, match="custom agents are disabled"):
        require_custom_agents(settings)
    with pytest.raises(ResourceNotFoundError, match="internal knowledge is disabled"):
        require_internal_knowledge(settings)


@pytest.mark.parametrize(
    ("knowledge", "field"),
    [
        ({"indexing_concurrency": 0}, "indexing_concurrency"),
        ({"max_upload_bytes": 0}, "max_upload_bytes"),
        ({"max_document_tokens": 999}, "max_document_tokens"),
        ({"max_storage_bytes_per_collection": 1024}, "max_storage_bytes_per_collection"),
        ({"embedding_dimensions": 1535}, "embedding_dimensions"),
    ],
)
def test_knowledge_rollout_limits_reject_unsafe_values(
    knowledge: dict[str, int], field: str
) -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None, knowledge=knowledge)

    assert field in str(exc.value)
