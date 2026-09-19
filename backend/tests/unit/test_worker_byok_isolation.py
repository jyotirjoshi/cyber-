"""The worker must preserve tenant-scoped BYOK credentials across queued runs."""

from __future__ import annotations

from contextlib import asynccontextmanager
import uuid

import pytest

import app.agent.runner as runner_module
from app.agent.runner import AgentRunner
from app.agent.registry import AgentDeps
from app.core.config import Settings
from app.db.enums import IntegrationKind, Role
from app.llm.gateway import LLMGateway
from app.services.context import ACTOR_WORKER


@pytest.mark.asyncio
async def test_worker_graph_resolves_llm_settings_for_the_run_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        db={"password": "database-password"},
        security={
            "jwt_secret": "a" * 32,
            "credential_encryption_key": "dGVzdC1vbmx5LWtleS0zMi1ieXRlcy1sb25nLXh4eHg=",
        },
    )
    runner = object.__new__(AgentRunner)
    runner._deps = AgentDeps(
        settings=settings,
        gateway=LLMGateway(settings),
        storage=object(),
        runner=object(),
        redis=object(),
        event_bus=object(),
    )
    runner._checkpointer = object()
    organization_id = uuid.uuid4()
    captured: dict[str, object] = {}

    @asynccontextmanager
    async def fake_session_scope(_settings: Settings):
        yield object()

    async def fake_resolve_settings(session: object, principal: object, kind: object, **kwargs: object) -> Settings:
        captured.update({"session": session, "principal": principal, "kind": kind})
        return settings

    graph = object()

    def fake_build_graph(deps: object, checkpointer: object) -> object:
        captured.update({"deps": deps, "checkpointer": checkpointer})
        return graph

    monkeypatch.setattr(runner_module, "session_scope", fake_session_scope)
    monkeypatch.setattr(runner_module.integration_service, "resolve_settings", fake_resolve_settings)
    monkeypatch.setattr(runner_module, "build_graph", fake_build_graph)

    assert await runner._graph_for_organization(organization_id) is graph
    principal = captured["principal"]
    assert getattr(principal, "organization_id") == organization_id
    assert getattr(principal, "role") is Role.VIEWER
    assert getattr(principal, "actor_type") == ACTOR_WORKER
    assert captured["kind"] is IntegrationKind.LLM
    assert getattr(captured["deps"], "gateway")._settings is settings
