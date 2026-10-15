"""Kind-only integration flows select an enabled connection when one exists."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.core.crypto import Secret
from app.db.enums import IntegrationKind, Role
from app.services.context import Principal


@pytest.mark.asyncio
async def test_kind_lookup_prefers_enabled_connection_over_older_disabled_one() -> None:
    from app.services.integration import find_integration

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    disabled = SimpleNamespace(kind="github", is_usable=False)
    enabled = SimpleNamespace(kind="github", is_usable=True)

    class _Result:
        def scalar_one_or_none(self):
            return disabled

        def scalars(self):
            return self

        def all(self):
            return [disabled, enabled]

    class _Session:
        async def execute(self, statement):
            self.statement = statement
            return _Result()

    session = _Session()
    assert await find_integration(session, principal, IntegrationKind.GITHUB) is enabled
    params = session.statement.compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in params


@pytest.mark.asyncio
async def test_configuration_preflight_does_not_mark_credential_used(monkeypatch) -> None:
    from app.services import integration as service

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    credential = SimpleNamespace(
        id=uuid.uuid4(),
        name="api_token",
        ciphertext=b"cipher",
        key_version=1,
        last_used_at=None,
    )
    integration = SimpleNamespace(
        kind_enum=IntegrationKind.GITHUB,
        is_usable=True,
        name="GitHub",
        credentials=[credential],
        base_url=None,
        config={"organization": "acme"},
    )

    class _Session:
        async def execute(self, _statement):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [integration]))

    monkeypatch.setattr(service, "_decrypt", lambda *_args, **_kwargs: Secret("test-token"))
    scoped = await service.resolve_settings(
        _Session(),
        principal,
        IntegrationKind.GITHUB,
        settings=Settings(github={"api_token": None}),
        require=True,
        mark_used=False,
    )
    assert scoped.github.api_token.get_secret_value() == "test-token"
    assert scoped.github.organization == "acme"
    assert credential.last_used_at is None


@pytest.mark.asyncio
async def test_llm_integration_ping_runs_a_bounded_completion_and_closes(monkeypatch) -> None:
    from app.services import integration as service

    calls: dict[str, object] = {}

    class _Gateway:
        def __init__(self, settings):
            calls["settings"] = settings

        async def complete(self, role, messages, **kwargs):
            calls["role"] = role
            calls["messages"] = messages
            calls["kwargs"] = kwargs
            return SimpleNamespace(text="OK")

        async def aclose(self):
            calls["closed"] = True

    monkeypatch.setattr(service, "LLMGateway", _Gateway)
    settings = Settings(
        llm={
            "provider": "openai",
            "default_model": "test-model",
            "openai_api_key": "test-key",
        }
    )

    assert await service._ping(IntegrationKind.LLM, settings, None) is True
    assert calls["role"] == "classification"
    assert calls["kwargs"] == {"max_output_tokens": 8, "temperature": 0.0}
    assert calls["closed"] is True
