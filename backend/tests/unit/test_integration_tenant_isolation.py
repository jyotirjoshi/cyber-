"""Customer-owned provider credentials never cross the production tenant boundary."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.core.crypto import Secret
from app.core.errors import IntegrationNotConfiguredError
from app.db.enums import IntegrationKind, Role
from app.db.models.integration import Integration, IntegrationCredential
from app.services.context import Principal


class _Rows:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.rows))


@pytest.mark.asyncio
async def test_production_customer_without_github_connection_cannot_use_global_key() -> None:
    from app.services.integration import resolve_settings

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session = _Rows([])
    base = Settings(
        environment="production",
        github={
            "api_token": "global-token",
            "organization": "platform-org",
        },
    )

    scoped = await resolve_settings(
        session,
        principal,
        IntegrationKind.GITHUB,
        settings=base,
    )
    assert scoped.github.api_token is None
    assert scoped.github.organization is None
    assert base.github.api_token.get_secret_value() == "global-token"
    with pytest.raises(IntegrationNotConfiguredError):
        await resolve_settings(
            session,
            principal,
            IntegrationKind.GITHUB,
            settings=base,
            require=True,
        )
    params = session.statements[0].compile(dialect=postgresql.dialect()).params.values()
    assert principal.organization_id in params


@pytest.mark.asyncio
async def test_production_customer_connection_does_not_inherit_global_scope_or_key() -> None:
    from app.services.integration import resolve_settings

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = Integration(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        kind="github",
        name="Customer GitHub",
        status="configured",
        is_enabled=True,
        base_url=None,
        config={},
        credentials=[],
    )
    base = Settings(
        environment="production",
        github={
            "api_token": "global-token",
            "organization": "platform-org",
        },
    )

    scoped = await resolve_settings(
        _Rows([row]),
        principal,
        IntegrationKind.GITHUB,
        settings=base,
    )
    assert scoped.github.api_token is None
    assert scoped.github.organization is None
    with pytest.raises(IntegrationNotConfiguredError):
        await resolve_settings(
            _Rows([row]),
            principal,
            IntegrationKind.GITHUB,
            settings=base,
            require=True,
        )


@pytest.mark.asyncio
async def test_platform_llm_and_development_provider_keep_intended_fallback() -> None:
    from app.services.integration import resolve_settings

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    prod = Settings(environment="production", llm={"openai_api_key": "platform-key"})
    dev = Settings(
        environment="development",
        github={
            "api_token": "dev-token",
            "organization": "dev-org",
        },
    )

    llm = await resolve_settings(_Rows([]), principal, IntegrationKind.LLM, settings=prod)
    github = await resolve_settings(_Rows([]), principal, IntegrationKind.GITHUB, settings=dev)
    assert llm.llm.openai_api_key.get_secret_value() == "platform-key"
    assert github.github.api_token.get_secret_value() == "dev-token"
    assert github.github.organization == "dev-org"


@pytest.mark.asyncio
async def test_production_customer_connection_uses_only_its_own_credentials(monkeypatch) -> None:
    from app.services import integration as service

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    token = IntegrationCredential(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        name="api_token",
        ciphertext=b"encrypted",
        key_version=1,
        fingerprint="fingerprint",
        hint="hint",
    )
    row = Integration(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        kind="github",
        name="Customer GitHub",
        status="configured",
        is_enabled=True,
        base_url="https://github.customer.example/api/v3",
        config={"organization": "customer-org"},
        credentials=[token],
    )
    base = Settings(
        environment="production",
        github={
            "base_url": "https://github.platform.example/api/v3",
            "api_token": "global-token",
            "organization": "platform-org",
        },
    )
    monkeypatch.setattr(
        service, "_decrypt", lambda credential, *, settings: Secret("customer-token")
    )

    scoped = await service.resolve_settings(
        _Rows([row]),
        principal,
        IntegrationKind.GITHUB,
        settings=base,
        require=True,
        mark_used=False,
    )
    assert scoped.github.api_token.get_secret_value() == "customer-token"
    assert scoped.github.organization == "customer-org"
    assert scoped.github.base_url == "https://github.customer.example/api/v3"
    assert base.github.api_token.get_secret_value() == "global-token"


@pytest.mark.asyncio
async def test_production_optional_connector_does_not_inherit_platform_key() -> None:
    from app.services.integration import resolve_settings

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    base = Settings(
        environment="production",
        dify={
            "base_url": "https://dify.platform.example",
            "dataset_api_key": "platform-key",
            "dataset_id": "platform-dataset",
        },
    )
    scoped = await resolve_settings(_Rows([]), principal, IntegrationKind.DIFY, settings=base)
    assert scoped.dify.base_url is None
    assert scoped.dify.dataset_api_key is None
    assert scoped.dify.dataset_id is None
    assert not scoped.dify.configured
