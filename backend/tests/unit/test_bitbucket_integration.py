"""Bitbucket repository connector contracts."""

from __future__ import annotations

import base64

import pytest

from app.core.config import Settings
from app.core.errors import InvalidConfigurationError
from app.db.enums import IntegrationKind


@pytest.mark.asyncio
async def test_bitbucket_connectivity_check_is_scoped_to_configured_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.integrations.bitbucket import BitbucketClient

    observed: dict[str, object] = {}

    class Transport:
        async def get_json(self, path, *, headers=None, **_kwargs):
            observed["path"] = path
            observed["headers"] = headers
            return {"full_name": "acme/service", "scm": "git"}

        async def aclose(self) -> None:
            return None

    def build_transport(**kwargs):
        observed["client_args"] = kwargs
        return Transport()

    monkeypatch.setattr("app.integrations.bitbucket.build_client", build_transport)
    client = BitbucketClient(
        Settings(
            bitbucket={
                "api_token": "tenant-token",
                "account_email": "operator@example.com",
                "workspace": "acme",
                "repository": "service",
            }
        )
    )

    assert await client.ping() is True
    assert observed["path"] == "/repositories/acme/service"
    encoded = base64.b64encode(b"operator@example.com:tenant-token").decode()
    assert observed["headers"] == {"Authorization": f"Basic {encoded}", "Accept": "application/json"}
    assert IntegrationKind.BITBUCKET.value == "bitbucket"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config",
    [
        {"account_email": "not-an-email"},
        {"workspace": "acme/team"},
        {"repository": "../../other"},
    ],
)
async def test_bitbucket_rejects_unsafe_repository_configuration_before_database_write(
    config: dict[str, str],
) -> None:
    import uuid

    from app.db.enums import Role
    from app.schemas.integration import IntegrationUpsertIn
    from app.services.context import Principal
    from app.services.integration import upsert_integration

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    payload = IntegrationUpsertIn(kind=IntegrationKind.BITBUCKET, config=config)

    with pytest.raises(InvalidConfigurationError):
        await upsert_integration(None, principal, payload, settings=Settings())
