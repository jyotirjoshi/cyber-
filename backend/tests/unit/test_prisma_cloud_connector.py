from __future__ import annotations

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.prisma_cloud import PrismaCloudClient
from app.services.external_alert import normalize_prisma_cloud_alert


def _settings() -> Settings:
    settings = Settings.model_construct()
    settings.prisma_cloud = type(
        "Cfg",
        (),
        {
            "configured": True,
            "base_url": "https://api.eu.prismacloud.io",
            "access_key_id": SecretStr("access"),
            "secret_key": SecretStr("secret"),
            "cloud_account_ids": ["123456789012"],
        },
    )()
    return settings


@pytest.mark.asyncio
async def test_prisma_cloud_fetches_a_bounded_complete_scoped_snapshot(monkeypatch) -> None:
    client = PrismaCloudClient(_settings())
    calls: list[tuple[str, dict]] = []

    class FakeHttp:
        async def post_json(self, path, **kwargs):
            assert path == "/login"
            return {"token": "jwt-token"}

        async def get_json(self, path, **kwargs):
            calls.append((path, kwargs))
            token = kwargs["params"].get("pageToken")
            resource = {"accountId": "123456789012", "id": "asset-1", "name": "bucket"}
            if token is None:
                return {"items": [{"id": "a-1", "resource": resource}], "nextPageToken": "p2"}
            return {"items": [{"id": "a-2", "resource": resource}]}

        async def aclose(self):
            return None

    monkeypatch.setattr(client, "_require", lambda: FakeHttp())
    alerts = await client.list_alerts()

    assert [item["id"] for item in alerts] == ["a-1", "a-2"]
    assert calls[0][1]["headers"] == {"x-redlock-auth": "jwt-token"}
    assert calls[1][1]["params"]["pageToken"] == "p2"


@pytest.mark.asyncio
async def test_prisma_cloud_rejects_alerts_outside_configured_accounts(monkeypatch) -> None:
    client = PrismaCloudClient(_settings())

    class FakeHttp:
        async def post_json(self, *args, **kwargs):
            return {"token": "jwt-token"}

        async def get_json(self, *args, **kwargs):
            return {
                "items": [
                    {"id": "escape", "resource": {"accountId": "999999999999", "id": "asset"}}
                ]
            }

        async def aclose(self):
            return None

    monkeypatch.setattr(client, "_require", lambda: FakeHttp())
    with pytest.raises(IntegrationError, match="outside the selected cloud accounts"):
        await client.list_alerts()


def test_prisma_cloud_alert_normalizes_to_canonical_cloud_identity() -> None:
    normalized = normalize_prisma_cloud_alert(
        {
            "id": "alert-1",
            "status": "open",
            "policy": {
                "policyId": "policy-1",
                "name": "Public storage bucket",
                "severity": "high",
                "recommendation": "Disable public access.",
                "policyType": "config",
            },
            "resource": {
                "accountId": "123456789012",
                "id": "arn:aws:s3:::example",
                "name": "example",
                "cloudType": "AWS",
                "region": "us-east-1",
                "resourceType": "aws-s3",
            },
        }
    )

    assert normalized.external_id == "alert-1"
    assert normalized.resource == "arn:aws:s3:::example"
    assert normalized.severity == "high"
    assert normalized.evidence["asset_type"] == "cloud"
    assert normalized.evidence["cloud_account_id"] == "123456789012"
