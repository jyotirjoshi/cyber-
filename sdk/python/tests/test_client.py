import hashlib
import hmac

import httpx
import pytest

from cynux.async_client import AsyncCynuxClient
from cynux.client import CynuxClient, verify_webhook_signature


def test_client_paginates_and_authenticates():
    seen = []

    def handler(request):
        seen.append(request)
        offset = int(request.url.params["offset"])
        items = [{"id": str(offset)}] if offset < 2 else []
        return httpx.Response(
            200,
            json={"items": items, "meta": {"total": 2, "limit": 1, "offset": offset}},
        )

    client = CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    )
    assert [row["id"] for row in client.iter_all("/assets", page_size=1)] == ["0", "1"]
    assert seen[0].headers["authorization"] == "Bearer cynux_test"


def test_webhook_signature_verification():
    body = b'{"event":"finding.created"}'
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature("secret", body, signature)
    assert not verify_webhook_signature("wrong", body, signature)


def test_asset_operations_use_typed_inventory_routes():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("export.csv"):
            return httpx.Response(200, content=b"id,name\n1,api.example.com\n")
        return httpx.Response(200, json={"id": "asset-1"})

    client = CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    )
    assert client.create_asset({"name": "api.example.com", "asset_type": "domain"})[
        "id"
    ] == "asset-1"
    assert client.merge_assets({"source_asset_id": "one", "target_asset_id": "two"})[
        "id"
    ] == "asset-1"
    assert b"api.example.com" in client.export_assets_csv()
    assert seen == [
        ("POST", "/api/v1/assets"),
        ("POST", "/api/v1/assets/merge"),
        ("GET", "/api/v1/assets/export.csv"),
    ]


@pytest.mark.asyncio
async def test_async_asset_operations_share_inventory_routes():
    async def handler(request):
        return httpx.Response(200, json={"source_asset_id": "one", "target_asset_id": "two"})

    client = AsyncCynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    )
    try:
        result = await client.merge_assets(
            {"source_asset_id": "one", "target_asset_id": "two"}
        )
    finally:
        await client.close()
    assert result["target_asset_id"] == "two"
