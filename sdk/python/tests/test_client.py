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


def test_private_access_evaluation_uses_native_control_plane_route():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, request.read()))
        return httpx.Response(
            200,
            json={
                "policy_id": "d631db3e-85a4-4e9d-a43d-d98b82608e21",
                "policy_version": 1,
                "event_id": "c51ab53f-0901-478e-bb8a-a6d67d56be9e",
                "decision": "allow",
                "enforced": True,
                "would_block": False,
                "session_minutes": 30,
                "reason_codes": ["explicit_group_allow"],
            },
        )

    client = CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    )
    result = client.evaluate_private_access(
        {
            "policy_id": "d631db3e-85a4-4e9d-a43d-d98b82608e21",
            "request_id": "access-1",
            "identity_ref": "user:alice@example.com",
            "application_ref": "app:payments",
        }
    )

    assert result["decision"] == "allow"
    assert seen[0][0:2] == ("POST", "/api/v1/control-plane/private-access/evaluate")


def test_casb_evaluation_uses_native_control_plane_route():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(
            200,
            json={
                "decision": "block",
                "severity": "critical",
                "score": "100.00",
                "reasons": ["restricted_data_action_blocked"],
                "content_digest": "a" * 64,
                "redacted_content": None,
                "approval_required": False,
            },
        )

    client = CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    )
    result = client.evaluate_casb(
        {
            "action": "external_share",
            "content": "Customer data",
            "identity_ref": "user:alice@example.com",
            "application_key": "saas:drive",
            "device_managed": True,
            "mfa": True,
        }
    )

    assert result["decision"] == "block"
    assert seen == [("POST", "/api/v1/control-plane/casb/evaluate")]


def test_experience_probe_uses_native_ingestion_route():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(201, json={"score": "98.00", "degraded": False})

    client = CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    )
    result = client.ingest_experience_probe({"event_key": "journey:checkout:1"})

    assert result["degraded"] is False
    assert seen == [("POST", "/api/v1/control-plane/experience/probes")]
