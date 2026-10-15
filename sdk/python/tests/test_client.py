import hashlib, hmac
import httpx
from cynux.client import CynuxClient, verify_webhook_signature


def test_client_paginates_and_authenticates():
    seen = []
    def handler(request):
        seen.append(request)
        offset = int(request.url.params["offset"])
        items = [{"id": str(offset)}] if offset < 2 else []
        return httpx.Response(200, json={"items": items, "meta": {"total": 2, "limit": 1, "offset": offset}})
    client = CynuxClient("https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler))
    assert [row["id"] for row in client.iter_all("/assets", page_size=1)] == ["0", "1"]
    assert seen[0].headers["authorization"] == "Bearer cynux_test"


def test_webhook_signature_verification():
    body = b'{"event":"finding.created"}'
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature("secret", body, signature)
    assert not verify_webhook_signature("wrong", body, signature)
