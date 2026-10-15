import base64
import json
from email.parser import BytesParser
from email.policy import default

import httpx
import pytest

from cynux import AsyncCynuxClient, CynuxClient, CynuxError

COLLECTION = "00000000-0000-0000-0000-000000000001"
SOURCE = "00000000-0000-0000-0000-000000000002"
COLLECTION_ID = base64.urlsafe_b64encode(f"KnowledgeCollection:{COLLECTION}".encode()).decode()
SOURCE_ID = base64.urlsafe_b64encode(f"KnowledgeSource:{SOURCE}".encode()).decode()
DOCUMENT = b"# Incident response\nRequire owner approval.\n"


def upload_handler(request):
    assert request.url.path == f"/api/v1/knowledge/collections/{COLLECTION}/sources"
    assert request.headers["authorization"] == "Bearer test_key"
    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + request.headers["content-type"].encode() + b"\r\n\r\n" + request.content
    )
    parts = list(message.iter_parts())
    assert len(parts) == 1
    assert parts[0].get_param("name", header="content-disposition") == "file"
    assert parts[0].get_filename() == "response.md"
    assert parts[0].get_content_type() == "text/markdown"
    assert parts[0].get_payload(decode=True) == DOCUMENT
    return httpx.Response(201, json={
        "id": SOURCE, "collection_id": COLLECTION, "filename": "response.md",
        "title": None, "mime_type": "text/markdown", "content_hash": "a" * 64,
        "size_bytes": len(DOCUMENT), "status": "stored", "error_code": None,
        "current_revision": 1, "current_version_id": None, "tombstoned_at": None,
        "created_at": "2026-10-15T10:00:00Z", "updated_at": "2026-10-15T10:00:00Z",
        "embedding_profile": None, "indexed_chunks": 0, "total_chunks": 0, "index_attempts": 0,
    })


@pytest.mark.parametrize("collection_id", [COLLECTION, COLLECTION_ID])
def test_upload_accepts_collection_ids_and_returns_usable_source_id(collection_id):
    with CynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(upload_handler)) as client:
        source = client.upload_knowledge_source(collection_id, filename="response.md", content=DOCUMENT)
    assert source["id"] == SOURCE_ID
    assert source["collectionId"] == COLLECTION_ID
    assert source["status"] == "stored"  # Upload does not imply indexed/ready.
    assert source["mimeType"] == "text/markdown"


@pytest.mark.asyncio
async def test_async_upload_uses_same_multipart_and_projection_contract():
    async with AsyncCynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(upload_handler)) as client:
        source = await client.upload_knowledge_source(COLLECTION_ID, filename="response.md", content=DOCUMENT)
    assert source["id"] == SOURCE_ID
    assert source["status"] == "stored"


@pytest.mark.parametrize("client_type", [CynuxClient, AsyncCynuxClient])
@pytest.mark.parametrize("failure", ["http", "transport"])
@pytest.mark.asyncio
async def test_upload_errors_are_single_attempt_and_do_not_echo_server_details(client_type, failure):
    calls = []
    def handler(request):
        calls.append(request)
        if failure == "transport":
            raise httpx.ConnectError("provider secret", request=request)
        return httpx.Response(503, json={"detail": "provider secret"}, headers={"x-request-id": "upload-1"})
    client = client_type("https://cynux.example", "test_key", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(CynuxError) as exc:
            if client_type is AsyncCynuxClient:
                await client.upload_knowledge_source(COLLECTION_ID, filename="response.md", content=DOCUMENT)
            else:
                client.upload_knowledge_source(COLLECTION_ID, filename="response.md", content=DOCUMENT)
        assert len(calls) == 1
        assert "secret" not in str(exc.value)
        assert exc.value.retryable
        if failure == "http":
            assert exc.value.request_id == "upload-1"
    finally:
        if client_type is AsyncCynuxClient:
            await client.close()
        else:
            client.close()


@pytest.mark.parametrize("kwargs", [
    {"collection_id": SOURCE_ID}, {"collection_id": "../../other"},
    {"filename": "../secrets.txt"}, {"filename": "a\r\nb.md"},
    {"content": b""}, {"filename": "unknown.bin"},
])
def test_invalid_upload_fails_before_network(kwargs):
    def unexpected(request):
        pytest.fail("invalid upload reached HTTP transport")
    with CynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(unexpected)) as client:
        with pytest.raises(ValueError):
            client.upload_knowledge_source(**{
                "collection_id": COLLECTION, "filename": "response.md", "content": DOCUMENT,
                **kwargs,
            })


def test_upload_rejects_malformed_or_wrong_parent_response():
    for body in ([], {}, {"id": SOURCE, "collection_id": SOURCE, "filename": "response.md", "status": "stored"}):
        with CynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(
            lambda request: httpx.Response(201, json=body)
        )) as client:
            with pytest.raises(CynuxError, match="invalid upload result"):
                client.upload_knowledge_source(COLLECTION, filename="response.md", content=DOCUMENT)


HIT = {
    "chunkId": "chunk-1", "sourceId": SOURCE_ID, "text": "Require owner approval.", "score": 0.03,
    "citation": {"collectionId": COLLECTION_ID, "sourceId": SOURCE_ID, "sourceVersionId": "version-1",
                 "filename": "response.md", "page": None, "section": "Incident response",
                 "ordinal": 0, "contentHash": "a" * 64, "provider": "internal"},
}


def search_handler(request):
    assert request.url.path == "/api/graphql"
    body = json.loads(request.content)
    assert body["operationName"] == "SearchKnowledge"
    assert body["variables"] == {
        "query": "approval", "collectionIds": [COLLECTION_ID], "limit": 4, "minSimilarity": 0.5,
    }
    return httpx.Response(200, json={"data": {"knowledgeSearch": [HIT]}})


def test_search_normalizes_collection_ids_and_preserves_citations():
    with CynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(search_handler)) as client:
        result = client.search_knowledge(" approval ", [COLLECTION, COLLECTION_ID], limit=4, min_similarity=0.5)
    assert result == [HIT]


@pytest.mark.asyncio
async def test_async_search_preserves_citations():
    async with AsyncCynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(search_handler)) as client:
        result = await client.search_knowledge(" approval ", [COLLECTION], limit=4, min_similarity=0.5)
    assert result == [HIT]


@pytest.mark.parametrize("kwargs", [
    {"query": " "}, {"query": "x" * 2001}, {"collection_ids": []},
    {"collection_ids": [SOURCE_ID]}, {"limit": True}, {"limit": 21},
    {"min_similarity": float("nan")},
])
def test_invalid_search_fails_before_network(kwargs):
    with CynuxClient("https://cynux.example", "test_key", transport=httpx.MockTransport(
        lambda request: pytest.fail("invalid search reached network")
    )) as client:
        with pytest.raises(ValueError):
            client.search_knowledge(**{"query": "approval", "collection_ids": [COLLECTION], **kwargs})
