import json

import httpx
import pytest

from cynux import CynuxClient, CynuxError


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost.evil.example",
        "https://user:secret@example.com",
        "https://example.com?token=secret",
    ],
)
def test_sync_client_rejects_unsafe_base_urls(base_url):
    with pytest.raises(ValueError):
        CynuxClient(base_url, "cynux_test")


def test_graphql_uses_correct_endpoint_and_paginates_lazily():
    seen = []

    def handler(request):
        seen.append(request)
        body = json.loads(request.content)
        after = body["variables"]["after"]
        assert request.url.path == "/api/graphql"
        assert request.headers["authorization"] == "Bearer cynux_test"
        return httpx.Response(
            200,
            json={
                "data": {
                    "agentDefinitions": {
                        "nodes": [{"name": "B" if after else "A"}],
                        "pageInfo": {
                            "hasNextPage": not bool(after),
                            "endCursor": "next" if not after else "last",
                        },
                    }
                }
            },
        )

    with CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    ) as client:
        iterator = client.iter_agents(page_size=1)
        assert seen == []
        assert next(iterator) == {"name": "A"}
        assert len(seen) == 1
        assert list(iterator) == [{"name": "B"}]


def test_graphql_never_automatically_retries_mutations_or_exposes_server_errors():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            503,
            json={"errors": [{"message": "secret upstream credential"}]},
            headers={"x-request-id": "req-123"},
        )

    with CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(CynuxError) as exc:
            client.graphql("mutation { example }")
    assert len(calls) == 1
    assert "secret" not in str(exc.value)
    assert exc.value.request_id == "req-123"


def test_graphql_partial_errors_do_not_look_like_success():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "data": {"agentDefinitions": None},
                "errors": [
                    {
                        "message": "provider secret",
                        "extensions": {
                            "code": "PERMISSION_DENIED",
                            "requestId": "req-1",
                        },
                    }
                ],
            },
        )

    with CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(CynuxError) as exc:
            client.graphql("{ agentDefinitions { nodes { name } } }")
    assert exc.value.code == "PERMISSION_DENIED"
    assert "secret" not in str(exc.value)


def test_cursor_iterator_stops_on_broken_server_cursor():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "data": {
                    "knowledgeCollections": {
                        "nodes": [],
                        "pageInfo": {"hasNextPage": True, "endCursor": None},
                    }
                }
            },
        )

    with CynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(CynuxError):
            list(client.iter_knowledge_collections())


@pytest.mark.asyncio
async def test_async_client_supports_same_graphql_and_cursor_contract():
    from cynux import AsyncCynuxClient

    async def handler(request):
        assert request.url.path == "/api/graphql"
        return httpx.Response(
            200,
            json={
                "data": {
                    "agentDefinitions": {
                        "nodes": [{"name": "A"}],
                        "pageInfo": {"hasNextPage": False, "endCursor": "last"},
                    }
                }
            },
        )

    async with AsyncCynuxClient(
        "https://cynux.example", "cynux_test", transport=httpx.MockTransport(handler)
    ) as client:
        assert [row async for row in client.iter_agents()] == [{"name": "A"}]
