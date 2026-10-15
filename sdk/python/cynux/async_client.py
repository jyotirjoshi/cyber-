"""Asynchronous GraphQL access sharing sync response and pagination contracts."""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx

from .errors import CynuxError
from .graphql import (
    AGENTS,
    COLLECTIONS,
    CREATE_AGENT,
    SOURCES,
    VERSIONS,
    connection_page,
    graphql_data,
    graphql_payload,
    mutation_result,
    service_root,
    validate_page_size,
)


class AsyncCynuxClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        base_url = service_root(base_url)
        self._graphql_url = base_url.rstrip("/") + "/api/graphql"
        self._client = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "cynux-python/0.1",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncCynuxClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        payload = graphql_payload(query, variables, operation_name)
        try:
            response = await self._client.post(self._graphql_url, json=payload)
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        return graphql_data(response)

    async def _iter_graphql(
        self,
        query: str,
        field: str,
        page_size: int,
        variables: dict[str, Any] | None = None,
    ):
        validate_page_size(page_size)
        cursor = None
        while True:
            data = await self.graphql(
                query, {**(variables or {}), "first": page_size, "after": cursor}
            )
            nodes, cursor = connection_page(data, field, cursor)
            for node in nodes:
                yield node
            if cursor is None:
                return

    def iter_agents(self, *, page_size: int = 25) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(AGENTS, "agentDefinitions", page_size)

    def iter_knowledge_collections(
        self, *, page_size: int = 25
    ) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(COLLECTIONS, "knowledgeCollections", page_size)

    def iter_agent_versions(
        self, agent_definition_id: str, *, page_size: int = 25
    ) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(
            VERSIONS, "agentDefinitionVersions", page_size, {"id": agent_definition_id}
        )

    def iter_knowledge_sources(
        self, collection_id: str, *, page_size: int = 25
    ) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(
            SOURCES, "knowledgeSources", page_size, {"id": collection_id}
        )

    async def create_agent_definition(
        self,
        configuration: dict[str, Any],
        *,
        idempotency_key: str,
        client_mutation_id: str,
    ) -> dict[str, Any]:
        if not idempotency_key or len(idempotency_key) > 160:
            raise ValueError("idempotency_key must contain 1 to 160 characters")
        if not client_mutation_id or len(client_mutation_id) > 160:
            raise ValueError("client_mutation_id must contain 1 to 160 characters")
        mutation_input = {
            **dict(configuration),
            "idempotencyKey": idempotency_key,
            "clientMutationId": client_mutation_id,
        }
        data = await self.graphql(
            CREATE_AGENT,
            {"input": mutation_input},
            operation_name="CreateAgentDefinition",
        )
        return mutation_result(data, "createAgentDefinition")
