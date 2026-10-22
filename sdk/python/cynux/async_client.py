"""Asynchronous GraphQL access sharing sync response and pagination contracts."""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx

from .errors import CynuxError
from .knowledge import search_results, search_variables, upload_request, upload_result
from .graphql import (
    AGENTS,
    ASSESSMENTS,
    ASSETS,
    AUTOMATION_RULES,
    CANONICAL_FINDINGS,
    COLLECTIONS,
    CREATE_AGENT,
    CREATE_AGENT_VERSION,
    CREATE_KNOWLEDGE_COLLECTION,
    DELETE_KNOWLEDGE_SOURCE,
    DISABLE_AGENT,
    RESTORE_KNOWLEDGE_SOURCE,
    REPORTS,
    SEARCH_KNOWLEDGE,
    SOURCES,
    VERSIONS,
    connection_page,
    graphql_data,
    graphql_payload,
    mutation_input,
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
            base_url=base_url.rstrip("/") + "/api/v1",
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "cynux-python/0.1",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _rest(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> Any:
        try:
            response = await self._client.request(method, path, json=json)
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        if response.is_error:
            try:
                problem = response.json()
            except ValueError:
                problem = {}
            raise CynuxError(
                str(problem.get("detail") or "Cynux request failed"),
                status_code=response.status_code,
                code=problem.get("code"),
                retryable=response.status_code in {429, 502, 503, 504},
            )
        return response.json() if response.content else None

    async def create_asset(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._rest("POST", "/assets", json=payload)

    async def bulk_update_assets(
        self, items: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return await self._rest("PATCH", "/assets/bulk", json={"items": items})

    async def merge_assets(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._rest("POST", "/assets/merge", json=payload)

    async def asset_relationships(self, asset_id: str) -> list[dict[str, Any]]:
        return await self._rest("GET", f"/assets/{asset_id}/relationships")

    async def create_asset_relationship(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._rest("POST", "/assets/relationships", json=payload)

    async def evaluate_private_access(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Evaluate and audit a native private-application access request."""

        return await self._rest(
            "POST", "/control-plane/private-access/evaluate", json=payload
        )

    async def evaluate_casb(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Evaluate and audit a transient SaaS data action."""

        return await self._rest("POST", "/control-plane/casb/evaluate", json=payload)

    async def import_assets_csv(
        self, content: bytes, *, filename: str = "assets.csv", dry_run: bool = True
    ) -> dict[str, Any]:
        try:
            response = await self._client.post(
                "/assets/csv-import",
                data={"dry_run": str(dry_run).lower()},
                files={"file": (filename, content, "text/csv")},
            )
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        if response.is_error:
            raise CynuxError(
                "Cynux asset import failed", status_code=response.status_code
            )
        return response.json()

    async def export_assets_csv(self) -> bytes:
        try:
            response = await self._client.get("/assets/export.csv")
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        if response.is_error:
            raise CynuxError(
                "Cynux asset export failed", status_code=response.status_code
            )
        return response.content

    async def search_knowledge(
        self, query: str, collection_ids: list[str], *, limit: int = 6,
        min_similarity: float = 0.25,
    ) -> list[dict[str, Any]]:
        """Retrieve cited passages from selected collections (UUIDs or GraphQL IDs)."""
        data = await self.graphql(
            SEARCH_KNOWLEDGE,
            search_variables(query, collection_ids, limit, min_similarity),
            operation_name="SearchKnowledge",
        )
        return search_results(data)

    async def upload_knowledge_source(
        self, collection_id: str, *, filename: str, content: bytes,
        mime_type: str | None = None,
    ) -> dict[str, Any]:
        """Upload once; return a source with GraphQL IDs. Indexing completes asynchronously.

        The server enforces document limits and deduplicates content per collection.
        Use iter_knowledge_sources to inspect ready/failed indexing status.
        """
        path, files = upload_request(collection_id, filename, content, mime_type)
        try:
            response = await self._client.post(path, files=files)
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        return upload_result(response, collection_id)

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

    def iter_assets(self, *, page_size: int = 25) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(ASSETS, "assets", page_size)

    def iter_canonical_findings(
        self, *, page_size: int = 25
    ) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(
            CANONICAL_FINDINGS, "canonicalFindings", page_size
        )

    def iter_assessments(
        self, *, page_size: int = 25
    ) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(ASSESSMENTS, "assessments", page_size)

    def iter_reports(self, *, page_size: int = 25) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(REPORTS, "reports", page_size)

    def iter_automation_rules(
        self, *, page_size: int = 25
    ) -> AsyncIterator[dict[str, Any]]:
        return self._iter_graphql(AUTOMATION_RULES, "automationRules", page_size)

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
        variables = mutation_input(
            configuration,
            idempotency_key=idempotency_key,
            client_mutation_id=client_mutation_id,
        )
        data = await self.graphql(
            CREATE_AGENT,
            {"input": variables},
            operation_name="CreateAgentDefinition",
        )
        return mutation_result(data, "createAgentDefinition")

    async def create_agent_definition_version(
        self,
        agent_definition_id: str,
        configuration: dict[str, Any],
        *,
        idempotency_key: str,
        client_mutation_id: str,
    ) -> dict[str, Any]:
        variables = mutation_input(
            {**dict(configuration), "agentDefinitionId": agent_definition_id},
            idempotency_key=idempotency_key,
            client_mutation_id=client_mutation_id,
        )
        data = await self.graphql(
            CREATE_AGENT_VERSION,
            {"input": variables},
            operation_name="CreateAgentDefinitionVersion",
        )
        return mutation_result(data, "createAgentDefinitionVersion")

    async def disable_agent_definition(
        self,
        agent_definition_id: str,
        *,
        idempotency_key: str,
        client_mutation_id: str,
    ) -> dict[str, Any]:
        variables = mutation_input(
            {"agentDefinitionId": agent_definition_id},
            idempotency_key=idempotency_key,
            client_mutation_id=client_mutation_id,
        )
        data = await self.graphql(
            DISABLE_AGENT,
            {"input": variables},
            operation_name="DisableAgentDefinition",
        )
        return mutation_result(data, "disableAgentDefinition")

    async def create_knowledge_collection(
        self,
        configuration: dict[str, Any],
        *,
        idempotency_key: str,
        client_mutation_id: str,
    ) -> dict[str, Any]:
        variables = mutation_input(
            configuration,
            idempotency_key=idempotency_key,
            client_mutation_id=client_mutation_id,
        )
        data = await self.graphql(
            CREATE_KNOWLEDGE_COLLECTION,
            {"input": variables},
            operation_name="CreateKnowledgeCollection",
        )
        return mutation_result(data, "createKnowledgeCollection")

    async def delete_knowledge_source(
        self,
        source_id: str,
        *,
        idempotency_key: str,
        client_mutation_id: str,
    ) -> dict[str, Any]:
        variables = mutation_input(
            {"sourceId": source_id},
            idempotency_key=idempotency_key,
            client_mutation_id=client_mutation_id,
        )
        data = await self.graphql(
            DELETE_KNOWLEDGE_SOURCE,
            {"input": variables},
            operation_name="DeleteKnowledgeSource",
        )
        return mutation_result(data, "deleteKnowledgeSource")

    async def restore_knowledge_source(
        self,
        source_id: str,
        *,
        idempotency_key: str,
        client_mutation_id: str,
    ) -> dict[str, Any]:
        variables = mutation_input(
            {"sourceId": source_id},
            idempotency_key=idempotency_key,
            client_mutation_id=client_mutation_id,
        )
        data = await self.graphql(
            RESTORE_KNOWLEDGE_SOURCE,
            {"input": variables},
            operation_name="RestoreKnowledgeSource",
        )
        return mutation_result(data, "restoreKnowledgeSource")
