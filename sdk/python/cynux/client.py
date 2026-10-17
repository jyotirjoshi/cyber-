from __future__ import annotations
import hashlib
import hmac
import time
import uuid
from collections.abc import Iterator
from typing import Any
import httpx
from .models import Page
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


def verify_webhook_signature(secret: str, body: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class CynuxClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30,
        max_retries: int = 3,
        transport: httpx.BaseTransport | None = None,
    ):
        base_url = service_root(base_url)
        self._max_retries = max(0, min(max_retries, 10))
        self._graphql_url = base_url.rstrip("/") + "/api/graphql"
        self._client = httpx.Client(
            base_url=base_url.rstrip("/") + "/api/v1",
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "cynux-python/0.1",
            },
        )

    def close(self) -> None:
        self._client.close()

    def search_knowledge(
        self, query: str, collection_ids: list[str], *, limit: int = 6,
        min_similarity: float = 0.25,
    ) -> list[dict[str, Any]]:
        """Retrieve cited passages from selected collections (UUIDs or GraphQL IDs)."""
        data = self.graphql(
            SEARCH_KNOWLEDGE,
            search_variables(query, collection_ids, limit, min_similarity),
            operation_name="SearchKnowledge",
        )
        return search_results(data)

    def upload_knowledge_source(
        self, collection_id: str, *, filename: str, content: bytes,
        mime_type: str | None = None,
    ) -> dict[str, Any]:
        """Upload once; return a source with GraphQL IDs. Indexing completes asynchronously.

        The server enforces document limits and deduplicates content per collection.
        Use iter_knowledge_sources to inspect ready/failed indexing status.
        """
        path, files = upload_request(collection_id, filename, content, mime_type)
        try:
            response = self._client.post(path, files=files)
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        return upload_result(response, collection_id)

    def __enter__(self) -> CynuxClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        idempotency_key: str | None = None,
    ) -> Any:
        headers = {}
        if method.upper() in {"POST", "PUT", "PATCH"}:
            headers["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(
                    method, path, params=params, json=json, headers=headers
                )
            except httpx.TransportError as exc:
                if attempt >= self._max_retries:
                    raise CynuxError(
                        "Cynux could not be reached", retryable=True
                    ) from exc
                time.sleep(min(2**attempt, 8))
                continue
            if (
                response.status_code in {429, 502, 503, 504}
                and attempt < self._max_retries
            ):
                retry_after = response.headers.get("retry-after")
                time.sleep(
                    min(
                        float(retry_after)
                        if retry_after and retry_after.isdigit()
                        else 2**attempt,
                        30,
                    )
                )
                continue
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
        raise CynuxError("Cynux request failed")

    def page(
        self, path: str, *, limit: int = 100, offset: int = 0, **filters: Any
    ) -> Page:
        payload = self.request(
            "GET",
            path,
            params={
                **filters,
                "limit": min(max(limit, 1), 200),
                "offset": max(offset, 0),
            },
        )
        meta = payload.get("meta", payload)
        return Page(
            items=list(payload.get("items", [])),
            total=int(meta.get("total", 0)),
            limit=int(meta.get("limit", limit)),
            offset=int(meta.get("offset", offset)),
        )

    def iter_all(
        self, path: str, *, page_size: int = 100, **filters: Any
    ) -> Iterator[dict[str, Any]]:
        offset = 0
        while True:
            page = self.page(path, limit=page_size, offset=offset, **filters)
            yield from page.items
            if not page.has_more or not page.items:
                return
            offset += len(page.items)

    def assets(self, **filters: Any) -> Iterator[dict[str, Any]]:
        return self.iter_all("/assets", **filters)

    def findings(self, **filters: Any) -> Iterator[dict[str, Any]]:
        return self.iter_all("/canonical-findings", **filters)

    def assessments(self, **filters: Any) -> Iterator[dict[str, Any]]:
        return self.iter_all("/assessments", **filters)

    def graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        payload = graphql_payload(query, variables, operation_name)
        try:
            response = self._client.post(self._graphql_url, json=payload)
        except httpx.TransportError:
            raise CynuxError("Cynux could not be reached", retryable=True) from None
        return graphql_data(response)

    def _iter_graphql(
        self,
        query: str,
        field: str,
        page_size: int,
        variables: dict[str, Any] | None = None,
    ):
        validate_page_size(page_size)
        cursor = None
        while True:
            data = self.graphql(
                query, {**(variables or {}), "first": page_size, "after": cursor}
            )
            nodes, cursor = connection_page(data, field, cursor)
            yield from nodes
            if cursor is None:
                return

    def iter_agents(self, *, page_size: int = 25) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(AGENTS, "agentDefinitions", page_size)

    def iter_assets(self, *, page_size: int = 25) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(ASSETS, "assets", page_size)

    def iter_canonical_findings(
        self, *, page_size: int = 25
    ) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(
            CANONICAL_FINDINGS, "canonicalFindings", page_size
        )

    def iter_assessments(self, *, page_size: int = 25) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(ASSESSMENTS, "assessments", page_size)

    def iter_reports(self, *, page_size: int = 25) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(REPORTS, "reports", page_size)

    def iter_automation_rules(
        self, *, page_size: int = 25
    ) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(AUTOMATION_RULES, "automationRules", page_size)

    def iter_knowledge_collections(
        self, *, page_size: int = 25
    ) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(COLLECTIONS, "knowledgeCollections", page_size)

    def iter_agent_versions(
        self, agent_definition_id: str, *, page_size: int = 25
    ) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(
            VERSIONS, "agentDefinitionVersions", page_size, {"id": agent_definition_id}
        )

    def iter_knowledge_sources(
        self, collection_id: str, *, page_size: int = 25
    ) -> Iterator[dict[str, Any]]:
        return self._iter_graphql(
            SOURCES, "knowledgeSources", page_size, {"id": collection_id}
        )

    def create_agent_definition(
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
        data = self.graphql(
            CREATE_AGENT,
            {"input": variables},
            operation_name="CreateAgentDefinition",
        )
        return mutation_result(data, "createAgentDefinition")

    def create_agent_definition_version(
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
        data = self.graphql(
            CREATE_AGENT_VERSION,
            {"input": variables},
            operation_name="CreateAgentDefinitionVersion",
        )
        return mutation_result(data, "createAgentDefinitionVersion")

    def disable_agent_definition(
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
        data = self.graphql(
            DISABLE_AGENT,
            {"input": variables},
            operation_name="DisableAgentDefinition",
        )
        return mutation_result(data, "disableAgentDefinition")

    def create_knowledge_collection(
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
        data = self.graphql(
            CREATE_KNOWLEDGE_COLLECTION,
            {"input": variables},
            operation_name="CreateKnowledgeCollection",
        )
        return mutation_result(data, "createKnowledgeCollection")

    def delete_knowledge_source(
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
        data = self.graphql(
            DELETE_KNOWLEDGE_SOURCE,
            {"input": variables},
            operation_name="DeleteKnowledgeSource",
        )
        return mutation_result(data, "deleteKnowledgeSource")

    def restore_knowledge_source(
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
        data = self.graphql(
            RESTORE_KNOWLEDGE_SOURCE,
            {"input": variables},
            operation_name="RestoreKnowledgeSource",
        )
        return mutation_result(data, "restoreKnowledgeSource")
