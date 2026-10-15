"""Shared GraphQL contracts. No automatic mutation replay or server-message echo."""
from typing import Any

import httpx

from .errors import CynuxError

AGENTS = """query Agents($first: Int!, $after: String) {
  agentDefinitions(first: $first, after: $after) {
    nodes { id name description isEnabled versionCount activeVersionId createdAt updatedAt }
    pageInfo { hasNextPage endCursor }
  }
}"""
COLLECTIONS = """query KnowledgeCollections($first: Int!, $after: String) {
  knowledgeCollections(first: $first, after: $after) {
    nodes { id name description isEnabled retrievalProvider revision createdAt updatedAt }
    pageInfo { hasNextPage endCursor }
  }
}"""
VERSIONS = """query AgentVersions($id: ID!, $first: Int!, $after: String) {
  agentDefinitionVersions(agentDefinitionId: $id, first: $first, after: $after) {
    nodes { id agentDefinitionId version role provider model autonomyMode temperature maxOutputTokens maxParallelTasks maxRuntimeSeconds maxToolCalls maxInputTokens maxEstimatedSpendMicros createdAt }
    pageInfo { hasNextPage endCursor }
  }
}"""
SOURCES = """query KnowledgeSources($id: ID!, $first: Int!, $after: String) {
  knowledgeSources(collectionId: $id, first: $first, after: $after) {
    nodes { id collectionId sourceType filename title mimeType contentHash sizeBytes status errorCode currentRevision indexedChunks totalChunks createdAt updatedAt }
    pageInfo { hasNextPage endCursor }
  }
}"""
CREATE_AGENT = """mutation CreateAgentDefinition($input: CreateAgentDefinitionInput!) {
  createAgentDefinition(input: $input) {
    agent { id name description isEnabled versionCount activeVersionId createdAt updatedAt }
    clientMutationId
  }
}"""
CREATE_AGENT_VERSION = """mutation CreateAgentDefinitionVersion($input: CreateAgentDefinitionVersionInput!) {
  createAgentDefinitionVersion(input: $input) {
    version { id agentDefinitionId version role provider model autonomyMode temperature maxOutputTokens maxParallelTasks maxRuntimeSeconds maxToolCalls maxInputTokens maxEstimatedSpendMicros createdAt }
    clientMutationId
  }
}"""
DISABLE_AGENT = """mutation DisableAgentDefinition($input: DisableAgentDefinitionInput!) {
  disableAgentDefinition(input: $input) {
    agent { id name description isEnabled versionCount activeVersionId createdAt updatedAt }
    clientMutationId
  }
}"""
CREATE_KNOWLEDGE_COLLECTION = """mutation CreateKnowledgeCollection($input: CreateKnowledgeCollectionInput!) {
  createKnowledgeCollection(input: $input) {
    collection { id name description isEnabled retrievalProvider revision createdAt updatedAt }
    clientMutationId
  }
}"""


def service_root(base_url: str) -> str:
    url = httpx.URL(base_url)
    if not url.host or (
        url.scheme != "https"
        and not (url.scheme == "http" and url.host in {"localhost", "127.0.0.1", "::1"})
    ):
        raise ValueError("Cynux base URL must use HTTPS")
    if url.userinfo or url.query or url.fragment:
        raise ValueError(
            "Cynux base URL must not contain credentials, query or fragment"
        )
    return str(url).rstrip("/")


def graphql_payload(
    query: str, variables: dict[str, Any] | None, operation_name: str | None
) -> dict[str, Any]:
    if not query.strip() or len(query) > 65_536:
        raise ValueError("GraphQL query must contain between 1 and 65536 characters")
    return {
        "query": query,
        "variables": variables or {},
        "operationName": operation_name,
    }


def graphql_data(response: httpx.Response) -> dict[str, Any]:
    request_id = response.headers.get("x-request-id")
    if response.is_error:
        raise CynuxError(
            "Cynux GraphQL request failed",
            status_code=response.status_code,
            retryable=response.status_code in {429, 502, 503, 504},
            request_id=request_id,
        )
    try:
        body = response.json()
    except ValueError:
        raise CynuxError(
            "Cynux returned an invalid GraphQL response", request_id=request_id
        ) from None
    if not isinstance(body, dict):
        raise CynuxError(
            "Cynux returned an invalid GraphQL response", request_id=request_id
        )
    if body.get("errors"):
        errors = body["errors"]
        first = errors[0] if isinstance(errors, list) and errors else {}
        extensions = first.get("extensions", {}) if isinstance(first, dict) else {}
        if not isinstance(extensions, dict):
            extensions = {}
        code = extensions.get("code")
        code = (
            code
            if isinstance(code, str) and code.isupper() and len(code) <= 80
            else None
        )
        raise CynuxError(
            "Cynux GraphQL operation failed",
            code=code,
            status_code=response.status_code,
            retryable=extensions.get("retryable") is True,
            request_id=request_id or extensions.get("requestId"),
        )
    if not isinstance(body.get("data"), dict):
        raise CynuxError(
            "Cynux returned an invalid GraphQL response", request_id=request_id
        )
    return body["data"]


def validate_page_size(page_size: int) -> None:
    if (
        not isinstance(page_size, int)
        or isinstance(page_size, bool)
        or not 1 <= page_size <= 100
    ):
        raise ValueError("page_size must be between 1 and 100")


def connection_page(data: dict[str, Any], field: str, previous: str | None):
    connection = data.get(field)
    if not isinstance(connection, dict):
        raise CynuxError("Cynux returned an invalid connection")
    nodes, info = connection.get("nodes"), connection.get("pageInfo")
    if (
        not isinstance(nodes, list)
        or not all(isinstance(node, dict) for node in nodes)
        or not isinstance(info, dict)
    ):
        raise CynuxError("Cynux returned an invalid connection")
    more, cursor = info.get("hasNextPage"), info.get("endCursor")
    if not isinstance(more, bool):
        raise CynuxError("Cynux returned invalid pagination metadata")
    if more and (
        not nodes
        or not isinstance(cursor, str)
        or not cursor
        or cursor == previous
        or len(cursor) > 4096
    ):
        raise CynuxError("Cynux returned a non-advancing pagination cursor")
    return nodes, cursor if more else None


def mutation_result(data: dict[str, Any], field: str) -> dict[str, Any]:
    payload = data.get(field)
    if not isinstance(payload, dict):
        raise CynuxError("Cynux returned an invalid mutation result")
    return payload


def mutation_input(
    configuration: dict[str, Any],
    *,
    idempotency_key: str,
    client_mutation_id: str,
) -> dict[str, Any]:
    if not idempotency_key or len(idempotency_key) > 160:
        raise ValueError("idempotency_key must contain 1 to 160 characters")
    if not client_mutation_id or len(client_mutation_id) > 160:
        raise ValueError("client_mutation_id must contain 1 to 160 characters")
    return {
        **dict(configuration),
        "idempotencyKey": idempotency_key,
        "clientMutationId": client_mutation_id,
    }
