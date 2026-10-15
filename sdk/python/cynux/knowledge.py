"""Shared upload and search contracts for sync and async knowledge clients."""
from __future__ import annotations

import base64
import binascii
import math
import uuid
from typing import Any

import httpx

from .errors import CynuxError


def collection_uuid(identifier: str) -> uuid.UUID:
    """Accept a REST UUID or the typed ID returned by GraphQL collections."""
    if not isinstance(identifier, str) or len(identifier) > 256:
        raise ValueError("collection_id must be a collection UUID or GraphQL ID")
    try:
        return uuid.UUID(identifier)
    except ValueError:
        pass
    try:
        value = base64.b64decode(identifier, altchars=b"-_", validate=True).decode("ascii")
        kind, raw_id = value.split(":", 1)
        if kind != "KnowledgeCollection":
            raise ValueError
        return uuid.UUID(raw_id)
    except (ValueError, UnicodeError, binascii.Error):
        raise ValueError("collection_id must be a collection UUID or GraphQL ID") from None


def global_id(kind: str, identifier: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{kind}:{identifier}".encode()).decode()


def search_variables(
    query: str, collection_ids: list[str], limit: int, min_similarity: float
) -> dict[str, Any]:
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 2000:
        raise ValueError("query must contain 1 to 2000 characters")
    if not isinstance(collection_ids, (list, tuple)) or not 1 <= len(collection_ids) <= 20:
        raise ValueError("select 1 to 20 knowledge collections")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise ValueError("limit must be between 1 and 20")
    if (
        isinstance(min_similarity, bool)
        or not isinstance(min_similarity, (int, float))
        or not math.isfinite(min_similarity)
        or not 0 <= min_similarity <= 1
    ):
        raise ValueError("min_similarity must be between 0 and 1")
    return {
        "query": query.strip(),
        "collectionIds": list(dict.fromkeys(
            global_id("KnowledgeCollection", collection_uuid(value)) for value in collection_ids
        )),
        "limit": limit,
        "minSimilarity": min_similarity,
    }


def search_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    hits = data.get("knowledgeSearch")
    if not isinstance(hits, list) or not all(isinstance(hit, dict) for hit in hits):
        raise CynuxError("Cynux returned invalid knowledge search results")
    return hits


def upload_request(collection_id: str, filename: str, content: bytes, mime_type: str | None):
    identifier = collection_uuid(collection_id)
    if (
        not isinstance(filename, str)
        or not 1 <= len(filename.strip()) <= 500
        or any(char in filename for char in ("\r", "\n", "\x00", "/", "\\"))
    ):
        raise ValueError("filename must be a document name of 1 to 500 characters")
    if not isinstance(content, bytes) or not content:
        raise ValueError("content must contain document bytes")
    if mime_type is None:
        mime_type = {
            "txt": "text/plain", "md": "text/markdown", "markdown": "text/markdown",
            "pdf": "application/pdf", "json": "application/json",
            "sarif": "application/sarif+json",
        }.get(filename.strip().rsplit(".", 1)[-1].lower())
    if (
        not isinstance(mime_type, str)
        or not 1 <= len(mime_type) <= 160
        or any(char in mime_type for char in ("\r", "\n", "\x00"))
    ):
        raise ValueError("provide mime_type for this document type")
    return f"/knowledge/collections/{identifier}/sources", {
        "file": (filename.strip(), content, mime_type)
    }


def upload_result(response: httpx.Response, collection_id: str) -> dict[str, Any]:
    request_id = response.headers.get("x-request-id")
    if response.is_error:
        raise CynuxError(
            "Cynux knowledge upload failed",
            status_code=response.status_code,
            retryable=response.status_code in {429, 502, 503, 504},
            request_id=request_id,
        )
    try:
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError
        source_id = uuid.UUID(body["id"])
        parent_id = uuid.UUID(body["collection_id"])
        if parent_id != collection_uuid(collection_id):
            raise ValueError
        if not isinstance(body["status"], str) or not isinstance(body["filename"], str):
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CynuxError("Cynux returned an invalid upload result", request_id=request_id) from None
    # Match GraphQL source projections so IDs can be passed to delete/restore.
    names = {
        "filename": "filename", "title": "title", "mime_type": "mimeType",
        "content_hash": "contentHash", "size_bytes": "sizeBytes", "status": "status",
        "error_code": "errorCode", "current_revision": "currentRevision",
        "indexed_chunks": "indexedChunks", "total_chunks": "totalChunks",
        "created_at": "createdAt", "updated_at": "updatedAt",
    }
    return {
        **{target: body[key] for key, target in names.items() if key in body},
        "id": global_id("KnowledgeSource", source_id),
        "collectionId": global_id("KnowledgeCollection", parent_id),
        "sourceType": "upload",
    }
