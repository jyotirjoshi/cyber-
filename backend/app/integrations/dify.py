"""Dify knowledge-base retrieval (FR-021).

Dify is Cynux's RAG layer, and the PRD's out-of-scope list is emphatic about why it is a
dependency rather than a component: no custom vector search engine, no custom BM25, no
custom MMR.  This module therefore does one thing -- send a query to Dify's dataset retrieval
endpoint and return the chunks -- and holds no ranking logic of its own.

The FR-021 rule that shapes the API: **when the knowledge base is unavailable, the model is
not allowed to answer from memory.**  So an unconfigured or failing Dify raises rather than
returning an empty list, and the caller's job is to tell the user the knowledge base is
unavailable.  Returning ``[]`` would put the agent in exactly the position FR-024 forbids --
generating security guidance with no retrieved source and no way for the reader to know that
is what happened.

:meth:`DifyClient.retrieve` returns chunks whose ``content`` is untrusted text.  Knowledge
bases are populated by humans from external documents, so a chunk can carry an injection
payload as readily as a crawled web page; every caller passes chunk content through
:func:`app.llm.prompts.wrap_untrusted` (SEC-005).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import IntegrationError, IntegrationNotConfiguredError
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "Dify"

#: Cap on how much of a chunk is carried into a prompt. Dify chunk sizes are configured
#: dataset-side and Cynux cannot assume they are small (SEC-006).
MAX_CHUNK_CHARS = 4000


@dataclass(frozen=True, slots=True)
class KnowledgeChunk:
    content: str
    score: float
    document_name: str = ""
    document_id: str = ""
    segment_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def citation_id(self) -> str:
        """The evidence id a model may cite for this chunk (FR-024).

        Keyed on the document rather than the segment: a reader following the citation wants
        the document, and a segment id means nothing outside Dify's database.
        """
        label = self.document_name or self.document_id or "unknown"
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in label)[:60]
        return f"kb:{safe}"

    def evidence(self) -> dict[str, Any]:
        return {
            "source": "internal knowledge base",
            "document": self.document_name or self.document_id,
            "relevance_score": round(self.score, 4),
            "content": self.content[:MAX_CHUNK_CHARS],
        }


def _parse_chunk(payload: dict[str, Any]) -> KnowledgeChunk | None:
    """Read one entry of Dify's ``records[]``.

    Dify nests the text under ``segment.content`` and the score at the record level. Both
    shapes have appeared across versions, so both are accepted.
    """
    if not isinstance(payload, dict):
        return None
    #: Read each nested object once and narrow it, rather than calling ``.get`` twice: the
    #: second call is what makes the ``isinstance`` guard decorative if the shape ever varies.
    raw_segment = payload.get("segment")
    segment: dict[str, Any] = raw_segment if isinstance(raw_segment, dict) else {}
    content = segment.get("content") or payload.get("content")
    if not isinstance(content, str) or not content.strip():
        return None

    raw_document = segment.get("document")
    document: dict[str, Any] = raw_document if isinstance(raw_document, dict) else {}
    try:
        score = float(payload.get("score", segment.get("score", 0.0)))
    except (TypeError, ValueError):
        score = 0.0

    return KnowledgeChunk(
        content=content.strip()[:MAX_CHUNK_CHARS],
        score=score,
        document_name=str(document.get("name") or payload.get("document_name") or ""),
        document_id=str(document.get("id") or segment.get("document_id") or ""),
        segment_id=str(segment.get("id") or ""),
        metadata={
            k: v
            for k, v in (segment.get("metadata") or {}).items()
            #: Dify echoes internal bookkeeping into metadata. Only carry values a human
            #: reading a citation would find meaningful.
            if k in {"source", "url", "title", "author", "updated_at", "category"}
        },
    )


class DifyClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.dify
        self._redis = redis
        self._client: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return bool(self._cfg.configured)

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint=(
                    "Set CYNUX_DIFY__BASE_URL, CYNUX_DIFY__DATASET_API_KEY and "
                    "CYNUX_DIFY__DATASET_ID."
                ),
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url or "",
                settings=self.settings,
                redis=self._redis,
                headers={
                    "Authorization": f"Bearer {reveal(self._cfg.dataset_api_key)}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=float(self._cfg.timeout_seconds),
                retry=RetryPolicy(max_attempts=2, backoff_base=0.75),
                breaker_config=BreakerConfig(failure_threshold=5, cooldown_seconds=120),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def retrieve(
        self,
        query: str,
        *,
        top_k: int | None = None,
        score_threshold: float | None = None,
    ) -> list[KnowledgeChunk]:
        """Retrieve knowledge chunks for ``query``.

        Raises when Dify is unconfigured or unreachable -- see the module docstring on why
        this must not degrade to an empty list. An *empty result from a working Dify* is a
        different and legitimate outcome, and is returned as ``[]``.
        """
        cleaned = query.strip()
        if not cleaned:
            return []

        threshold = self._cfg.score_threshold if score_threshold is None else score_threshold
        payload = await self._require().post_json(
            f"/v1/datasets/{self._cfg.dataset_id}/retrieve",
            json={
                "query": cleaned[:2000],
                "retrieval_model": {
                    #: Hybrid search plus Dify's reranker. Choosing the strategy here rather
                    #: than leaving it to the dataset default keeps retrieval behaviour a
                    #: property of Cynux's code, so a dataset edited in Dify's UI cannot
                    #: silently change how the agent retrieves.
                    "search_method": "hybrid_search",
                    "reranking_enable": True,
                    "reranking_mode": "reranking_model",
                    "top_k": top_k or self._cfg.top_k,
                    "score_threshold_enabled": threshold > 0,
                    "score_threshold": threshold,
                },
            },
        )
        if not isinstance(payload, dict):
            raise IntegrationError(
                "Dify returned an unexpected document shape for a retrieval.",
                provider=PROVIDER,
            )

        records = (payload.get("records") or []) if "records" in payload else []
        chunks: list[KnowledgeChunk] = []
        for entry in records:
            chunk = _parse_chunk(entry)
            if chunk is not None and chunk.score >= threshold:
                chunks.append(chunk)
        chunks.sort(key=lambda c: c.score, reverse=True)

        logger.debug(
            "dify.retrieved",
            returned=len(records),
            kept=len(chunks),
            threshold=threshold,
        )
        return chunks

    async def ping(self) -> bool:
        """Confirm the dataset key and id are usable.

        A trivial retrieval is the cheapest authenticated call that also proves the dataset
        id resolves -- ``/v1/datasets`` would validate the key while still leaving a wrong
        dataset id to fail at the first real retrieval.
        """
        await self.retrieve("connectivity check", top_k=1, score_threshold=0.99)
        return True


__all__ = ["MAX_CHUNK_CHARS", "PROVIDER", "DifyClient", "KnowledgeChunk"]
