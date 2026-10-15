"""Tenant-scoped hybrid search with durable citations and bounded source diversity."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections import Counter, OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol

from sqlalchemy import and_, func, select

from app.core.errors import InvalidConfigurationError, ResourceNotFoundError
from app.db.enums import IntegrationKind, Permission
from app.db.models.knowledge import (
    KnowledgeChunk,
    KnowledgeCollection,
    KnowledgeEmbedding,
    KnowledgeSource,
)
from app.services.context import Principal
from app.services.embedding import EmbeddingProfile, embedding_provider


@dataclass(frozen=True, slots=True)
class KnowledgeCitation:
    collection_id: uuid.UUID
    source_id: uuid.UUID
    source_version_id: uuid.UUID
    filename: str
    page: int | None
    section: str | None
    ordinal: int
    content_hash: str
    provider: str = "internal"


@dataclass(frozen=True, slots=True)
class KnowledgeHit:
    chunk_id: uuid.UUID
    source_id: uuid.UUID
    text: str
    score: float
    citation: KnowledgeCitation


@dataclass(frozen=True, slots=True)
class RetrievalPolicy:
    organization_id: uuid.UUID
    collection_ids: tuple[uuid.UUID, ...]
    limit: int = 6
    per_source_limit: int = 2
    min_similarity: float = 0.25
    metadata_filter: dict[str, Any] | None = None

    def __post_init__(self):
        if not 1 <= len(self.collection_ids) <= 20:
            raise ValueError("select between 1 and 20 knowledge collections")
        if not 1 <= self.limit <= 20 or not 1 <= self.per_source_limit <= 5:
            raise ValueError("retrieval limits are out of range")
        if not 0 <= self.min_similarity <= 1:
            raise ValueError("similarity must be between 0 and 1")


class KnowledgeRetriever(Protocol):
    async def retrieve(self, query: str, policy: RetrievalPolicy) -> list[KnowledgeHit]: ...


def retrieval_cache_key(query: str, policy: RetrievalPolicy, *, collection_revisions,
                        profiles) -> str:
    normalized_query = " ".join(query.split())
    payload = {"organization_id": str(policy.organization_id),
        "collection_revisions": sorted((str(key), int(value)) for key, value in collection_revisions),
        "profiles": sorted(str(value) for value in profiles), "query": normalized_query,
        "limit": policy.limit, "per_source_limit": policy.per_source_limit,
        "min_similarity": policy.min_similarity, "metadata_filter": policy.metadata_filter}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode()).hexdigest()


class _RetrievalCache:
    """Revision-keyed process cache; stale values become unreachable after any source change."""
    def __init__(self, maximum: int = 512, ttl_seconds: int = 300):
        self.maximum, self.ttl_seconds = maximum, ttl_seconds
        self.values: OrderedDict[str, tuple[float, tuple[KnowledgeHit, ...]]] = OrderedDict()

    def get(self, key: str) -> list[KnowledgeHit] | None:
        value = self.values.get(key)
        if value is None:
            return None
        created, hits = value
        if created + self.ttl_seconds < time.monotonic():
            self.values.pop(key, None)
            return None
        self.values.move_to_end(key)
        return list(hits)

    def put(self, key: str, hits: Sequence[KnowledgeHit]) -> None:
        self.values[key] = (time.monotonic(), tuple(hits))
        self.values.move_to_end(key)
        while len(self.values) > self.maximum:
            self.values.popitem(last=False)


_RETRIEVAL_CACHE = _RetrievalCache()


def reciprocal_rank_fusion(*rankings: Sequence[KnowledgeHit], limit: int = 6,
                           per_source_limit: int = 2) -> list[KnowledgeHit]:
    scores: dict[uuid.UUID, float] = {}
    hits: dict[uuid.UUID, KnowledgeHit] = {}
    for ranking in rankings:
        seen = set()
        for rank, hit in enumerate(ranking, start=1):
            if hit.chunk_id in seen:
                continue
            seen.add(hit.chunk_id)
            scores[hit.chunk_id] = scores.get(hit.chunk_id, 0.0) + 1 / (60 + rank)
            hits[hit.chunk_id] = hit
    selected: list[KnowledgeHit] = []
    counts: Counter[uuid.UUID] = Counter()
    for chunk_id in sorted(scores, key=lambda key: (-scores[key], str(key))):
        hit = hits[chunk_id]
        if counts[hit.source_id] >= per_source_limit:
            continue
        if any(item.source_id == hit.source_id and
               abs(item.citation.ordinal - hit.citation.ordinal) <= 1 for item in selected):
            continue
        selected.append(replace(hit, score=scores[chunk_id]))
        counts[hit.source_id] += 1
        if len(selected) >= limit:
            break
    return selected


def candidate_statement(policy: RetrievalPolicy, *, profile: str):
    statement = (select(KnowledgeChunk, KnowledgeSource)
        .join(KnowledgeSource, and_(KnowledgeSource.current_version_id == KnowledgeChunk.source_version_id,
                                   KnowledgeSource.organization_id == KnowledgeChunk.organization_id))
        .join(KnowledgeCollection, and_(KnowledgeCollection.id == KnowledgeSource.collection_id,
                                       KnowledgeCollection.organization_id == KnowledgeSource.organization_id))
        .join(KnowledgeEmbedding, and_(KnowledgeEmbedding.chunk_id == KnowledgeChunk.id,
                                      KnowledgeEmbedding.organization_id == KnowledgeChunk.organization_id))
        .where(KnowledgeChunk.organization_id == policy.organization_id,
               KnowledgeCollection.id.in_(policy.collection_ids),
               KnowledgeCollection.is_enabled.is_(True),
               KnowledgeSource.status == "ready", KnowledgeSource.tombstoned_at.is_(None),
               KnowledgeSource.embedding_profile == profile,
               KnowledgeEmbedding.embedding_profile == profile,
               KnowledgeEmbedding.status == "ready",
               KnowledgeEmbedding.embedding_content_hash == KnowledgeChunk.content_hash))
    if policy.metadata_filter:
        statement = statement.where(KnowledgeSource.document_metadata.contains(policy.metadata_filter))
    return statement


def _hit(chunk, source) -> KnowledgeHit:
    return KnowledgeHit(chunk.id, source.id, chunk.normalized_text[:4000], 0,
        KnowledgeCitation(source.collection_id, source.id, chunk.source_version_id,
            source.filename, chunk.page, chunk.section, chunk.ordinal, chunk.content_hash))


class InternalKnowledgeRetriever:
    def __init__(self, session, principal: Principal, settings, *, provider_factory=embedding_provider):
        self.session, self.principal, self.settings = session, principal, settings
        self.provider_factory = provider_factory

    async def retrieve(self, query: str, policy: RetrievalPolicy) -> list[KnowledgeHit]:
        self.principal.require(Permission.AGENT_CHAT)
        if policy.organization_id != self.principal.organization_id:
            raise ResourceNotFoundError("knowledge collections not found")
        query = query.strip()
        if not query or len(query.encode()) > 8000:
            raise ValueError("knowledge query must contain 1 to 8000 UTF-8 bytes")
        collections = list((await self.session.scalars(select(KnowledgeCollection).where(
            KnowledgeCollection.organization_id == policy.organization_id,
            KnowledgeCollection.id.in_(policy.collection_ids), KnowledgeCollection.is_enabled.is_(True),
        ))).all())
        if {row.id for row in collections} != set(policy.collection_ids):
            raise ResourceNotFoundError("knowledge collections not found")
        profiles = list((await self.session.scalars(select(KnowledgeSource.embedding_profile)
            .where(KnowledgeSource.organization_id == policy.organization_id,
                   KnowledgeSource.collection_id.in_(policy.collection_ids),
                   KnowledgeSource.status == "ready", KnowledgeSource.tombstoned_at.is_(None))
            .distinct().limit(5))).all())
        if len(profiles) > 4:
            raise InvalidConfigurationError("Narrow this search to at most four embedding profiles")
        cache_key = retrieval_cache_key(query, policy,
            collection_revisions=[(row.id, row.revision) for row in collections], profiles=profiles)
        cached = _RETRIEVAL_CACHE.get(cache_key)
        if cached is not None:
            return cached
        from app.services.integration import resolve_settings
        rankings = []
        if profiles:
            scoped = await resolve_settings(self.session, self.principal, IntegrationKind.LLM,
                                            settings=self.settings)
            for key in profiles:
                parts = key.split(":")
                profile = EmbeddingProfile(parts[0], parts[1])
                async with self.provider_factory(scoped, profile) as provider:
                    vector = (await provider.embed([query], query=True))[0]
                statement = candidate_statement(policy, profile=key)
                distance = KnowledgeEmbedding.embedding.cosine_distance(vector)
                vector_rows = (await self.session.execute(statement.where(
                    distance <= 1 - policy.min_similarity).order_by(distance, KnowledgeChunk.id).limit(50))).all()
                tsquery = func.websearch_to_tsquery("english", query)
                text_rows = (await self.session.execute(statement.where(
                    KnowledgeChunk.search_document.op("@@")(tsquery)).order_by(
                    func.ts_rank_cd(KnowledgeChunk.search_document, tsquery).desc(), KnowledgeChunk.id).limit(50))).all()
                rankings.extend([[_hit(*row) for row in vector_rows], [_hit(*row) for row in text_rows]])
        for collection in collections:
            if collection.retrieval_provider == "dify":
                rankings.append(await DifyKnowledgeRetriever(self.session, self.principal,
                    self.settings, collection).retrieve(query, policy))
        result = reciprocal_rank_fusion(*rankings, limit=policy.limit, per_source_limit=policy.per_source_limit)
        _RETRIEVAL_CACHE.put(cache_key, result)
        return result


class DifyKnowledgeRetriever:
    def __init__(self, session, principal, settings, collection):
        self.session, self.principal, self.settings, self.collection = session, principal, settings, collection

    async def retrieve(self, query: str, policy: RetrievalPolicy) -> list[KnowledgeHit]:
        from app.integrations.dify import DifyClient
        from app.services.integration import resolve_settings
        self.principal.require(Permission.AGENT_CHAT)
        if (policy.organization_id != self.principal.organization_id or
            self.collection.organization_id != policy.organization_id or
            self.collection.id not in policy.collection_ids or not self.collection.is_enabled):
            raise ResourceNotFoundError("knowledge collection not found")
        if policy.metadata_filter:
            raise InvalidConfigurationError("Dify metadata filtering is not supported by this connector")
        scoped = await resolve_settings(self.session, self.principal, IntegrationKind.DIFY, settings=self.settings)
        client = DifyClient(scoped)
        try:
            rows = await client.retrieve(query, top_k=policy.limit, score_threshold=policy.min_similarity)
        finally:
            await client.aclose()
        namespace = self.collection.id
        result = []
        for ordinal, row in enumerate(rows[:policy.limit]):
            source_id = uuid.uuid5(namespace, row.document_id or row.document_name)
            digest = hashlib.sha256(row.content.encode()).hexdigest()
            chunk_id = uuid.uuid5(namespace, f"{source_id}:{row.segment_id}:{digest}")
            result.append(KnowledgeHit(chunk_id, source_id, row.content[:4000], row.score,
                KnowledgeCitation(namespace, source_id, uuid.uuid5(source_id, digest),
                    row.document_name, None, None, ordinal, digest, provider="dify")))
        return result
