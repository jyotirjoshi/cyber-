"""Resumable database-backed indexing with short transactions and fenced leases.

Committed stored sources are queue entries. A lease is committed before I/O; each
batch rechecks generation, version and tombstone under a row lock. Interrupted
workers lose their lease and a new worker resumes missing embeddings only.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import aliased

from app.core.config import Settings
from app.core.errors import InvalidConfigurationError
from app.db.base import utcnow
from app.db.enums import IntegrationKind, Permission, Role
from app.db.models.knowledge import (
    KnowledgeChunk,
    KnowledgeCollection,
    KnowledgeEmbedding,
    KnowledgeSource,
    KnowledgeSourceVersion,
)
from app.db.session import session_scope
from app.integrations.storage import ObjectStorage
from app.services.context import Principal
from app.services.embedding import (
    MAX_BATCH,
    EmbeddingDimensionError,
    EmbeddingProfile,
    embedding_provider,
    validate_vectors,
)
from app.services.knowledge_extractors import (
    KnowledgeExtractionError,
    chunk_document,
    extract_document,
)

LEASE_SECONDS = 180
MAX_ATTEMPTS = 5
BUSY_STATES = ("extracting", "chunking", "embedding")


@dataclass(frozen=True, slots=True)
class IndexLease:
    source_id: uuid.UUID
    organization_id: uuid.UUID
    version_id: uuid.UUID
    generation: int


def lease_matches(source: Any, lease: IndexLease, *, now: dt.datetime | None = None) -> bool:
    return bool(
        source is not None
        and source.id == lease.source_id
        and source.organization_id == lease.organization_id
        and source.current_version_id == lease.version_id
        and source.lease_generation == lease.generation
        and source.status in BUSY_STATES
        and source.tombstoned_at is None
        and source.lease_until is not None
        and source.lease_until > (now or utcnow())
    )


def due_sources_statement(*, now: dt.datetime, limit: int = 20):
    return (
        select(KnowledgeSource.id, KnowledgeSource.organization_id)
        .join(KnowledgeCollection, and_(KnowledgeCollection.id == KnowledgeSource.collection_id,
             KnowledgeCollection.organization_id == KnowledgeSource.organization_id))
        .where(KnowledgeCollection.is_enabled.is_(True),
               KnowledgeCollection.retrieval_provider == "internal",
               KnowledgeSource.tombstoned_at.is_(None),
               KnowledgeSource.current_version_id.is_not(None),
               or_(KnowledgeSource.next_index_at.is_(None), KnowledgeSource.next_index_at <= now),
               or_(KnowledgeSource.status == "stored",
                   and_(KnowledgeSource.status.in_(BUSY_STATES), KnowledgeSource.lease_until <= now)))
        .order_by(KnowledgeSource.next_index_at.asc().nullsfirst(), KnowledgeSource.updated_at,
                  KnowledgeSource.id).limit(limit)
    )


async def claim_source(session, organization_id: uuid.UUID, source_id: uuid.UUID) -> IndexLease | None:
    now = utcnow()
    # Serialize only claims for this tenant. No lock survives the short claim transaction.
    lock_key = int.from_bytes(hashlib.sha256(f"knowledge:{organization_id}".encode()).digest()[:8],
                              byteorder="big", signed=True)
    if not (await session.execute(select(func.pg_try_advisory_xact_lock(lock_key)))).scalar_one():
        return None
    other = aliased(KnowledgeSource)
    source = (await session.execute(
        select(KnowledgeSource).where(
            KnowledgeSource.id == source_id, KnowledgeSource.organization_id == organization_id,
            KnowledgeSource.tombstoned_at.is_(None),
            KnowledgeSource.current_version_id.is_not(None),
            or_(KnowledgeSource.next_index_at.is_(None), KnowledgeSource.next_index_at <= now),
            or_(KnowledgeSource.status == "stored",
                and_(KnowledgeSource.status.in_(BUSY_STATES), KnowledgeSource.lease_until <= now)),
            ~exists(select(other.id).where(other.organization_id == organization_id,
                other.id != source_id, other.status.in_(BUSY_STATES), other.lease_until > now)),
        ).with_for_update(skip_locked=True)
    )).scalar_one_or_none()
    if source is None:
        return None
    if source.index_attempts >= MAX_ATTEMPTS:
        source.status, source.error_code = "failed", "index_retries_exhausted"
        source.lease_until = None
        return None
    collection = (await session.execute(select(KnowledgeCollection).where(
        KnowledgeCollection.id == source.collection_id,
        KnowledgeCollection.organization_id == organization_id,
        KnowledgeCollection.is_enabled.is_(True),
    ))).scalar_one_or_none()
    if collection is None or collection.retrieval_provider != "internal":
        return None
    if not source.embedding_profile:
        try:
            config = (collection.retrieval_policy or {}).get("embedding", {})
            profile = EmbeddingProfile(config.get("provider", "openai"),
                                       config.get("model", "text-embedding-3-small"))
            source.embedding_profile = profile.key
        except (ValueError, AttributeError):
            source.status, source.error_code = "failed", "invalid_embedding_profile"
            return None
    source.lease_generation += 1
    source.index_attempts += 1
    source.lease_until = now + dt.timedelta(seconds=LEASE_SECONDS)
    source.status, source.error_code, source.error_detail = "extracting", None, None
    return IndexLease(source.id, organization_id, source.current_version_id, source.lease_generation)


async def _locked_source(session, lease: IndexLease):
    source = (await session.execute(select(KnowledgeSource).where(
        KnowledgeSource.id == lease.source_id,
        KnowledgeSource.organization_id == lease.organization_id,
    ).with_for_update())).scalar_one_or_none()
    return source if lease_matches(source, lease) else None


async def _enabled(session, source) -> bool:
    return bool((await session.execute(select(KnowledgeCollection.id).where(
        KnowledgeCollection.id == source.collection_id,
        KnowledgeCollection.organization_id == source.organization_id,
        KnowledgeCollection.is_enabled.is_(True),
    ))).scalar_one_or_none())


def missing_embeddings_statement(lease: IndexLease, profile: str):
    return select(KnowledgeChunk).where(
        KnowledgeChunk.organization_id == lease.organization_id,
        KnowledgeChunk.source_version_id == lease.version_id,
        ~exists(select(KnowledgeEmbedding.id).where(
            KnowledgeEmbedding.organization_id == lease.organization_id,
            KnowledgeEmbedding.chunk_id == KnowledgeChunk.id,
            KnowledgeEmbedding.embedding_profile == profile,
            KnowledgeEmbedding.embedding_content_hash == KnowledgeChunk.content_hash,
            KnowledgeEmbedding.status == "ready",
        )),
    ).order_by(KnowledgeChunk.ordinal).limit(MAX_BATCH)


async def finish_index_batch(session, lease: IndexLease, chunks, vectors, *, profile: str) -> bool:
    # Reject the complete batch before any INSERT, including NaN, infinity and zero vectors.
    vectors = validate_vectors(vectors, len(chunks))
    source = await _locked_source(session, lease)
    if source is None or not await _enabled(session, source) or source.embedding_profile != profile:
        return False
    if any(chunk.organization_id != lease.organization_id or
           chunk.source_version_id != lease.version_id for chunk in chunks):
        raise ValueError("index batch does not belong to this source version")
    values = [{"id": uuid.uuid4(), "organization_id": lease.organization_id,
        "chunk_id": chunk.id, "embedding_profile": profile, "embedding": vector, "status": "ready",
        "embedding_content_hash": chunk.content_hash} for chunk, vector in zip(chunks, vectors, strict=True)]
    if values:
        statement = insert(KnowledgeEmbedding).values(values)
        await session.execute(statement.on_conflict_do_update(
            constraint="unique_knowledge_embedding_profile",
            set_={"embedding": statement.excluded.embedding,
                  "embedding_content_hash": statement.excluded.embedding_content_hash,
                  "status": "ready"},
            where=KnowledgeEmbedding.organization_id == lease.organization_id,
        ))
    source.indexed_chunks = int((await session.execute(
        select(func.count()).select_from(KnowledgeChunk).join(KnowledgeEmbedding,
            and_(KnowledgeEmbedding.chunk_id == KnowledgeChunk.id,
                 KnowledgeEmbedding.organization_id == KnowledgeChunk.organization_id))
        .where(KnowledgeChunk.organization_id == lease.organization_id,
               KnowledgeChunk.source_version_id == lease.version_id,
               KnowledgeEmbedding.embedding_profile == profile,
               KnowledgeEmbedding.embedding_content_hash == KnowledgeChunk.content_hash,
               KnowledgeEmbedding.status == "ready")
    )).scalar_one())
    source.lease_until = utcnow() + dt.timedelta(seconds=LEASE_SECONDS)
    source.document_metadata = dict(source.document_metadata or {}) | {
        "embedding_input_bytes": int((source.document_metadata or {}).get("embedding_input_bytes", 0))
            + sum(len(chunk.normalized_text.encode()) for chunk in chunks),
    }
    if source.indexed_chunks == source.total_chunks and source.total_chunks > 0:
        source.status, source.lease_until, source.next_index_at = "ready", None, None
        await session.execute(update(KnowledgeCollection).where(
            KnowledgeCollection.id == source.collection_id,
            KnowledgeCollection.organization_id == lease.organization_id,
        ).values(revision=KnowledgeCollection.revision + 1))
    return True


async def settle_index_failure(session, lease: IndexLease, error: Exception) -> None:
    source = await _locked_source(session, lease)
    if source is None:
        return
    permanent = isinstance(error, KnowledgeExtractionError | EmbeddingDimensionError | InvalidConfigurationError | ValueError)
    source.error_code = (error.error_code if isinstance(error, KnowledgeExtractionError)
                         else "invalid_embedding_response" if isinstance(error, EmbeddingDimensionError)
                         else "embedding_configuration_required" if isinstance(error, InvalidConfigurationError)
                         else "index_failed")
    source.error_detail = None
    source.status = "failed" if permanent or source.index_attempts >= MAX_ATTEMPTS else "stored"
    source.lease_until = None
    source.next_index_at = utcnow() + dt.timedelta(seconds=min(60 * 2 ** source.index_attempts, 1800))


async def index_source(settings: Settings, lease: IndexLease, *, sessions=None, storage=None,
                       provider_factory=embedding_provider) -> bool:
    sessions = sessions or (lambda: session_scope(settings))
    storage = storage or ObjectStorage(settings)
    try:
        async with sessions() as session:
            source = await _locked_source(session, lease)
            if source is None or not await _enabled(session, source):
                return False
            version = (await session.execute(select(KnowledgeSourceVersion).where(
                KnowledgeSourceVersion.id == lease.version_id,
                KnowledgeSourceVersion.organization_id == lease.organization_id,
                KnowledgeSourceVersion.source_id == lease.source_id,
            ))).scalar_one()
            object_key, mime, expected_hash = version.object_key, version.mime_type, version.content_hash
            profile_parts = source.embedding_profile.split(":")
            profile = EmbeddingProfile(profile_parts[0], profile_parts[1])
            has_chunks = source.total_chunks > 0
            # Resolve encrypted tenant credentials before leaving the short transaction.
            from app.services.integration import resolve_settings
            principal = Principal(user_id=None, organization_id=lease.organization_id,
                role=Role.VIEWER, permission_override=frozenset({Permission.INTEGRATION_READ}),
                actor_type="worker")
            scoped = await resolve_settings(session, principal, IntegrationKind.LLM, settings=settings)

        if not has_chunks:
            data = await asyncio.wait_for(storage.get_bytes(object_key,
                organization_id=lease.organization_id), timeout=60)
            if hashlib.sha256(data).hexdigest() != expected_hash:
                raise KnowledgeExtractionError("source_integrity_failed")
            blocks = await asyncio.wait_for(asyncio.to_thread(extract_document, data, mime_type=mime), timeout=30)
            chunks = chunk_document(blocks)
            if len(chunks) > 5000:
                raise KnowledgeExtractionError("too_many_chunks")
            async with sessions() as session:
                source = await _locked_source(session, lease)
                if source is None or not await _enabled(session, source):
                    return False
                source.status = "chunking"
                for start in range(0, len(chunks), 100):
                    values = [{"id": uuid.uuid4(), "organization_id": lease.organization_id,
                        "source_version_id": lease.version_id, "ordinal": chunk.ordinal,
                        "normalized_text": chunk.text, "token_count": chunk.token_count,
                        "page": chunk.page, "section": chunk.section, "content_hash": chunk.content_hash,
                        "chunk_metadata": {"extractor": "cynux-v1"}} for chunk in chunks[start:start+100]]
                    await session.execute(insert(KnowledgeChunk).values(values).on_conflict_do_nothing(
                        constraint="unique_knowledge_chunk_ordinal"))
                source.total_chunks = len(chunks)
                source.status = "embedding"
                source.lease_until = utcnow() + dt.timedelta(seconds=LEASE_SECONDS)

        async with provider_factory(scoped, profile) as provider:
            while True:
                async with sessions() as session:
                    source = await _locked_source(session, lease)
                    if source is None or not await _enabled(session, source):
                        return False
                    chunks = list((await session.scalars(missing_embeddings_statement(lease, profile.key))).all())
                    if not chunks:
                        return await finish_index_batch(session, lease, [], [], profile=profile.key)
                    source.status = "embedding"
                    source.lease_until = utcnow() + dt.timedelta(seconds=LEASE_SECONDS)
                vectors = await asyncio.wait_for(provider.embed([chunk.normalized_text for chunk in chunks]), timeout=60)
                async with sessions() as session:
                    if not await finish_index_batch(session, lease, chunks, vectors, profile=profile.key):
                        return False
                    # Record usage inside the accepted batch transaction.
                    from app.services.usage_metering import MeterEvent, increment
                    await increment(session, organization_id=lease.organization_id,
                                    event=MeterEvent.AI_ANALYSIS_CALL)
                    source = await session.get(KnowledgeSource, lease.source_id)
                    if source.status == "ready":
                        return True
    except asyncio.CancelledError:
        raise  # Expiring lease permits safe recovery after worker shutdown.
    except Exception as error:
        async with sessions() as session:
            await settle_index_failure(session, lease, error)
        return False


async def run_due_knowledge_indexing(settings: Settings) -> int:
    async with session_scope(settings) as session:
        candidates = (await session.execute(due_sources_statement(now=utcnow()))).all()
    for source_id, organization_id in candidates:
        async with session_scope(settings) as session:
            lease = await claim_source(session, organization_id, source_id)
        if lease is not None:
            return int(await index_source(settings, lease))
    return 0
