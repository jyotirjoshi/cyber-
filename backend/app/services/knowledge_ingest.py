"""Tenant-scoped collection and durable source lifecycle operations."""

from __future__ import annotations

import hashlib
import uuid
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.knowledge import KnowledgeCollection, KnowledgeSource, KnowledgeSourceVersion
from app.db.repository import tenant_select
from app.integrations.storage import ObjectStorage, sanitize_segment, tenant_prefix
from app.schemas.knowledge import KnowledgeCollectionCreateIn
from app.services import audit as audit_service
from app.services.context import Principal
from app.services.knowledge_extractors import validate_upload

DEFAULT_MAX_DOCUMENTS_PER_COLLECTION = 200
DEFAULT_MAX_STORAGE_BYTES_PER_COLLECTION = 200 * 1024 * 1024


class StorageWriter(Protocol):
    async def put_bytes(
        self,
        key: str,
        data: bytes,
        *,
        content_type: str | None = None,
        organization_id: uuid.UUID | str | None = None,
    ) -> object: ...


def source_object_key(
    organization_id: uuid.UUID, collection_id: uuid.UUID, source_id: uuid.UUID, filename: str
) -> str:
    return (
        f"{tenant_prefix(organization_id)}knowledge/{collection_id}/"
        f"sources/{source_id}/{sanitize_segment(filename)}"
    )[:1000]


async def create_collection(
    session: AsyncSession,
    principal: Principal,
    payload: KnowledgeCollectionCreateIn,
) -> KnowledgeCollection:
    principal.require(Permission.ORG_MANAGE)
    name = payload.name.strip()
    if not name:
        raise ValueError("collection name must not be blank")
    duplicate = (
        await session.execute(
            tenant_select(KnowledgeCollection, principal.organization_id).where(
                func.lower(KnowledgeCollection.name) == name.casefold()
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise ConflictError("a knowledge collection with this name already exists")
    collection = KnowledgeCollection(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        name=name,
        description=payload.description,
        retrieval_provider=payload.retrieval_provider,
        retrieval_policy=payload.retrieval_policy,
        is_enabled=True,
        revision=1,
        created_by_id=principal.user_id,
    )
    session.add(collection)
    await session.flush()
    await audit_service.record(
        session, action="knowledge.collection.create", principal=principal,
        resource_type="knowledge_collection", resource_id=collection.id,
        detail={"retrieval_provider": collection.retrieval_provider},
    )
    return collection


async def _enabled_collection(
    session: AsyncSession, principal: Principal, collection_id: uuid.UUID
) -> KnowledgeCollection:
    collection = (
        await session.execute(
            tenant_select(KnowledgeCollection, principal.organization_id).where(
                KnowledgeCollection.id == collection_id,
                KnowledgeCollection.is_enabled.is_(True),
            ).with_for_update()
        )
    ).scalar_one_or_none()
    if collection is None:
        raise ResourceNotFoundError("knowledge collection not found")
    if collection.retrieval_provider != "internal":
        raise ConflictError("Upload documents through the connected Dify dataset for this collection")
    return collection


async def store_source(
    session: AsyncSession,
    principal: Principal,
    collection_id: uuid.UUID,
    *,
    filename: str,
    data: bytes,
    mime_type: str,
    storage: StorageWriter | ObjectStorage,
    max_upload_bytes: int | None = None,
    max_documents_per_collection: int = DEFAULT_MAX_DOCUMENTS_PER_COLLECTION,
    max_storage_bytes_per_collection: int = DEFAULT_MAX_STORAGE_BYTES_PER_COLLECTION,
) -> KnowledgeSource:
    """Store one deduplicated source; failures leave a stable terminal source state."""
    principal.require(Permission.ORG_MANAGE)
    resolved_mime = validate_upload(
        data,
        mime_type,
        **({"max_bytes": max_upload_bytes} if max_upload_bytes is not None else {}),
    )
    safe_filename = filename.strip()
    if not safe_filename or len(safe_filename) > 500:
        raise ValueError("source filenames must contain 1 to 500 characters")
    collection = await _enabled_collection(session, principal, collection_id)
    digest = hashlib.sha256(data).hexdigest()
    existing = (
        await session.execute(
            tenant_select(KnowledgeSource, principal.organization_id).where(
                KnowledgeSource.collection_id == collection_id,
                KnowledgeSource.content_hash == digest,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.status == "deleted":
            raise ConflictError("This document was deleted. Restore it before re-uploading.")
        if existing.status == "failed" and existing.error_code == "storage_failed":
            try:
                await storage.put_bytes(existing.object_key, data, content_type=resolved_mime,
                                        organization_id=principal.organization_id)
            except Exception:
                return existing
            existing.status, existing.error_code = "stored", None
            await session.flush()
        return existing

    count, size = (await session.execute(select(func.count(KnowledgeSource.id),
        func.coalesce(func.sum(KnowledgeSource.size_bytes), 0)).where(
            KnowledgeSource.organization_id == principal.organization_id,
            KnowledgeSource.collection_id == collection_id,
            KnowledgeSource.status != "deleted",
        ))).one()
    if (
        count >= max_documents_per_collection
        or int(size) + len(data) > max_storage_bytes_per_collection
    ):
        raise ConflictError("Collection document or storage limit reached")

    source_id = uuid.uuid4()
    object_key = source_object_key(
        principal.organization_id, collection_id, source_id, safe_filename
    )
    source = KnowledgeSource(
        id=source_id,
        organization_id=principal.organization_id,
        collection_id=collection_id,
        source_type="upload",
        filename=safe_filename,
        object_key=object_key,
        mime_type=resolved_mime,
        content_hash=digest,
        size_bytes=len(data),
        status="storing",
        document_metadata={},
        current_revision=1,
        created_by_id=principal.user_id,
    )
    session.add(source)
    await session.flush()
    version = KnowledgeSourceVersion(
        id=uuid.uuid4(), organization_id=principal.organization_id, source_id=source.id,
        revision=1, object_key=object_key, mime_type=resolved_mime,
        content_hash=digest, size_bytes=len(data), extraction_provenance={},
    )
    session.add(version)
    await session.flush()
    source.current_version_id = version.id
    try:
        await storage.put_bytes(
            object_key,
            data,
            content_type=resolved_mime,
            organization_id=principal.organization_id,
        )
    except Exception:
        source.status = "failed"
        source.error_code = "storage_failed"
        source.error_detail = None
        await session.flush()
        return source
    source.status = "stored"
    collection.revision = int(collection.revision or 0) + 1
    await session.flush()
    # The committed 'stored' row is the durable queue item. A worker claims it
    # with an expiring lease, eliminating a DB/Redis dual-write window.
    await audit_service.record(
        session, action="knowledge.source.upload", principal=principal,
        resource_type="knowledge_source", resource_id=source.id,
        detail={"size_bytes": source.size_bytes, "content_hash": digest},
    )
    return source


async def tombstone_source(
    session: AsyncSession, principal: Principal, source_id: uuid.UUID
) -> KnowledgeSource:
    principal.require(Permission.ORG_MANAGE)
    source = (
        await session.execute(
            tenant_select(KnowledgeSource, principal.organization_id)
            .where(KnowledgeSource.id == source_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if source is None:
        raise ResourceNotFoundError("knowledge source not found")
    if source.status == "deleted":
        return source
    collection = (
        await session.execute(
            tenant_select(KnowledgeCollection, principal.organization_id)
            .where(KnowledgeCollection.id == source.collection_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if collection is None:
        raise ResourceNotFoundError("knowledge source not found")
    source.status = "deleted"
    source.tombstoned_at = utcnow()
    source.error_code = None
    source.error_detail = None
    collection.revision = int(collection.revision or 0) + 1
    await session.flush()
    await audit_service.record(
        session, action="knowledge.source.delete", principal=principal,
        resource_type="knowledge_source", resource_id=source.id, detail={},
    )
    return source


async def restore_source(
    session: AsyncSession, principal: Principal, source_id: uuid.UUID
) -> KnowledgeSource:
    """Restore a retained object and enqueue a fresh, fenced indexing attempt."""
    principal.require(Permission.ORG_MANAGE)
    source = (await session.execute(tenant_select(KnowledgeSource, principal.organization_id)
        .where(KnowledgeSource.id == source_id).with_for_update())).scalar_one_or_none()
    if source is None:
        raise ResourceNotFoundError("knowledge source not found")
    if source.status != "deleted" or source.tombstoned_at is None:
        raise ConflictError("Only a deleted knowledge source can be restored")
    collection = (await session.execute(tenant_select(KnowledgeCollection, principal.organization_id)
        .where(KnowledgeCollection.id == source.collection_id,
               KnowledgeCollection.is_enabled.is_(True)).with_for_update())).scalar_one_or_none()
    if collection is None:
        raise ResourceNotFoundError("knowledge collection not found")
    source.status, source.tombstoned_at = "stored", None
    source.error_code, source.error_detail = None, None
    source.index_attempts, source.next_index_at, source.lease_until = 0, None, None
    source.lease_generation = int(source.lease_generation or 0) + 1
    source.indexed_chunks = 0
    collection.revision = int(collection.revision or 0) + 1
    await session.flush()
    await audit_service.record(session, action="knowledge.source.restore", principal=principal,
        resource_type="knowledge_source", resource_id=source.id, detail={})
    return source


__all__ = [
    "StorageWriter",
    "create_collection",
    "restore_source",
    "source_object_key",
    "store_source",
    "tombstone_source",
]
