"""Knowledge administration and cited retrieval over existing tenant services."""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, File, Query, UploadFile
from sqlalchemy import and_, select

from app.api.deps import DbSession, PrincipalDep, SettingsDep, StorageDep
from app.core.errors import ConflictError, InvalidConfigurationError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.knowledge import (
    KnowledgeChunk,
    KnowledgeCollection,
    KnowledgeFeedback,
    KnowledgeSource,
)
from app.db.repository import tenant_select
from app.schemas.knowledge import (
    KnowledgeCollectionCreateIn,
    KnowledgeCollectionOut,
    KnowledgeFeedbackIn,
    KnowledgeSearchIn,
    KnowledgeSourceOut,
)
from app.services.knowledge_extractors import DEFAULT_MAX_DOCUMENT_BYTES, KnowledgeExtractionError
from app.services.knowledge_ingest import (
    create_collection,
    restore_source,
    store_source,
    tombstone_source,
)
from app.services.knowledge_retrieval import (
    InternalKnowledgeRetriever,
    KnowledgeHit,
    RetrievalPolicy,
)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("/collections", response_model=list[KnowledgeCollectionOut])
async def collections(principal: PrincipalDep, session: DbSession,
                      limit: Annotated[int, Query(ge=1, le=200)] = 100):
    principal.require(Permission.AGENT_CHAT)
    return list((await session.scalars(tenant_select(KnowledgeCollection, principal.organization_id)
        .order_by(KnowledgeCollection.name, KnowledgeCollection.id).limit(limit))).all())


@router.post("/collections", response_model=KnowledgeCollectionOut, status_code=201)
async def add_collection(payload: KnowledgeCollectionCreateIn, principal: PrincipalDep, session: DbSession):
    row = await create_collection(session, principal, payload)
    await session.commit()
    return row


@router.get("/collections/{collection_id}/sources", response_model=list[KnowledgeSourceOut])
async def sources(collection_id: uuid.UUID, principal: PrincipalDep, session: DbSession,
                  limit: Annotated[int, Query(ge=1, le=200)] = 100,
                  offset: Annotated[int, Query(ge=0)] = 0):
    principal.require(Permission.AGENT_CHAT)
    collection = await session.scalar(tenant_select(KnowledgeCollection, principal.organization_id)
        .where(KnowledgeCollection.id == collection_id))
    if collection is None:
        raise ResourceNotFoundError("knowledge collection not found")
    return list((await session.scalars(tenant_select(KnowledgeSource, principal.organization_id)
        .where(KnowledgeSource.collection_id == collection_id)
        .order_by(KnowledgeSource.created_at.desc(), KnowledgeSource.id).limit(limit).offset(offset))).all())


@router.post("/collections/{collection_id}/sources", response_model=KnowledgeSourceOut, status_code=201)
async def upload_source(collection_id: uuid.UUID, principal: PrincipalDep, session: DbSession,
                        storage: StorageDep, file: Annotated[UploadFile, File()]):
    principal.require(Permission.ORG_MANAGE)
    try:
        data = await file.read(DEFAULT_MAX_DOCUMENT_BYTES + 1)
        row = await store_source(session, principal, collection_id,
            filename=file.filename or "document", data=data,
            mime_type=file.content_type or "application/octet-stream", storage=storage)
    except KnowledgeExtractionError as error:
        raise InvalidConfigurationError(error.error_code, user_message=error.error_code.replace("_", " ")) from error
    finally:
        await file.close()
    await session.commit()
    return row


@router.delete("/sources/{source_id}", response_model=KnowledgeSourceOut)
async def delete_source(source_id: uuid.UUID, principal: PrincipalDep, session: DbSession):
    row = await tombstone_source(session, principal, source_id)
    await session.commit()
    return row


@router.post("/sources/{source_id}/restore", response_model=KnowledgeSourceOut)
async def restore_deleted_source(source_id: uuid.UUID, principal: PrincipalDep, session: DbSession):
    row = await restore_source(session, principal, source_id)
    await session.commit()
    return row


@router.post("/sources/{source_id}/retry", response_model=KnowledgeSourceOut)
async def retry_source(source_id: uuid.UUID, principal: PrincipalDep, session: DbSession):
    principal.require(Permission.ORG_MANAGE)
    source = (await session.execute(tenant_select(KnowledgeSource, principal.organization_id)
        .where(KnowledgeSource.id == source_id).with_for_update())).scalar_one_or_none()
    if source is None:
        raise ResourceNotFoundError("knowledge source not found")
    if source.status != "failed" or source.error_code == "storage_failed":
        raise ConflictError("Only an indexing failure can be retried. Re-upload a storage failure.")
    source.status, source.error_code, source.error_detail = "stored", None, None
    source.lease_generation += 1
    source.index_attempts, source.lease_until, source.next_index_at = 0, None, None
    await session.commit()
    return source


@router.post("/search", response_model=list[KnowledgeHit])
async def search(payload: KnowledgeSearchIn, principal: PrincipalDep, session: DbSession,
                 settings: SettingsDep):
    policy = RetrievalPolicy(principal.organization_id, tuple(payload.collection_ids),
        limit=payload.limit, min_similarity=payload.min_similarity)
    return await InternalKnowledgeRetriever(session, principal, settings).retrieve(payload.query, policy)


@router.post("/feedback", status_code=201)
async def feedback(payload: KnowledgeFeedbackIn, principal: PrincipalDep, session: DbSession):
    principal.require(Permission.AGENT_CHAT)
    chunk = await session.scalar(select(KnowledgeChunk).join(KnowledgeSource,
        and_(KnowledgeSource.current_version_id == KnowledgeChunk.source_version_id,
             KnowledgeSource.organization_id == KnowledgeChunk.organization_id))
        .where(KnowledgeChunk.id == payload.chunk_id,
               KnowledgeChunk.organization_id == principal.organization_id,
               KnowledgeSource.status == "ready", KnowledgeSource.tombstoned_at.is_(None)))
    if chunk is None:
        raise ResourceNotFoundError("knowledge chunk not found")
    row = KnowledgeFeedback(id=uuid.uuid4(), organization_id=principal.organization_id,
                            reviewed_by_id=principal.user_id, **payload.model_dump())
    session.add(row)
    await session.commit()
    return {"id": row.id}
