"""PTaaS engagement management over canonical assessments and findings."""

from __future__ import annotations

import uuid
from contextlib import suppress
from typing import Annotated, Literal

from fastapi import APIRouter, File, Form, UploadFile, status

from app.api.deps import DbSession, PaginationDep, PrincipalDep, StorageDep
from app.core.errors import InvalidConfigurationError
from app.db.models.engagement import (
    EngagementDocument,
    EngagementMilestone,
    EngagementParticipant,
    EngagementRetestRound,
    EngagementTimeEntry,
)
from app.integrations.storage import engagement_document_key
from app.schemas.common import Page
from app.schemas.engagement import (
    EngagementCreateIn,
    EngagementDocumentCreateIn,
    EngagementDocumentOut,
    EngagementMilestoneCreateIn,
    EngagementMilestoneOut,
    EngagementOut,
    EngagementParticipantCreateIn,
    EngagementParticipantOut,
    EngagementRetestRoundCreateIn,
    EngagementRetestRoundOut,
    EngagementStatusUpdateIn,
    EngagementTimeEntryCreateIn,
    EngagementTimeEntryOut,
)
from app.services import engagement as engagement_service

router = APIRouter(prefix="/engagements", tags=["engagements"])
_MAX_DOCUMENT_BYTES = 25 * 1024 * 1024


@router.get("", response_model=Page[EngagementOut])
async def list_engagements(
    principal: PrincipalDep, session: DbSession, pagination: PaginationDep
) -> Page[EngagementOut]:
    rows, total = await engagement_service.list_engagements(
        session, principal, limit=pagination.limit, offset=pagination.offset
    )
    return Page.build(
        [EngagementOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    payload: EngagementCreateIn, principal: PrincipalDep, session: DbSession
) -> EngagementOut:
    row = await engagement_service.create_engagement(session, principal, payload)
    await session.commit()
    await session.refresh(row)
    return EngagementOut.model_validate(row)


@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(
    engagement_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> EngagementOut:
    row = await engagement_service.get_engagement(session, principal, engagement_id)
    return EngagementOut.model_validate(row)


@router.patch("/{engagement_id}/status", response_model=EngagementOut)
async def update_engagement_status(
    engagement_id: uuid.UUID,
    payload: EngagementStatusUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> EngagementOut:
    row = await engagement_service.update_status(
        session,
        principal,
        engagement_id,
        status=payload.status,
        expected_version=payload.expected_version,
    )
    await session.commit()
    await session.refresh(row)
    return EngagementOut.model_validate(row)


@router.post(
    "/{engagement_id}/participants",
    response_model=EngagementParticipantOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_participant(
    engagement_id: uuid.UUID,
    payload: EngagementParticipantCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> EngagementParticipantOut:
    row = await engagement_service.add_participant(
        session, principal, engagement_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return EngagementParticipantOut.model_validate(row)


@router.post(
    "/{engagement_id}/milestones",
    response_model=EngagementMilestoneOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_milestone(
    engagement_id: uuid.UUID,
    payload: EngagementMilestoneCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> EngagementMilestoneOut:
    row = await engagement_service.add_milestone(
        session, principal, engagement_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return EngagementMilestoneOut.model_validate(row)


@router.post(
    "/{engagement_id}/time-entries",
    response_model=EngagementTimeEntryOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_time_entry(
    engagement_id: uuid.UUID,
    payload: EngagementTimeEntryCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> EngagementTimeEntryOut:
    row = await engagement_service.add_time_entry(
        session, principal, engagement_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return EngagementTimeEntryOut.model_validate(row)


@router.post(
    "/{engagement_id}/documents",
    response_model=EngagementDocumentOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_document(
    engagement_id: uuid.UUID,
    payload: EngagementDocumentCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> EngagementDocumentOut:
    row = await engagement_service.add_document(
        session, principal, engagement_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return EngagementDocumentOut.model_validate(row)


@router.post(
    "/{engagement_id}/documents/upload",
    response_model=EngagementDocumentOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_document(
    engagement_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
    file: Annotated[UploadFile, File()],
    title: Annotated[str, Form(min_length=1, max_length=300)],
    kind: Annotated[
        Literal["scope", "authorization", "evidence", "report", "deliverable", "other"],
        Form(),
    ] = "evidence",
    client_visible: Annotated[bool, Form()] = False,
) -> EngagementDocumentOut:
    await engagement_service.get_engagement(session, principal, engagement_id)
    document_id = uuid.uuid4()
    key = engagement_document_key(
        principal.organization_id,
        engagement_id,
        document_id,
        file.filename or "document",
    )
    stored = None
    try:
        data = await file.read(_MAX_DOCUMENT_BYTES + 1)
        if len(data) > _MAX_DOCUMENT_BYTES:
            raise InvalidConfigurationError(
                "engagement document exceeds 25 MiB",
                user_message="The document is larger than the 25 MiB upload limit.",
            )
        stored = await storage.put_bytes(
            key,
            data,
            content_type=file.content_type or "application/octet-stream",
            organization_id=principal.organization_id,
            metadata={"engagement_id": str(engagement_id), "kind": kind},
        )
        row = await engagement_service.add_document(
            session,
            principal,
            engagement_id,
            EngagementDocumentCreateIn(
                title=title,
                kind=kind,
                storage_key=stored.storage_key,
                content_type=stored.content_type,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                client_visible=client_visible,
            ),
            document_id=document_id,
        )
        await session.commit()
        await session.refresh(row)
        return EngagementDocumentOut.model_validate(row)
    except BaseException:
        if stored is not None:
            with suppress(Exception):
                await storage.delete(key, organization_id=principal.organization_id)
        raise
    finally:
        await file.close()


@router.post(
    "/{engagement_id}/retest-rounds",
    response_model=EngagementRetestRoundOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_retest_round(
    engagement_id: uuid.UUID,
    payload: EngagementRetestRoundCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> EngagementRetestRoundOut:
    row = await engagement_service.create_retest_round(
        session, principal, engagement_id, payload
    )
    await session.commit()
    await session.refresh(row)
    return EngagementRetestRoundOut.model_validate(row)


async def _list_children(
    session: DbSession,
    principal: PrincipalDep,
    engagement_id: uuid.UUID,
    model,
    projection,
):
    rows = await engagement_service.list_children(
        session, principal, model, engagement_id
    )
    return [projection.model_validate(row) for row in rows]


@router.get("/{engagement_id}/participants", response_model=list[EngagementParticipantOut])
async def list_participants(
    engagement_id: uuid.UUID, principal: PrincipalDep, session: DbSession
):
    return await _list_children(
        session, principal, engagement_id, EngagementParticipant, EngagementParticipantOut
    )


@router.get("/{engagement_id}/milestones", response_model=list[EngagementMilestoneOut])
async def list_milestones(
    engagement_id: uuid.UUID, principal: PrincipalDep, session: DbSession
):
    return await _list_children(
        session, principal, engagement_id, EngagementMilestone, EngagementMilestoneOut
    )


@router.get("/{engagement_id}/time-entries", response_model=list[EngagementTimeEntryOut])
async def list_time_entries(
    engagement_id: uuid.UUID, principal: PrincipalDep, session: DbSession
):
    return await _list_children(
        session, principal, engagement_id, EngagementTimeEntry, EngagementTimeEntryOut
    )


@router.get("/{engagement_id}/documents", response_model=list[EngagementDocumentOut])
async def list_documents(
    engagement_id: uuid.UUID, principal: PrincipalDep, session: DbSession
):
    return await _list_children(
        session, principal, engagement_id, EngagementDocument, EngagementDocumentOut
    )


@router.get("/{engagement_id}/retest-rounds", response_model=list[EngagementRetestRoundOut])
async def list_retest_rounds(
    engagement_id: uuid.UUID, principal: PrincipalDep, session: DbSession
):
    return await _list_children(
        session, principal, engagement_id, EngagementRetestRound, EngagementRetestRoundOut
    )


__all__ = ["router"]
