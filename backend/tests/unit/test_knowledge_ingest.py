"""Bounded, deterministic and tenant-safe first-party knowledge ingestion."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from pypdf import PdfWriter

from app.db.enums import Role
from app.db.models.knowledge import KnowledgeCollection, KnowledgeSource, KnowledgeSourceVersion
from app.schemas.knowledge import KnowledgeCollectionCreateIn
from app.services.context import Principal


def _encrypted_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt("test-password")
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


@pytest.mark.parametrize(
    ("payload", "mime_type", "error_code"),
    [
        (b"", "text/plain", "empty_document"),
        (b"%PDF-1.7 broken", "application/pdf", "invalid_pdf"),
        (_encrypted_pdf(), "application/pdf", "encrypted_pdf"),
    ],
)
def test_bad_documents_settle_with_stable_code(
    payload: bytes, mime_type: str, error_code: str
) -> None:
    from app.services.knowledge_extractors import KnowledgeExtractionError, extract_document

    with pytest.raises(KnowledgeExtractionError, match=error_code) as raised:
        extract_document(payload, mime_type=mime_type)

    assert raised.value.error_code == error_code


def test_text_extraction_normalizes_unicode_and_preserves_heading_provenance() -> None:
    from app.services.knowledge_extractors import extract_document

    blocks = extract_document(
        "# Re\u0301sume\u0301 Policy\r\nUse\u00a0MFA on every admin account.\x00".encode(),
        mime_type="text/markdown",
    )

    assert blocks[0].section == "Résumé Policy"
    assert "Résumé Policy" in blocks[0].text
    assert "\r" not in blocks[0].text
    assert "\x00" not in blocks[0].text


def test_repeated_pdf_furniture_is_removed_without_losing_page_provenance() -> None:
    from app.services.knowledge_extractors import ExtractedBlock, remove_repeated_furniture

    blocks = [
        ExtractedBlock("CONFIDENTIAL\nPage body one\nAcme Security", page=1, section=None),
        ExtractedBlock("CONFIDENTIAL\nPage body two\nAcme Security", page=2, section=None),
        ExtractedBlock("CONFIDENTIAL\nPage body three\nAcme Security", page=3, section=None),
    ]

    cleaned = remove_repeated_furniture(blocks)

    assert [block.page for block in cleaned] == [1, 2, 3]
    assert all("CONFIDENTIAL" not in block.text for block in cleaned)
    assert all("Acme Security" not in block.text for block in cleaned)
    assert "Page body two" in cleaned[1].text


def test_chunks_are_bounded_deterministic_and_keep_overlap_and_provenance() -> None:
    from app.services.knowledge_extractors import ExtractedBlock, chunk_document

    text = " ".join(f"word{index}" for index in range(75))
    blocks = [ExtractedBlock(text, page=7, section="Incident Response")]

    first = chunk_document(blocks, max_tokens=24, overlap_tokens=5)
    second = chunk_document(blocks, max_tokens=24, overlap_tokens=5)

    assert first == second
    assert len(first) > 1
    assert all(chunk.token_count <= 24 for chunk in first)
    assert all(chunk.page == 7 and chunk.section == "Incident Response" for chunk in first)
    assert first[0].text.split()[-5:] == first[1].text.split()[:5]
    assert len({chunk.content_hash for chunk in first}) == len(first)


def test_upload_limits_reject_unsupported_or_oversized_content() -> None:
    from app.services.knowledge_extractors import KnowledgeExtractionError, validate_upload

    with pytest.raises(KnowledgeExtractionError, match="unsupported_media_type"):
        validate_upload(b"{}", "application/zip")
    with pytest.raises(KnowledgeExtractionError, match="document_too_large"):
        validate_upload(b"x" * 11, "text/plain", max_bytes=10)


class _Result:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def one(self):
        return self.value if self.value is not None else (0, 0)


class _Session:
    def __init__(self, *results: Any) -> None:
        self.results = [_Result(value) for value in results]
        self.added: list[Any] = []
        self.flush_count = 0

    async def execute(self, _statement: Any) -> _Result:
        return self.results.pop(0) if self.results else _Result()

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flush_count += 1


class _Storage:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes, dict[str, Any]]] = []

    async def put_bytes(self, key: str, data: bytes, **kwargs: Any) -> SimpleNamespace:
        self.calls.append((key, data, kwargs))
        return SimpleNamespace(storage_key=key, size_bytes=len(data))


@pytest.fixture
def owner() -> Principal:
    return Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)


@pytest.fixture(autouse=True)
def disable_audit(monkeypatch):
    from app.services import audit
    async def record(*args, **kwargs):
        pass
    monkeypatch.setattr(audit, "record", record)


@pytest.mark.asyncio
async def test_create_collection_normalizes_name_and_sets_tenant(owner: Principal) -> None:
    from app.services.knowledge_ingest import create_collection

    session = _Session(None)
    collection = await create_collection(
        session,
        owner,
        KnowledgeCollectionCreateIn(name="  Runbooks  ", description="Approved procedures"),
    )

    assert collection.name == "Runbooks"
    assert collection.organization_id == owner.organization_id
    assert collection.revision == 1
    assert session.added == [collection]


@pytest.mark.asyncio
async def test_store_source_is_tenant_scoped_hash_deduplicated_and_staged(owner: Principal) -> None:
    from app.services.knowledge_ingest import store_source

    collection = KnowledgeCollection(
        id=uuid.uuid4(), organization_id=owner.organization_id, name="Runbooks", is_enabled=True, retrieval_provider="internal"
    )
    session = _Session(collection, None)
    storage = _Storage()

    source = await store_source(
        session,
        owner,
        collection.id,
        filename="Incident Response.md",
        data=b"# Incident Response\nIsolate the host.",
        mime_type="text/markdown",
        storage=storage,
    )

    version = next(row for row in session.added if isinstance(row, KnowledgeSourceVersion))
    assert source.status == "stored"
    assert source.current_version_id == version.id
    assert source.content_hash == version.content_hash
    assert storage.calls[0][0].startswith(f"org/{owner.organization_id}/knowledge/")
    assert storage.calls[0][2]["organization_id"] == owner.organization_id


@pytest.mark.asyncio
async def test_duplicate_source_reuses_row_without_upload(owner: Principal) -> None:
    from app.services.knowledge_ingest import store_source

    collection = KnowledgeCollection(
        id=uuid.uuid4(), organization_id=owner.organization_id, name="Runbooks", is_enabled=True, retrieval_provider="internal"
    )
    existing = KnowledgeSource(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        collection_id=collection.id,
        filename="existing.md",
        object_key="org/existing",
        mime_type="text/markdown",
        content_hash=hashlib.sha256(b"same").hexdigest(),
        size_bytes=4,
        status="ready",
    )
    session = _Session(collection, existing)
    storage = _Storage()

    returned = await store_source(
        session,
        owner,
        collection.id,
        filename="duplicate.md",
        data=b"same",
        mime_type="text/markdown",
        storage=storage,
    )

    assert returned is existing
    assert storage.calls == []
    assert session.added == []


@pytest.mark.asyncio
async def test_storage_failure_marks_source_failed_instead_of_leaving_storing(owner: Principal) -> None:
    from app.services.knowledge_ingest import store_source

    collection = KnowledgeCollection(
        id=uuid.uuid4(), organization_id=owner.organization_id, name="Runbooks", is_enabled=True, retrieval_provider="internal"
    )
    session = _Session(collection, None)

    class BrokenStorage(_Storage):
        async def put_bytes(self, key: str, data: bytes, **kwargs: Any) -> SimpleNamespace:
            raise RuntimeError("provider detail that must not be persisted")

    failed = await store_source(
            session,
            owner,
            collection.id,
            filename="runbook.txt",
            data=b"Recover safely",
            mime_type="text/plain",
            storage=BrokenStorage(),
    )

    source = next(row for row in session.added if isinstance(row, KnowledgeSource))
    assert source.status == "failed"
    assert failed is source
    assert source.error_code == "storage_failed"
    assert source.error_detail is None


@pytest.mark.asyncio
async def test_tombstone_is_tenant_scoped_and_invalidates_collection_revision(owner: Principal) -> None:
    from app.services.knowledge_ingest import tombstone_source

    collection = KnowledgeCollection(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        name="Runbooks",
        is_enabled=True,
        revision=2,
    )
    source = KnowledgeSource(
        id=uuid.uuid4(),
        organization_id=owner.organization_id,
        collection_id=collection.id,
        filename="old.txt",
        object_key="org/old",
        mime_type="text/plain",
        content_hash="b" * 64,
        size_bytes=3,
        status="ready",
    )
    session = _Session(source, collection)

    deleted = await tombstone_source(session, owner, source.id)

    assert deleted.status == "deleted"
    assert deleted.tombstoned_at is not None
    assert collection.revision == 3


@pytest.mark.asyncio
async def test_restore_requeues_deleted_source_and_invalidates_collection(owner: Principal) -> None:
    from app.services.knowledge_ingest import restore_source
    collection = KnowledgeCollection(id=uuid.uuid4(), organization_id=owner.organization_id,
        name="Runbooks", is_enabled=True, revision=4)
    source = KnowledgeSource(id=uuid.uuid4(), organization_id=owner.organization_id,
        collection_id=collection.id, filename="old.txt", object_key="org/old",
        mime_type="text/plain", content_hash="c" * 64, size_bytes=3, status="deleted",
        tombstoned_at=dt.datetime.now(dt.UTC), index_attempts=5, error_code="old_error")
    restored = await restore_source(_Session(source, collection), owner, source.id)
    assert restored.status == "stored" and restored.tombstoned_at is None
    assert restored.index_attempts == 0 and restored.error_code is None
    assert collection.revision == 5
