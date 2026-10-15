"""Embedding validation and durable indexing fences require no provider credentials."""
import datetime as dt
import uuid
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("vector", [[1.0] * 1535, [float('nan')] * 1536, [float('inf')] * 1536, [0.0] * 1536])
def test_bad_vectors_cannot_be_persisted(vector):
    from app.services.embedding import EmbeddingDimensionError, validate_vectors
    with pytest.raises(EmbeddingDimensionError):
        validate_vectors([vector], expected=1)


def test_vectors_validate_cardinality_and_normalize():
    from app.services.embedding import EmbeddingDimensionError, validate_vectors
    with pytest.raises(EmbeddingDimensionError):
        validate_vectors([], expected=1)
    result = validate_vectors([[3.0, 4.0] + [0.0] * 1534], expected=1)
    assert result[0][:2] == pytest.approx([0.6, 0.8])


def test_index_lease_rejects_deleted_revised_expired_and_reclaimed_source():
    from app.services.knowledge_indexer import IndexLease, lease_matches
    now = dt.datetime.now(dt.UTC)
    lease = IndexLease(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 3)
    source = SimpleNamespace(id=lease.source_id, organization_id=lease.organization_id,
        current_version_id=lease.version_id, lease_generation=3,
        lease_until=now + dt.timedelta(seconds=60), status='embedding', tombstoned_at=None)
    assert lease_matches(source, lease, now=now)
    for field, value in [('status', 'deleted'), ('lease_generation', 4),
                         ('current_version_id', uuid.uuid4()), ('organization_id', uuid.uuid4()),
                         ('lease_until', now - dt.timedelta(seconds=1))]:
        changed = SimpleNamespace(**(vars(source) | {field: value}))
        assert not lease_matches(changed, lease, now=now)


@pytest.mark.asyncio
async def test_openai_adapter_orders_vectors_by_index_and_requests_fixed_dimensions():
    from app.services.embedding import EmbeddingProfile, OpenAIEmbeddingProvider
    calls = []
    class Client:
        @property
        def embeddings(self):
            return self
        async def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(data=[
                SimpleNamespace(index=1, embedding=[0., 1.] + [0.] * 1534),
                SimpleNamespace(index=0, embedding=[1., 0.] + [0.] * 1534)])
    provider = OpenAIEmbeddingProvider(Client(), EmbeddingProfile('openai', 'text-embedding-3-small'))
    vectors = await provider.embed(['one', 'two'])
    assert calls[0]['dimensions'] == 1536
    assert vectors[0][:2] == [1., 0.]


@pytest.mark.asyncio
async def test_gemini_adapter_requests_1536_and_document_task_type():
    from app.services.embedding import EmbeddingProfile, GoogleEmbeddingProvider
    calls = []
    class Client:
        async def embed_content(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(embeddings=[SimpleNamespace(values=[1.] * 1536)])
    provider = GoogleEmbeddingProvider(Client(), EmbeddingProfile('google', 'gemini-embedding-001'))
    assert len((await provider.embed(['runbook']))[0]) == 1536
    assert calls[0]['config']['output_dimensionality'] == 1536
    assert calls[0]['config']['task_type'] == 'RETRIEVAL_DOCUMENT'


def test_embedding_profiles_reject_unknown_models_and_dimensions():
    from app.services.embedding import EmbeddingProfile
    with pytest.raises(ValueError):
        EmbeddingProfile('anthropic', 'claude')
    with pytest.raises(ValueError):
        EmbeddingProfile('openai', 'text-embedding-ada-002')


@pytest.mark.asyncio
async def test_invalid_batch_cannot_write_before_all_vectors_are_valid():
    from app.services.embedding import EmbeddingDimensionError
    from app.services.knowledge_indexer import IndexLease, finish_index_batch
    class NoDatabaseWrites:
        async def execute(self, statement):
            pytest.fail('invalid vector reached the database')
    with pytest.raises(EmbeddingDimensionError):
        await finish_index_batch(NoDatabaseWrites(), IndexLease(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 1),
            [object()], [[1.] * 1535], profile='test')


@pytest.mark.asyncio
async def test_deleted_source_cannot_be_resurrected_by_late_batch():
    from app.services.knowledge_indexer import IndexLease, finish_index_batch
    lease = IndexLease(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 1)
    class Session:
        async def execute(self, statement):
            assert statement.is_select
            return SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(
                id=lease.source_id, organization_id=lease.organization_id,
                current_version_id=lease.version_id, lease_generation=1, status='deleted',
                lease_until=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=60), tombstoned_at=None))
    assert not await finish_index_batch(Session(), lease, [object()], [[1.] * 1536], profile='test')
