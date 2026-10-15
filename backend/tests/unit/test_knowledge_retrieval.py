import uuid

from sqlalchemy.dialects import postgresql


def _hit(source, ordinal, chunk=None):
    from app.services.knowledge_retrieval import KnowledgeCitation, KnowledgeHit
    return KnowledgeHit(chunk_id=chunk or uuid.uuid4(), source_id=source,
        text='Approved runbook text', score=0, citation=KnowledgeCitation(
            collection_id=uuid.uuid4(), source_id=source, source_version_id=uuid.uuid4(),
            filename='runbook.md', page=1, section='Operations', ordinal=ordinal, content_hash='a'*64))


def test_fusion_is_stable_deduplicates_and_limits_adjacent_chunks():
    from app.services.knowledge_retrieval import reciprocal_rank_fusion
    source = uuid.uuid4()
    a, b, c = _hit(source, 0), _hit(source, 1), _hit(uuid.uuid4(), 0)
    result = reciprocal_rank_fusion([a, b, c], [c, a], limit=3)
    assert {hit.chunk_id for hit in result} == {a.chunk_id, c.chunk_id}
    assert result == reciprocal_rank_fusion([a, b, c], [c, a], limit=3)


def test_retrieval_query_contains_tenant_version_tombstone_and_profile_predicates():
    from app.services.knowledge_retrieval import RetrievalPolicy, candidate_statement
    org, collection = uuid.uuid4(), uuid.uuid4()
    policy = RetrievalPolicy(organization_id=org, collection_ids=(collection,))
    sql = candidate_statement(policy, profile='openai:test:1536:v1')
    compiled = sql.compile(dialect=postgresql.dialect())
    rendered = str(compiled)
    assert 'current_version_id' in rendered
    assert 'tombstoned_at IS NULL' in rendered
    assert 'knowledge_sources.status' in rendered
    assert 'knowledge_collections.is_enabled IS true' in rendered
    assert org in compiled.params.values()
    assert 'openai:test:1536:v1' in compiled.params.values()


def test_empty_collection_allowlist_does_not_expand_to_all_tenant_knowledge():
    import pytest

    from app.services.knowledge_retrieval import RetrievalPolicy
    with pytest.raises(ValueError):
        RetrievalPolicy(organization_id=uuid.uuid4(), collection_ids=())


def test_cache_key_changes_with_tenant_revision_profile_and_policy():
    from app.services.knowledge_retrieval import RetrievalPolicy, retrieval_cache_key
    org, collection = uuid.uuid4(), uuid.uuid4()
    policy = RetrievalPolicy(org, (collection,), limit=4, metadata_filter={"environment": "prod"})
    base = retrieval_cache_key("CAB Wednesday", policy,
        collection_revisions=[(collection, 3)], profiles=["openai:model:1536:v1"])
    assert base == retrieval_cache_key(" CAB   Wednesday ", policy,
        collection_revisions=[(collection, 3)], profiles=["openai:model:1536:v1"])
    assert base != retrieval_cache_key("CAB Wednesday", policy,
        collection_revisions=[(collection, 4)], profiles=["openai:model:1536:v1"])
    assert base != retrieval_cache_key("CAB Wednesday", policy,
        collection_revisions=[(collection, 3)], profiles=["google:model:1536:v1"])
    assert base != retrieval_cache_key("CAB Wednesday", RetrievalPolicy(org, (collection,), limit=8),
        collection_revisions=[(collection, 3)], profiles=["openai:model:1536:v1"])
