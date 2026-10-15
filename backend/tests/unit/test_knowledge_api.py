"""Validate the mounted wire contracts without requiring a database or paid provider."""
from fastapi import FastAPI


def test_knowledge_routes_have_valid_openapi_and_response_schemas():
    from app.api.v1.knowledge import router
    app = FastAPI()
    app.include_router(router, prefix='/api/v1')
    schema = app.openapi()
    assert '/api/v1/knowledge/collections' in schema['paths']
    assert '/api/v1/knowledge/search' in schema['paths']
    assert '/api/v1/knowledge/sources/{source_id}/retry' in schema['paths']
    assert 'KnowledgeHit' in schema['components']['schemas']
