"""The HTTP entry point must use the existing JWT/API-key authentication path."""
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import _deny_list, _settings, current_principal
from app.core.config import Settings
from app.db.session import get_db
from app.graphql.schema import graphql_router
from app.services.context import Principal


def test_graphql_requires_bearer_before_business_queries():
    from app.api.app import create_app

    app = create_app(Settings(_env_file=None))

    async def no_database():
        yield None

    app.dependency_overrides[get_db] = no_database
    app.dependency_overrides[_deny_list] = lambda: None
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/api/graphql", json={"query": "{ system { apiVersion } }"})
    assert response.status_code == 401


def test_graphql_authentication_context_keeps_scoped_principal():
    app = FastAPI()
    app.include_router(graphql_router, prefix="/api/graphql")
    principal = Principal.for_api_key(organization_id=uuid.uuid4(), scopes=frozenset())
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[_settings] = lambda: Settings(_env_file=None)
    response = TestClient(app).post(
        "/api/graphql", json={"query": "{ agentDefinitions { nodes { name } } }"}
    )
    assert response.status_code == 200
    assert response.json()["errors"][0]["extensions"]["code"] == "PERMISSION_DENIED"
