"""The public GraphQL entry point is stable and mounted once."""

from __future__ import annotations

from app.api.app import create_app
from app.core.config import Settings
from app.graphql.schema import schema


def test_schema_exposes_system_version_and_capabilities() -> None:
    result = schema.execute_sync("{ system { apiVersion capabilities } }")

    assert result.errors is None
    assert result.data is not None
    assert result.data["system"]["apiVersion"]
    assert "graphql" in result.data["system"]["capabilities"]


def test_graphql_router_is_mounted_once() -> None:
    app = create_app(Settings(_env_file=None))
    post_routes = [
        route
        for route in app.routes
        if route.path == "/api/graphql" and "POST" in getattr(route, "methods", set())
    ]

    assert len(post_routes) == 1
