"""Unified, source-preserving exposure feed contracts."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.schemas.common import PaginationParams
from app.services.context import Principal


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def mappings(self):
        return self

    def all(self):
        return self.value


class _Session:
    def __init__(self):
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return _Result(2 if len(self.statements) == 1 else [])


@pytest.mark.asyncio
async def test_exposure_feed_unions_tenant_scoped_sources_without_deduplicating() -> None:
    from app.services.exposure_feed import list_exposures

    organization_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=organization_id, role=Role.VIEWER)
    session = _Session()

    rows, total = await list_exposures(
        session, principal, pagination=PaginationParams(limit=25, offset=25)
    )

    assert rows == []
    assert total == 2
    assert len(session.statements) == 2
    sql = [
        str(statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
        for statement in session.statements
    ]
    for statement in sql:
        assert statement.count(f"organization_id = '{organization_id}'") == 2
        assert "UNION ALL" in statement
        assert "findings" in statement
        assert "external_security_alerts" in statement
    assert "LIMIT 25 OFFSET 25" in sql[1]
    assert "ORDER BY" in sql[1]


@pytest.mark.asyncio
async def test_exposure_feed_filters_source_and_severity_after_union() -> None:
    from app.services.exposure_feed import list_exposures

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.VIEWER)
    session = _Session()
    await list_exposures(session, principal, source="sonarqube", severity="high")
    for statement in session.statements:
        sql = str(statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
        assert "exposures.source = 'sonarqube'" in sql
        assert "exposures.severity = 'high'" in sql


def test_exposure_route_is_mounted_and_has_bounded_filters() -> None:
    from fastapi import FastAPI

    from app.api.v1.router import api_router

    app = FastAPI()
    app.include_router(api_router, prefix="/api/v1")
    path = app.openapi()["paths"]["/api/v1/exposures"]["get"]
    assert path["responses"]["200"]
    parameters = {item["name"]: item for item in path["parameters"]}
    assert "sonarqube" in str(parameters["source"]["schema"])
    assert "severity" in parameters
