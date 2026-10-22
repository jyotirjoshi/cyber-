from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import current_principal
from app.db.enums import Role
from app.db.session import get_db
from app.schemas.assessment import AssessmentFilter, AssessmentListQuery
from app.schemas.asset import AssetFilter, AssetListQuery
from app.services.context import Principal


def test_asset_collection_accepts_pagination_alongside_strict_filters() -> None:
    query = AssetListQuery(limit=25, offset=10, internet_exposed=True)
    filters = AssetFilter.model_validate(
        query.model_dump(include=set(AssetFilter.model_fields))
    )

    assert query.limit == 25
    assert query.offset == 10
    assert filters.internet_exposed is True


def test_assessment_collection_accepts_frontend_sorting_contract() -> None:
    query = AssessmentListQuery(
        limit=50, sort_by="created_at", sort_dir="desc", active=True
    )
    filters = AssessmentFilter.model_validate(
        query.model_dump(include=set(AssessmentFilter.model_fields))
    )

    assert query.limit == 50
    assert query.sort_by == "created_at"
    assert query.sort_dir == "desc"
    assert filters.active is True


@pytest.mark.parametrize(
    ("module_name", "path", "expected"),
    [
        ("assets", "/api/v1/assets?limit=25&offset=0", (25, 0)),
        (
            "assessments",
            "/api/v1/assessments?limit=50&sort_by=created_at&sort_dir=desc",
            (50, 0),
        ),
    ],
)
def test_fastapi_collection_contract_accepts_frontend_queries(
    monkeypatch, module_name: str, path: str, expected: tuple[int, int]
) -> None:
    from app.api.v1 import assessments, assets

    module = assets if module_name == "assets" else assessments
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER
    )

    async def database():
        yield object()

    async def empty_page(_session, _principal, **kwargs):
        pagination = kwargs["pagination"]
        assert (pagination.limit, pagination.offset) == expected
        return [], 0

    monkeypatch.setattr(
        module.asset_service if module_name == "assets" else module.assessment_service,
        "list_assets" if module_name == "assets" else "list_assessments",
        empty_page,
    )
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[current_principal] = lambda: principal
    app.dependency_overrides[get_db] = database

    response = TestClient(app).get(path)

    assert response.status_code == 200, response.text
    assert response.json()["meta"]["limit"] == expected[0]
