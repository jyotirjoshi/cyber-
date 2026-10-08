"""Canonical findings are a first-class, tenant-scoped API resource."""

import datetime as dt
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from sqlalchemy.dialects import postgresql

from app.api.v1.router import api_router
from app.db.enums import Role
from app.schemas.canonical import CanonicalFindingOut
from app.schemas.common import PaginationParams
from app.services.canonical_query import list_canonical_findings
from app.services.context import Principal


def test_canonical_findings_list_and_detail_are_mounted() -> None:
    app = FastAPI()
    app.include_router(api_router, prefix="/api/v1")
    paths = app.openapi()["paths"]
    assert "get" in paths["/api/v1/canonical-findings"]
    assert "get" in paths["/api/v1/canonical-findings/{finding_id}"]
    assert "patch" in paths["/api/v1/canonical-findings/{finding_id}/status"]
    assert "post" in paths["/api/v1/canonical-findings/{finding_id}/tickets"]


def test_canonical_response_exposes_score_and_explanation() -> None:
    now = dt.datetime.now(dt.UTC)
    finding = SimpleNamespace(
        id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        title="Risk",
        severity="high",
        status="open",
        cve_ids=["CVE-2024-12345"],
        first_seen_at=now,
        last_seen_at=now,
        closed_at=None,
        status_version=1,
        risk_score=67.5,
        risk_factors={"inputs": {"in_kev": True}},
    )

    payload = CanonicalFindingOut.model_validate(finding)

    assert payload.risk_score == 67.5
    assert payload.risk_factors["inputs"]["in_kev"] is True


@pytest.mark.asyncio
async def test_my_overdue_queue_filters_count_and_rows() -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=Role.SECURITY_ENGINEER,
    )
    session = AsyncMock()
    count = MagicMock()
    count.scalar_one.return_value = 0
    rows = MagicMock()
    rows.scalars.return_value.all.return_value = []
    session.execute.side_effect = [count, rows]

    await list_canonical_findings(
        session,
        principal,
        PaginationParams(limit=25, offset=0),
        mine=True,
        overdue=True,
    )

    for call in session.execute.call_args_list:
        statement = call.args[0]
        compiled = statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)
        assert "assignee_user_id =" in sql
        assert "due_at <" in sql
        assert "status NOT IN" in sql
        assert principal.user_id in compiled.params.values()
