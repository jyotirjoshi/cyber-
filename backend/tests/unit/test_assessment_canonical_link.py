"""Assessment reports retain the exact canonical findings a scan observed."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import Select


class _Rows:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class _Session:
    def __init__(self, finding_ids):
        self.finding_ids = finding_ids
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        if isinstance(statement, Select):
            return _Rows(self.finding_ids)
        return type("Result", (), {"rowcount": len(set(self.finding_ids))})()


@pytest.mark.asyncio
async def test_cloud_observations_link_distinct_findings_only_to_own_tenant() -> None:
    from app.services.canonical_ingest import link_scan_observations

    tenant, assessment, job = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    finding_a, finding_b = uuid.uuid4(), uuid.uuid4()
    session = _Session([finding_a, finding_a, finding_b])
    linked = await link_scan_observations(
        session,
        organization_id=tenant,
        assessment_id=assessment,
        job_id=job,
        provider="prowler",
        external_ids=["check-1", "check-2"],
    )

    assert linked == 2
    select_sql = session.statements[0].compile(dialect=postgresql.dialect())
    assert tenant in select_sql.params.values()
    assert "prowler" in select_sql.params.values()
    assert set(select_sql.params.get("external_id_1", [])) == {"check-1", "check-2"}
    insert_sql = session.statements[1].compile(dialect=postgresql.dialect())
    values = list(insert_sql.params.values())
    assert values.count(tenant) == 2
    assert values.count(assessment) == 2
    assert values.count(job) == 2
    assert {finding_a, finding_b}.issubset(values)


@pytest.mark.asyncio
async def test_no_observations_does_not_create_assessment_links() -> None:
    from app.services.canonical_ingest import link_scan_observations

    session = _Session([])
    linked = await link_scan_observations(
        session,
        organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        provider="prowler",
        external_ids=[],
    )
    assert linked == 0
    assert session.statements == []
