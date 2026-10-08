"""Cloud-only assessments import canonical findings without DefectDojo."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.db.enums import ScannerName


def _drive(coroutine):
    with pytest.raises(StopIteration) as finished:
        coroutine.send(None)
    return finished.value.value


def test_assessment_counter_refresh_uses_unified_severity_counts(monkeypatch) -> None:
    from app.services import assessment as assessment_service

    tenant, assessment_id = uuid.uuid4(), uuid.uuid4()
    assessment = SimpleNamespace(
        id=assessment_id,
        organization_id=tenant,
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        findings_info=0,
    )

    async def counts(session, organization_id, selected_assessment_id):
        assert (organization_id, selected_assessment_id) == (tenant, assessment_id)
        return {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0}

    monkeypatch.setattr(assessment_service, "assessment_finding_counts", counts, raising=False)
    _drive(assessment_service.refresh_counters(object(), assessment))
    assert assessment.findings_total == 3
    assert assessment.findings_high == 1
    assert assessment.findings_medium == 2


def test_final_total_includes_cloud_findings_without_recounting_native(monkeypatch) -> None:
    from app.agent.nodes import importer

    tenant, assessment_id = uuid.uuid4(), uuid.uuid4()
    assessment = SimpleNamespace(
        id=assessment_id,
        organization_id=tenant,
        findings_total=2,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        findings_info=0,
    )
    calls = []

    class Session:
        pass

    @asynccontextmanager
    async def scope(settings):
        yield Session()

    async def load(session, state):
        return assessment

    async def refresh(session, row):
        calls.append((row.organization_id, row.id))
        row.findings_total = 3
        row.findings_critical = 1
        row.findings_high = 2

    monkeypatch.setattr(importer, "session_scope", scope)
    monkeypatch.setattr(importer, "load_assessment", load)
    monkeypatch.setattr(importer, "refresh_counters", refresh)
    result = _drive(
        importer._final_total(
            {"organization_id": str(tenant)},
            deps=SimpleNamespace(settings=object()),
        )
    )
    assert result == 3
    assert assessment.findings_total == 3
    assert assessment.findings_critical == 1
    assert assessment.findings_high == 2
    assert calls == [(tenant, assessment_id)]


def test_unified_severity_query_excludes_native_duplicates_and_is_tenant_scoped() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.canonical_ingest import assessment_finding_counts

    tenant, assessment_id = uuid.uuid4(), uuid.uuid4()
    statements = []

    class Result:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self.rows

    class Session:
        async def execute(self, statement):
            statements.append(statement)
            return Result([("critical", 1), ("high", 1)] if len(statements) == 1 else [("high", 1)])

    result = _drive(assessment_finding_counts(Session(), tenant, assessment_id))
    assert result == {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}
    assert len(statements) == 2
    for statement in statements:
        params = statement.compile(dialect=postgresql.dialect()).params.values()
        assert tenant in params
        assert assessment_id in params
    native_sql = str(statements[0].compile(dialect=postgresql.dialect()))
    assert "is_duplicate IS false" in native_sql
    assert "is_false_positive IS false" in native_sql
    linked_sql = str(statements[1].compile(dialect=postgresql.dialect()))
    assert "canonical_findings.status !=" in linked_sql
    assert "is_duplicate IS false" in linked_sql
    assert "is_false_positive IS false" in linked_sql


@pytest.mark.parametrize(
    "scanner",
    [
        ScannerName.PROWLER_AWS,
        ScannerName.PROWLER_AZURE,
        ScannerName.PROWLER_GCP,
    ],
)
def test_cloud_only_import_bypasses_defectdojo(monkeypatch, scanner: ScannerName) -> None:
    from app.agent.nodes import importer

    tenant = uuid.uuid4()
    plan = importer._JobPlan(
        job_id=uuid.uuid4(),
        scanner=scanner,
        artifact=importer._Artifact(storage_key="safe", filename="prowler.safe.json"),
    )
    calls = []

    async def plans(state, *, deps, org_id):
        assert org_id == tenant
        return [plan]

    async def no_defectdojo(*args, **kwargs):
        raise AssertionError("cloud-only assessment must not require DefectDojo")

    async def advance(state, *, deps):
        calls.append("advance")

    async def cloud_job(state, *, deps, plan, step, org_id):
        assert plan.scanner is scanner
        assert org_id == tenant
        calls.append("import-cloud")

    async def total(state, *, deps):
        return 1

    class Step:
        def record_output(self, output):
            calls.append(("output", output))

    @asynccontextmanager
    async def step(*args, **kwargs):
        yield Step()

    monkeypatch.setattr(importer, "_plan_imports", plans)
    monkeypatch.setattr(importer, "_prepare", no_defectdojo)
    monkeypatch.setattr(importer, "_advance_without_defectdojo", advance, raising=False)
    monkeypatch.setattr(importer, "_import_cloud_job", cloud_job, raising=False)
    monkeypatch.setattr(importer, "_final_total", total)
    monkeypatch.setattr(importer, "record_step", step)
    result = _drive(
        importer.import_findings(
            {"organization_id": str(tenant)},
            deps=SimpleNamespace(settings=object()),
        )
    )
    assert calls == ["advance", "import-cloud"]
    assert result["findings_total"] == 1
