"""Large DefectDojo imports must process complete, bounded pages."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_defectdojo_pages_stream_past_legacy_2000_finding_cap() -> None:
    from app.integrations.defectdojo import DefectDojoClient

    class _Transport:
        def __init__(self) -> None:
            self.offsets: list[int] = []

        async def get_json(self, path, *, params):
            assert path == "/api/v2/findings/"
            assert params["test"] == 42
            offset = int(params["offset"])
            self.offsets.append(offset)
            records = [
                {"id": index, "title": f"Finding {index}", "severity": "Low"}
                for index in range(offset + 1, min(offset + 200, 2205) + 1)
            ]
            return {"results": records, "next": offset + 200 < 2205}

    client = object.__new__(DefectDojoClient)
    transport = _Transport()
    client._client = transport
    client._cfg = SimpleNamespace(configured=True)
    pages = [page async for page in client.iter_finding_pages(test_id=42)]
    assert len(pages) == 12
    assert max(map(len, pages)) <= 200
    assert sum(map(len, pages)) == 2205
    assert pages[-1][-1].id == 2205
    assert transport.offsets == list(range(0, 2205, 200))


@pytest.mark.asyncio
async def test_defectdojo_rejects_provider_page_larger_than_requested_bound() -> None:
    from app.core.errors import DefectDojoError
    from app.integrations.defectdojo import DefectDojoClient

    class _Transport:
        async def get_json(self, path, *, params):
            return {
                "results": [
                    {"id": index, "title": "Finding", "severity": "Low"} for index in range(201)
                ],
                "next": None,
            }

    client = object.__new__(DefectDojoClient)
    client._client = _Transport()
    client._cfg = SimpleNamespace(configured=True)
    with pytest.raises(DefectDojoError):
        async for _ in client.iter_finding_pages(test_id=42):
            pass


@pytest.mark.asyncio
async def test_defectdojo_malformed_record_does_not_log_untrusted_id(monkeypatch) -> None:
    from app.integrations import defectdojo as module

    class _Transport:
        async def get_json(self, path, *, params):
            return {"results": [{"id": "secret-token-value"}], "next": None}

    logged: list[dict] = []
    monkeypatch.setattr(module.logger, "warning", lambda event, **fields: logged.append(fields))
    client = object.__new__(module.DefectDojoClient)
    client._client = _Transport()
    client._cfg = SimpleNamespace(configured=True)
    pages = [page async for page in client.iter_finding_pages(test_id=42)]
    assert pages == []
    assert logged
    assert "secret-token-value" not in str(logged)


@pytest.mark.asyncio
async def test_native_import_ingests_each_page_without_collecting_all_findings(monkeypatch) -> None:
    from app.db.enums import Severity
    from app.db.models.finding import Finding
    from app.integrations.defectdojo import DDFinding
    from app.services import canonical_ingest
    from app.services import finding as service

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    batches: list[list[int]] = []
    audits: list[dict] = []

    class _Client:
        async def iter_finding_pages(self, *, test_id):
            assert test_id == 73
            yield [DDFinding(id=1, title="First", severity=Severity.LOW)]
            yield [DDFinding(id=2, title="Second", severity=Severity.HIGH)]

    class _Session:
        def __init__(self) -> None:
            self.rows: list[Finding] = []

        def add(self, row):
            self.rows.append(row)

        async def flush(self):
            for row in self.rows:
                if row.id is None:
                    row.id = uuid.uuid4()

    async def existing(session, *, organization_id, dd_ids):
        return {}

    async def no_job(session, assessment, *, test_id):
        return None

    async def no_assets(session, *, organization_id, hosts):
        return {}, {}

    async def ingest(session, organization_id, findings):
        batches.append([finding.defectdojo_finding_id for finding in findings])
        assert len(findings) == 1

    async def refresh(session, assessment):
        return None

    async def audit(session, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(service, "_existing_by_dd_id", existing)
    monkeypatch.setattr(service, "_job_for_test", no_job)
    monkeypatch.setattr(service, "_asset_index", no_assets)
    monkeypatch.setattr(canonical_ingest, "ingest_native_findings", ingest)
    monkeypatch.setattr(service, "refresh_counters", refresh)
    monkeypatch.setattr(service.audit_service, "record", audit)

    session = _Session()
    count = await service.import_from_defectdojo(
        session,
        assessment,
        client=_Client(),
        test_id=73,
    )
    assert count == 2
    assert batches == [[1], [2]]
    assert len(session.rows) == 2
    assert len(audits) == 1
    assert audits[0]["detail"]["imported"] == 2


@pytest.mark.asyncio
async def test_clean_scan_marks_import_complete_only_after_projection_succeeds(monkeypatch) -> None:
    from app.services import finding as service

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    job = SimpleNamespace(
        id=uuid.uuid4(),
        scanner="nmap",
        targets=["example.org"],
        assessment_id=assessment.id,
        organization_id=organization_id,
        imported_at=None,
        imported_finding_count=0,
        defectdojo_test_id=77,
    )

    async def matched_job(*args, **kwargs):
        return job

    async def no_op(*args, **kwargs):
        return None

    class _CleanClient:
        async def iter_finding_pages(self, *, test_id):
            if False:
                yield []

    class _FailedClient:
        async def iter_finding_pages(self, *, test_id):
            raise RuntimeError("provider projection failed")
            if False:
                yield []

    monkeypatch.setattr(service, "_job_for_test", matched_job)
    monkeypatch.setattr(service.audit_service, "record", no_op)
    assert (
        await service.import_from_defectdojo(
            object(),
            assessment,
            client=_CleanClient(),
            test_id=77,
        )
        == 0
    )
    assert job.imported_at is not None

    job.imported_at = None
    with pytest.raises(RuntimeError, match="provider projection failed"):
        await service.import_from_defectdojo(
            object(),
            assessment,
            client=_FailedClient(),
            test_id=77,
        )
    assert job.imported_at is None


@pytest.mark.asyncio
async def test_trivy_job_attribution_rejects_cross_tenant_or_other_target_asset() -> None:
    from app.db.models.asset import Asset
    from app.services import finding as service

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    target = "https://github.com/acme/api"
    job = SimpleNamespace(
        scanner="trivy_repo",
        targets=[target],
        assessment_id=assessment.id,
        organization_id=organization_id,
    )

    class _Rows:
        def __init__(self, asset):
            self.asset = asset

        def scalars(self):
            return self

        def first(self):
            return self.asset

    class _Session:
        def __init__(self, asset):
            self.asset = asset

        async def execute(self, statement):
            return _Rows(self.asset)

    asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name=target,
        asset_type="repository",
        seen_in_assessments=[str(assessment.id)],
    )
    assert await service._job_target_asset(_Session(asset), assessment, job) is asset
    asset.organization_id = uuid.uuid4()
    assert await service._job_target_asset(_Session(asset), assessment, job) is None
    asset.organization_id = organization_id
    asset.name = "https://github.com/other/repo"
    assert await service._job_target_asset(_Session(asset), assessment, job) is None


def test_trivy_import_attributes_finding_to_job_target_not_provider_endpoint() -> None:
    from app.db.enums import Severity
    from app.db.models.asset import Asset
    from app.integrations.defectdojo import DDFinding
    from app.services import finding as service

    asset = Asset(id=uuid.uuid4(), name="https://github.com/acme/api", asset_type="repository")
    record = DDFinding(
        id=9,
        title="Package vulnerability",
        severity=Severity.HIGH,
        endpoints=["https://unrelated.example.org/package"],
    )
    assert (
        service._import_asset_for_record(
            record,
            scanner="trivy_repo",
            job_asset=asset,
            by_host_port={},
            by_host={},
        )
        is asset
    )


@pytest.mark.asyncio
async def test_trivy_import_projects_to_canonical_with_approved_repository_asset(
    monkeypatch,
) -> None:
    from app.db.enums import Severity
    from app.db.models.asset import Asset
    from app.integrations.defectdojo import DDFinding
    from app.services import canonical_ingest
    from app.services import finding as service

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    target = "https://github.com/acme/api"
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name=target,
        asset_type="repository",
        criticality="normal",
        seen_in_assessments=[str(assessment.id)],
    )
    job = SimpleNamespace(
        id=uuid.uuid4(),
        scanner="trivy_repo",
        targets=[target],
        organization_id=organization_id,
        assessment_id=assessment.id,
    )
    seen: list[uuid.UUID | None] = []

    class _Rows:
        def scalars(self):
            return self

        def first(self):
            return asset

    class _Session:
        def __init__(self):
            self.rows = []

        async def execute(self, statement):
            return _Rows()

        def add(self, row):
            self.rows.append(row)

        async def flush(self):
            for row in self.rows:
                if row.id is None:
                    row.id = uuid.uuid4()

    class _Client:
        async def iter_finding_pages(self, *, test_id):
            yield [
                DDFinding(
                    id=23,
                    title="Vulnerable package",
                    severity=Severity.HIGH,
                    endpoints=["https://unrelated.example.org/package"],
                )
            ]

    async def no_existing(*args, **kwargs):
        return {}

    async def matched_job(*args, **kwargs):
        return job

    async def no_host_assets(*args, **kwargs):
        return {}, {}

    async def ingest(session, tenant_id, findings):
        assert tenant_id == organization_id
        seen.extend(finding.asset_id for finding in findings)

    async def no_op(*args, **kwargs):
        return None

    monkeypatch.setattr(service, "_existing_by_dd_id", no_existing)
    monkeypatch.setattr(service, "_job_for_test", matched_job)
    monkeypatch.setattr(service, "_asset_index", no_host_assets)
    monkeypatch.setattr(canonical_ingest, "ingest_native_findings", ingest)
    monkeypatch.setattr(service, "refresh_counters", no_op)
    monkeypatch.setattr(service.audit_service, "record", no_op)

    assert (
        await service.import_from_defectdojo(
            _Session(),
            assessment,
            client=_Client(),
            test_id=77,
        )
        == 1
    )
    assert seen == [asset.id]
