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
                    {"id": index, "title": "Finding", "severity": "Low"}
                    for index in range(201)
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
    monkeypatch.setattr(
        module.logger, "warning", lambda event, **fields: logged.append(fields)
    )
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
        session, assessment, client=_Client(), test_id=73,
    )
    assert count == 2
    assert batches == [[1], [2]]
    assert len(session.rows) == 2
    assert len(audits) == 1
    assert audits[0]["detail"]["imported"] == 2
