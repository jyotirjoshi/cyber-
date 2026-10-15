"""Background intelligence refresh for tenant-owned canonical exposures."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_provider_outage_is_unknown_not_a_negative_signal() -> None:
    from app.services.canonical_intel_refresh import fetch_cve_intelligence, verified_intel_evidence

    class NVD:
        async def get_cve(self, cve_id):
            raise TimeoutError("NVD unavailable")

    class KEV:
        async def lookup(self, cve_id):
            raise TimeoutError("KEV unavailable")

    class EPSS:
        async def score(self, cve_id):
            return SimpleNamespace(probability=0.72, percentile=0.96)

    snapshot = await fetch_cve_intelligence(
        "CVE-2024-12345", nvd=NVD(), kev=KEV(), epss=EPSS(),
    )
    assert snapshot == {
        "cve_id": "CVE-2024-12345",
        "nvd_status": "unavailable",
        "kev_status": "unavailable",
        "epss_status": "complete",
        "epss_score": 0.72,
    }
    evidence = verified_intel_evidence({"CVE-2024-12345": snapshot})
    assert evidence == [{"epss_score": 0.72}]


@pytest.mark.asyncio
async def test_refresh_cancellation_is_not_recorded_as_provider_outage() -> None:
    from app.services.canonical_intel_refresh import fetch_cve_intelligence

    class Cancelled:
        async def get_cve(self, cve_id):
            raise asyncio.CancelledError()

    class KEV:
        async def lookup(self, cve_id):
            return None

    class EPSS:
        async def score(self, cve_id):
            return None

    with pytest.raises(asyncio.CancelledError):
        await fetch_cve_intelligence(
            "CVE-2024-12345", nvd=Cancelled(), kev=KEV(), epss=EPSS(),
        )


def test_outage_preserves_prior_verified_positive_with_stale_provenance() -> None:
    from app.services.canonical_intel_refresh import (
        merge_last_known_intelligence,
        verified_intel_evidence,
    )

    prior = {
        "nvd_status": "complete", "cvss_score": 8.8, "exploit_available": True,
        "exploit_references": ["https://example.org/poc"],
        "kev_status": "complete", "in_kev": True,
        "epss_status": "complete", "epss_score": 0.8,
    }
    current = {
        "nvd_status": "unavailable", "kev_status": "unavailable",
        "epss_status": "unavailable",
    }
    merged = merge_last_known_intelligence(current, prior)
    evidence = verified_intel_evidence({"CVE-2024-12345": merged})
    assert merged["stale_providers"] == ["nvd", "kev"]
    assert evidence == [{
        "cvss_score": 8.8, "exploit_available": True,
        "in_kev": True, "observed_in_the_wild": True,
    }]
    assert "epss_score" not in evidence[0]


@pytest.mark.asyncio
async def test_verified_public_feed_signals_reach_canonical_risk() -> None:
    from app.schemas.organization import RiskWeights
    from app.services.canonical_intel_refresh import fetch_cve_intelligence, verified_intel_evidence
    from app.services.canonical_risk import score_canonical

    class NVD:
        async def get_cve(self, cve_id):
            return SimpleNamespace(base_score=8.8, is_rejected=False)

    class KEV:
        async def lookup(self, cve_id):
            return SimpleNamespace(known_ransomware_use=True)

    class EPSS:
        async def score(self, cve_id):
            return SimpleNamespace(probability=0.73, percentile=0.98)

    snapshot = await fetch_cve_intelligence(
        "CVE-2024-12345", nvd=NVD(), kev=KEV(), epss=EPSS(),
    )
    evidence = verified_intel_evidence({"CVE-2024-12345": snapshot})
    score, factors = score_canonical(
        "high", SimpleNamespace(criticality="critical", internet_exposed=True),
        evidence, RiskWeights(),
    )
    assert factors["inputs"]["cvss_score"] == 8.8
    assert factors["inputs"]["in_kev"] is True
    assert factors["inputs"]["epss_score"] == 0.73
    assert factors["inputs"]["ransomware_use"] is True
    assert score > 70


@pytest.mark.asyncio
async def test_only_nvd_exploit_tag_counts_as_exploit_availability() -> None:
    from app.integrations.nvd import parse_cve
    from app.services.canonical_intel_refresh import fetch_cve_intelligence, verified_intel_evidence

    class NVD:
        def __init__(self, tags):
            self.tags = tags

        async def get_cve(self, cve_id):
            return parse_cve({
                "cve": {
                    "id": cve_id, "references": [
                        {"url": "https://example.org/advisory", "tags": ["Vendor Advisory"]},
                        {"url": "https://example.org/poc", "tags": self.tags},
                    ],
                }
            })

    class KEV:
        async def lookup(self, cve_id):
            return None

    class EPSS:
        async def score(self, cve_id):
            return None

    tagged = await fetch_cve_intelligence(
        "CVE-2024-12345", nvd=NVD(["Exploit"]), kev=KEV(), epss=EPSS(),
    )
    untagged = await fetch_cve_intelligence(
        "CVE-2024-12345", nvd=NVD(["Third Party Advisory"]), kev=KEV(), epss=EPSS(),
    )
    assert tagged["exploit_available"] is True
    assert tagged["exploit_reference_count"] == 1
    assert tagged["exploit_references"] == ["https://example.org/poc"]
    assert verified_intel_evidence({"CVE-2024-12345": tagged})[0]["exploit_available"] is True
    assert "exploit_available" not in untagged


@pytest.mark.asyncio
async def test_refresh_batch_recomputes_two_tenants_without_cross_tenant_evidence(monkeypatch) -> None:
    from sqlalchemy.dialects import postgresql

    from app.schemas.organization import RiskWeights
    from app.services import canonical_intel_refresh as service

    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    finding_a, finding_b = uuid.uuid4(), uuid.uuid4()
    now = dt.datetime(2026, 10, 8, tzinfo=dt.UTC)

    def row(tenant_id, finding_id):
        finding = SimpleNamespace(
            id=finding_id, organization_id=tenant_id, severity="high", status="open",
            cve_ids=["CVE-2024-12345"], intel_evidence={}, intel_refreshed_at=None,
            risk_score=0, risk_factors={}, risk_policy_version=0,
        )
        organization = SimpleNamespace(id=tenant_id, risk_policy_version=1)
        asset = SimpleNamespace(criticality="critical", internet_exposed=True)
        return finding, organization, asset

    rows = [row(tenant_a, finding_a), row(tenant_b, finding_b)]
    observations = [
        SimpleNamespace(canonical_finding_id=finding_a, organization_id=tenant_a,
                        evidence={"cvss_score": 4.0}),
        SimpleNamespace(canonical_finding_id=finding_b, organization_id=tenant_b,
                        evidence={"cvss_score": 2.0}),
    ]

    class Result:
        def __init__(self, value):
            self.value = value

        def all(self):
            return self.value

        def scalars(self):
            return self

    class Session:
        def __init__(self):
            self.statements = []
            self.flushed = False

        async def execute(self, statement):
            self.statements.append(statement)
            return Result(rows if len(self.statements) == 1 else observations)

        async def flush(self):
            self.flushed = True

    class NVD:
        def __init__(self, scoped, redis):
            self.tenant_id = scoped.tenant_id

        async def get_cve(self, cve_id):
            return SimpleNamespace(
                base_score=9.7 if self.tenant_id == tenant_a else 7.1,
                is_rejected=False,
            )

        async def aclose(self):
            return None

    class KEV:
        def __init__(self, settings, redis):
            pass

        async def lookup(self, cve_id):
            return None

        async def aclose(self):
            return None

    class EPSS:
        def __init__(self, settings, redis):
            pass

        async def score(self, cve_id):
            return SimpleNamespace(probability=0.1, percentile=0.5)

        async def aclose(self):
            return None

    resolved = []

    async def resolve(session, principal, kind, *, settings, mark_used):
        resolved.append(principal.organization_id)
        return SimpleNamespace(tenant_id=principal.organization_id)

    async def cached(session, cve_id, *, nvd, kev, epss, now, max_age_seconds):
        result = await nvd.get_cve(cve_id)
        return {
            "cve_id": cve_id,
            "nvd_status": "complete",
            "cvss_score": result.base_score,
            "kev_status": "complete",
            "in_kev": False,
            "epss_status": "complete",
            "epss_score": 0.1,
        }

    monkeypatch.setattr(service, "NVDClient", NVD)
    monkeypatch.setattr(service, "KEVClient", KEV)
    monkeypatch.setattr(service, "EPSSClient", EPSS)
    monkeypatch.setattr(service, "resolve_settings", resolve)
    monkeypatch.setattr(service, "cached_cve_intelligence", cached)
    monkeypatch.setattr(service, "load_policy", lambda organization: SimpleNamespace(risk_weights=RiskWeights()))
    session = Session()
    count = await service.refresh_stale_intel_batch(
        session, settings=SimpleNamespace(intel=SimpleNamespace(canonical_refresh_seconds=86400)),
        now=now, limit=2,
    )
    assert count == 2
    assert set(resolved) == {tenant_a, tenant_b}
    assert rows[0][0].risk_factors["inputs"]["cvss_score"] == 9.7
    assert rows[1][0].risk_factors["inputs"]["cvss_score"] == 7.1
    assert rows[0][0].intel_refreshed_at == rows[1][0].intel_refreshed_at == now
    assert session.flushed
    observation_query = session.statements[1].compile(dialect=postgresql.dialect())
    assert "finding_observations.organization_id = canonical_findings.organization_id" in str(observation_query)
    assert {finding_a, finding_b}.issubset(set(observation_query.params["canonical_finding_id_1"]))


@pytest.mark.asyncio
async def test_policy_rescore_keeps_verified_intelligence(monkeypatch) -> None:
    from app.schemas.organization import RiskWeights
    from app.services import canonical_risk_refresh

    tenant_id, finding_id = uuid.uuid4(), uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id, organization_id=tenant_id, severity="high", status="open",
        risk_score=0, risk_factors={}, risk_policy_version=1,
        intel_evidence={
            "CVE-2024-12345": {
                "cve_id": "CVE-2024-12345", "nvd_status": "unavailable", "cvss_score": 8.8,
                "kev_status": "unavailable", "in_kev": True,
                "epss_status": "complete", "epss_score": 0.73,
                "stale_providers": ["nvd", "kev"],
            }
        },
    )
    organization = SimpleNamespace(id=tenant_id, risk_policy_version=2)
    asset = SimpleNamespace(id=uuid.uuid4(), organization_id=tenant_id,
                            criticality="critical", internet_exposed=True)

    class Result:
        def __init__(self, values):
            self.values = values

        def all(self):
            return self.values

        def scalars(self):
            return self

    class Session:
        def __init__(self):
            self.count = 0

        async def execute(self, statement):
            self.count += 1
            return Result([(finding, organization, asset)] if self.count == 1 else [])

        async def flush(self):
            return None

    monkeypatch.setattr(
        canonical_risk_refresh, "load_policy",
        lambda organization: SimpleNamespace(risk_weights=RiskWeights()),
    )
    assert await canonical_risk_refresh.refresh_stale_risk_batch(Session()) == 1
    assert finding.risk_factors["inputs"]["cvss_score"] == 8.8
    assert finding.risk_factors["inputs"]["in_kev"] is True
    assert finding.risk_factors["intelligence_stale_providers"] == {
        "CVE-2024-12345": ["nvd", "kev"]
    }
    assert finding.risk_policy_version == 2


@pytest.mark.asyncio
async def test_worker_maintenance_runs_intelligence_refresh(monkeypatch) -> None:
    pytest.importorskip("croniter")
    from app.worker import worker as worker_module

    worker = object.__new__(worker_module.AgentWorker)
    worker._stopping = False
    worker._settings = object()
    worker._redis = object()
    session = object()
    calls = []

    async def one_tick(seconds):
        worker._stopping = True

    @asynccontextmanager
    async def scoped(settings):
        yield session

    async def no_op(*args, **kwargs):
        return 0

    async def refresh(actual_session, *, settings, redis):
        calls.append((actual_session, settings, redis))
        return 1

    monkeypatch.setattr(worker_module.asyncio, "sleep", one_tick)
    monkeypatch.setattr(worker_module, "session_scope", scoped)
    for name in (
        "reclaim_orphans", "run_due_scans", "deliver_pending_dispatches",
        "deliver_pending", "execute_approved_batch", "refresh_stale_risk_batch",
    ):
        monkeypatch.setattr(worker_module, name, no_op)
    monkeypatch.setattr(worker_module, "refresh_stale_intel_batch", refresh, raising=False)
    await worker._maintenance_loop()
    assert calls == [(session, worker._settings, worker._redis)]


@pytest.mark.asyncio
async def test_worker_maintenance_executes_pending_automation(monkeypatch) -> None:
    pytest.importorskip("croniter")
    from app.worker import worker as worker_module

    worker = object.__new__(worker_module.AgentWorker)
    worker._stopping = False
    worker._settings = object()
    worker._redis = object()
    session = object()
    calls = []

    async def one_tick(seconds):
        worker._stopping = True

    @asynccontextmanager
    async def scoped(settings):
        yield session

    async def no_op(*args, **kwargs):
        return 0

    async def execute(actual_session, *, settings, redis):
        calls.append((actual_session, settings, redis))
        return 1

    monkeypatch.setattr(worker_module.asyncio, "sleep", one_tick)
    monkeypatch.setattr(worker_module, "session_scope", scoped)
    for name in (
        "reclaim_orphans", "run_due_scans", "deliver_pending_dispatches",
        "deliver_pending", "execute_approved_batch", "refresh_stale_risk_batch",
        "refresh_stale_intel_batch",
    ):
        monkeypatch.setattr(worker_module, name, no_op)
    monkeypatch.setattr(worker_module, "execute_pending_automations", execute, raising=False)
    await worker._maintenance_loop()
    assert calls == [(session, worker._settings, worker._redis)]
