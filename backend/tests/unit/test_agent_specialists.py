"""Durable autonomous specialist planning and evidence gates."""

from __future__ import annotations

from app.db.enums import JobStatus, ScannerName
from app.services.agent_specialist import (
    SpecialistOutcome,
    evidence_gate,
    specialist_fingerprint,
    specialist_for_scanner,
)


def test_specialist_roles_are_deterministic_and_domain_specific() -> None:
    assert specialist_for_scanner(ScannerName.NMAP) == "network"
    assert specialist_for_scanner(ScannerName.ZAP) == "web"
    assert specialist_for_scanner(ScannerName.SEMGREP_REPO) == "code"
    assert specialist_for_scanner(ScannerName.TRIVY_IMAGE) == "container"
    assert specialist_for_scanner(ScannerName.PROWLER_AWS) == "cloud"


def test_specialist_fingerprint_is_order_independent_without_exposing_targets() -> None:
    first = specialist_fingerprint(ScannerName.NUCLEI, ["https://b.example", "https://a.example"])
    second = specialist_fingerprint(ScannerName.NUCLEI, ["https://a.example", "https://b.example"])
    assert first == second
    assert len(first) == 64
    assert "example" not in first


def test_evidence_gate_never_calls_work_complete_without_archived_evidence() -> None:
    assert evidence_gate(JobStatus.COMPLETED.value, artifacts_archived=True, artifact_count=2) == SpecialistOutcome.COMPLETED
    assert evidence_gate(JobStatus.COMPLETED.value, artifacts_archived=False, artifact_count=0) == SpecialistOutcome.DEGRADED
    assert evidence_gate(JobStatus.TIMEOUT.value, artifacts_archived=True, artifact_count=1) == SpecialistOutcome.FAILED
