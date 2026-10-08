"""Approved scan jobs must target only compatible, individually attributable assets."""

import uuid

from app.agent.nodes import scan
from app.db.enums import ScannerName


def test_nuclei_jobs_are_per_web_target_and_never_scan_repository_or_image_hosts() -> None:
    jobs = scan._jobs_for_scope(
        [
            "https://api.example.org/",
            "https://shop.example.org/",
            "https://github.com/acme/api",
            "docker.io/acme/api:1.0",
        ],
        [ScannerName.NMAP, ScannerName.NUCLEI, ScannerName.ZAP],
    )
    assert jobs == [
        (ScannerName.NMAP, ["https://api.example.org/", "https://shop.example.org/"]),
        (ScannerName.NUCLEI, ["https://api.example.org/"]),
        (ScannerName.NUCLEI, ["https://shop.example.org/"]),
        (ScannerName.ZAP, ["https://api.example.org/"]),
        (ScannerName.ZAP, ["https://shop.example.org/"]),
    ]


def test_no_compatible_targets_produces_no_active_scan_jobs() -> None:
    assert (
        scan._jobs_for_scope(
            ["https://github.com/acme/api", "docker.io/acme/api:1.0"],
            [ScannerName.NMAP, ScannerName.NUCLEI, ScannerName.ZAP],
        )
        == []
    )


def test_each_nuclei_job_has_distinct_replay_key_and_exact_live_scope() -> None:
    run_id = uuid.uuid4()
    first = ["https://api.example.org/"]
    second = ["https://shop.example.org/"]
    assert scan._job_idempotency_key(run_id, ScannerName.NUCLEI, first) != (
        scan._job_idempotency_key(run_id, ScannerName.NUCLEI, second)
    )
    approved = [*first, *second, "https://github.com/acme/api"]
    scanners = [ScannerName.NUCLEI]
    assert scan._job_matches_approval(ScannerName.NUCLEI, first, approved, scanners)
    assert not scan._job_matches_approval(
        ScannerName.NUCLEI,
        ["https://other.example.org/"],
        approved,
        scanners,
    )
    assert not scan._job_matches_approval(
        ScannerName.NUCLEI,
        first + second,
        approved,
        scanners,
    )
    assert not scan._job_matches_approval(
        ScannerName.NUCLEI,
        first,
        approved,
        [],
    )


def test_trivy_jobs_are_per_approved_repository_or_image() -> None:
    targets = [
        "https://github.com/acme/api",
        "https://github.com/acme/web",
        "docker.io/acme/api:1.0",
        "docker.io/acme/web:2.0",
        "https://api.example.org/",
    ]
    scanners = [ScannerName.TRIVY_REPO, ScannerName.TRIVY_IMAGE]
    jobs = scan._jobs_for_scope(targets, scanners)
    assert jobs == [
        (ScannerName.TRIVY_REPO, [targets[0]]),
        (ScannerName.TRIVY_REPO, [targets[1]]),
        (ScannerName.TRIVY_IMAGE, [targets[2]]),
        (ScannerName.TRIVY_IMAGE, [targets[3]]),
    ]
    run_id = uuid.uuid4()
    assert scan._job_idempotency_key(run_id, ScannerName.TRIVY_REPO, [targets[0]]) != (
        scan._job_idempotency_key(run_id, ScannerName.TRIVY_REPO, [targets[1]])
    )
    assert scan._job_matches_approval(ScannerName.TRIVY_IMAGE, [targets[2]], targets, scanners)
    assert not scan._job_matches_approval(
        ScannerName.TRIVY_IMAGE,
        [targets[0]],
        targets,
        scanners,
    )
