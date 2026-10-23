"""Scanner adapter contracts, and FR-008 in particular.

FR-008 is the PRD's one *critical constraint* on reconnaissance: ReconFTW must run in
passive discovery mode only.  The reason is a sequencing one rather than a preference.
Recon runs **before** the FR-011 approval interrupt, because its output is the asset list
the human is being asked to approve a scan of.  If recon itself port-scanned or fired
Nuclei templates, Cynux would have attacked a system nobody had yet agreed to attack --
and the approval gate would be theatre.

:mod:`app.scanners.reconftw` defends that with three independent mechanisms, and the
tests below exercise each separately.  Testing only the built argv would pass even if the
config override silently stopped being written, and testing only the config would pass if
somebody switched ``-p`` to ``-r``.

The rest of the file checks the properties every adapter must hold, swept across the
registry rather than asserted one adapter at a time, so a fifth scanner added later is
covered on the day it is written.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import ScannerSettings
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ArtifactKind, JobStatus, ScannerName
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest, ScannerResult, tail
from app.scanners.reconftw import FORBIDDEN_FLAGS, ReconFTWAdapter, hardening_config
from app.scanners.registry import ALL_ADAPTERS, PRE_APPROVAL_SCANNERS
from app.scanners.sandbox import (
    ALLOWED_ENV_NAMES,
    ALLOWED_WORK_MOUNTS,
    build_sandbox,
    validate_argv,
)
from app.scanners.zap import ZapAdapter
from app.services.job import _apply_result

ADAPTERS = sorted(ALL_ADAPTERS.items(), key=lambda kv: str(kv[0]))
ADAPTER_IDS = [str(name) for name, _ in ADAPTERS]


def test_zap_configuration_failure_cannot_complete_as_success() -> None:
    adapter = ZapAdapter()
    assert 0 in adapter.success_exit_codes
    assert 1 in adapter.success_exit_codes  # FAIL-level findings
    assert 2 in adapter.success_exit_codes  # WARN-level findings
    assert 3 not in adapter.success_exit_codes  # scan or configuration failure
    assert adapter.requires_output is True


@pytest.mark.parametrize("exit_code", [0, 1, 2, 3])
@pytest.mark.parametrize("has_report", [False, True])
def test_zap_job_completion_requires_success_code_and_report(
    exit_code: int, has_report: bool, tmp_path: Path
) -> None:
    adapter = ZapAdapter()
    artifacts = (
        (
            ArtifactFile(
                kind=ArtifactKind.RAW_OUTPUT,
                filename="zap.xml",
                path=tmp_path / "zap.xml",
                size_bytes=42,
                sha256="0" * 64,
                defectdojo_scan_type="ZAP Scan",
            ),
        )
        if has_report
        else ()
    )
    result = ScannerResult(
        scanner=ScannerName.ZAP,
        exit_code=exit_code,
        duration_seconds=1.0,
        argv=("zap-baseline.py",),
        image="zap:test",
        container_id="container",
        sandbox={},
        artifacts=artifacts,
        stdout_tail="",
        stderr_tail="",
    )
    job = SimpleNamespace(timeout_seconds=120)
    _apply_result(
        job,
        result,
        adapter_success_codes=adapter.success_exit_codes,
        requires_output=adapter.requires_output,
    )
    assert (job.status == JobStatus.COMPLETED.value) is (exit_code != 3 and has_report)


def make_request(
    scanner: ScannerName, workdir: Path, *targets: str, **options: object
) -> ScannerRequest:
    return ScannerRequest(
        scanner=scanner,
        targets=targets or ("example.com",),
        workdir=workdir,
        timeout_seconds=1800,
        options=options,
    )


# ---------------------------------------------------------------------------
# FR-008 mechanism 1: passive mode is selected
# ---------------------------------------------------------------------------


def test_recon_argv_selects_passive_mode(workdir: Path) -> None:
    adapter = ReconFTWAdapter()
    argv = adapter.build_argv(make_request(ScannerName.RECONFTW, workdir))
    assert "-p" in argv, "passive mode flag is absent"
    assert "-r" not in argv, "recon mode port-scans and probes; FR-008 forbids it"


@pytest.mark.parametrize("flag", sorted(FORBIDDEN_FLAGS))
def test_no_active_mode_flag_is_ever_emitted(workdir: Path, flag: str) -> None:
    adapter = ReconFTWAdapter()
    argv = adapter.build_argv(make_request(ScannerName.RECONFTW, workdir))
    assert flag not in argv, f"ReconFTW argv contains the active-mode flag {flag}"


def test_multi_target_recon_is_still_passive(workdir: Path) -> None:
    """The list-input branch builds a different argv, so it needs its own assertion."""
    adapter = ReconFTWAdapter()
    request = make_request(ScannerName.RECONFTW, workdir, "a.example.com", "b.example.com")
    adapter.prepare(request)
    argv = adapter.build_argv(request)
    assert "-p" in argv
    assert "-l" in argv
    assert not FORBIDDEN_FLAGS.intersection(argv)


# ---------------------------------------------------------------------------
# FR-008 mechanism 2: the config override disables every active stage
# ---------------------------------------------------------------------------

#: The stages that would generate traffic to a target. Named individually rather than
#: counted, so that a future ReconFTW upgrade that renames one is a visible failure.
MUST_BE_DISABLED = [
    "PORTSCANNER",
    "PORTSCAN_ACTIVE",
    "PORTSCAN_PASSIVE",
    "SUBBRUTE",
    "SUBPERMUTE",
    "ZONETRANSFER",
    "WEBPROBESIMPLE",
    "WEBPROBEFULL",
    "WEBSCREENSHOT",
    "FUZZ",
    "CMS_SCANNER",
    "NUCLEICHECK",
    "VULNS_GENERAL",
    "XSS",
    "SQLI",
    "SSRF_CHECKS",
    "LFI",
    "SSTI",
    "COMM_INJ",
    "OPEN_REDIRECT",
    "CRLF_CHECKS",
    "TEST_SSL",
    "SUBTAKEOVER",
    "SPRAY",
    "BYPASSER4XX",
]


@pytest.mark.parametrize("stage", MUST_BE_DISABLED)
def test_hardening_config_disables_every_active_stage(stage: str) -> None:
    assert f"{stage}=false" in hardening_config(), f"{stage} is not disabled"


def test_hardening_config_enables_nothing() -> None:
    """A single ``=true`` that is not an explicitly safe housekeeping flag is a bug.

    Asserting the shape of the whole file, rather than checking a list of known-bad
    names, is what catches a stage nobody thought to add to ``MUST_BE_DISABLED``.
    """
    #: ``REMOVETMP`` deletes scratch; it produces no traffic.
    allowed_true = {"REMOVETMP"}
    enabled = {
        line.split("=", 1)[0]
        for line in hardening_config().splitlines()
        if line and not line.startswith("#") and line.endswith("=true")
    }
    assert enabled <= allowed_true, f"hardening config enables {sorted(enabled - allowed_true)}"


def test_prepare_writes_the_config_into_the_workdir(workdir: Path) -> None:
    """Mechanism 2 only works if the file actually reaches the bind mount.

    An adapter whose ``build_argv`` references ``-f /work/reconftw.cfg`` while ``prepare``
    wrote nothing would run with ReconFTW's defaults -- fully active -- and the argv
    assertions above would still pass.
    """
    adapter = ReconFTWAdapter()
    request = make_request(ScannerName.RECONFTW, workdir)
    adapter.prepare(request)

    config = workdir / adapter.CONFIG_NAME
    assert config.is_file(), "the hardening config was not written"
    assert "PORTSCANNER=false" in config.read_text(encoding="utf-8")

    argv = adapter.build_argv(request)
    referenced = argv[argv.index("-f") + 1]
    assert referenced == adapter.container_path(adapter.CONFIG_NAME)
    assert (
        referenced.rsplit("/", 1)[-1] == config.name
    ), "the argv references a config filename that prepare() does not write"


# ---------------------------------------------------------------------------
# FR-008 mechanism 3: the assertion that survives a future "extra flags" option
# ---------------------------------------------------------------------------


def test_an_injected_active_flag_is_refused() -> None:
    """Simulates the change most likely to break FR-008 later: an adapter subclass, or a
    pass-through option, that appends a flag to the argv."""
    adapter = ReconFTWAdapter()
    for flag in ("-a", "--all", "-w", "-r", "--deep"):
        with pytest.raises(UnsafeScannerInvocationError) as excinfo:
            adapter._assert_passive(["-p", "-d", "example.com", flag])
        assert "FR-008" in str(excinfo.value) or "active" in str(excinfo.value).lower()


def test_dropping_passive_mode_is_refused() -> None:
    adapter = ReconFTWAdapter()
    with pytest.raises(UnsafeScannerInvocationError):
        adapter._assert_passive(["-d", "example.com"])


def test_recon_is_the_only_scanner_allowed_before_approval() -> None:
    """The set that answers "what may Cynux run without a human?" is exactly one entry.

    If an active scanner ever joined it, the FR-011 approval gate would still exist and
    still be displayed, while the scan it gates had already happened.
    """
    assert set(PRE_APPROVAL_SCANNERS) == {ScannerName.RECONFTW}
    assert (
        ALL_ADAPTERS[ScannerName.RECONFTW].defectdojo_scan_type is None
    ), "recon output is assets, not findings -- nothing here is a DefectDojo import"


def test_recon_refuses_an_unreasonable_target_count(workdir: Path) -> None:
    adapter = ReconFTWAdapter()
    with pytest.raises(UnsafeScannerInvocationError):
        adapter.validate(
            make_request(ScannerName.RECONFTW, workdir, *[f"h{i}.example.com" for i in range(51)])
        )


def test_zap_emits_the_xml_contract_required_by_defectdojo(workdir: Path) -> None:
    adapter = ZapAdapter()
    argv = adapter.build_argv(
        make_request(ScannerName.ZAP, workdir, "https://example.com")
    )

    assert "-x" in argv
    assert argv[argv.index("-x") + 1] == "zap.xml"
    assert "-J" not in argv
    assert adapter.REPORT_NAME == "zap.xml"


def test_nuclei_default_matches_the_production_worker_image() -> None:
    assert ScannerSettings(_env_file=None).image_nuclei == "projectdiscovery/nuclei:v3.11.1"


# ---------------------------------------------------------------------------
# Properties every adapter must hold
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "adapter"), ADAPTERS, ids=ADAPTER_IDS)
def test_every_adapter_builds_argv_that_passes_validation(
    name: ScannerName, adapter: ScannerAdapter, workdir: Path
) -> None:
    """The argv check is enforced at run time; an adapter that cannot pass it is broken.

    Each adapter receives a target of the type it supports.
    """
    target = {
        ScannerName.TRIVY_REPO: "https://github.com/acme/api",
        ScannerName.SEMGREP_REPO: "https://github.com/acme/api",
        ScannerName.GITLEAKS_REPO: "https://github.com/acme/api",
        ScannerName.TRIVY_IMAGE: "docker.io/acme/api:1.0",
        ScannerName.SYFT_IMAGE: "docker.io/acme/api:1.0",
        ScannerName.PROWLER_AWS: "aws:123456789012",
        ScannerName.PROWLER_AZURE: "azure:11111111-2222-4333-8444-555555555555",
        ScannerName.PROWLER_GCP: "gcp:acme-project",
    }.get(name, "https://example.com")
    request = make_request(name, workdir, target)
    if name not in {ScannerName.SEMGREP_REPO, ScannerName.GITLEAKS_REPO}:
        adapter.prepare(request)
    argv = adapter.build_argv(request)
    assert argv, f"{name} built an empty argv"
    assert validate_argv(argv, scanner=str(name)) == argv


@pytest.mark.parametrize(("name", "adapter"), ADAPTERS, ids=ADAPTER_IDS)
def test_every_adapter_writes_only_under_its_work_mount(
    name: ScannerName, adapter: ScannerAdapter, workdir: Path
) -> None:
    """An output path outside the bind mount is written to the container's own
    filesystem, which is read-only or discarded -- so the artifact never reaches Cynux."""
    target = {
        ScannerName.TRIVY_REPO: "https://github.com/acme/api",
        ScannerName.SEMGREP_REPO: "https://github.com/acme/api",
        ScannerName.GITLEAKS_REPO: "https://github.com/acme/api",
        ScannerName.TRIVY_IMAGE: "docker.io/acme/api:1.0",
        ScannerName.SYFT_IMAGE: "docker.io/acme/api:1.0",
        ScannerName.PROWLER_AWS: "aws:123456789012",
        ScannerName.PROWLER_AZURE: "azure:11111111-2222-4333-8444-555555555555",
        ScannerName.PROWLER_GCP: "gcp:acme-project",
    }.get(name, "https://example.com")
    request = make_request(name, workdir, target)
    if name not in {ScannerName.SEMGREP_REPO, ScannerName.GITLEAKS_REPO}:
        adapter.prepare(request)
    for element in adapter.build_argv(request):
        if element.startswith("/") and not element.startswith((adapter.work_mount, "/tmp/")):
            pytest.fail(f"{name} references {element}, outside {adapter.work_mount}")


@pytest.mark.parametrize(("name", "adapter"), ADAPTERS, ids=ADAPTER_IDS)
def test_every_adapter_declares_a_bounded_configuration(
    name: ScannerName, adapter: ScannerAdapter
) -> None:
    """The four per-adapter sandbox dials, each checked against its allow-list."""
    assert adapter.work_mount in ALLOWED_WORK_MOUNTS
    assert set(adapter.container_env) <= ALLOWED_ENV_NAMES
    assert adapter.name == name, f"{name} is registered under the wrong key"
    if adapter.run_as_user is not None:
        assert adapter.run_as_user.split(":", 1)[0] not in ("0", "root")
    assert adapter.success_exit_codes, f"{name} declares no successful exit code"


@pytest.mark.parametrize(("name", "adapter"), ADAPTERS, ids=ADAPTER_IDS)
def test_every_adapter_runs_in_a_safe_sandbox(
    name: ScannerName, adapter: ScannerAdapter, scanner_settings: ScannerSettings, workdir: Path
) -> None:
    """End-to-end: the adapter's declared dials must survive ``build_sandbox``.

    This is the test that would have caught ZAP's ``/zap/wrk`` mount or its uid-1000
    requirement being disallowed, rather than discovering it on a live container.
    """
    sandbox = build_sandbox(
        scanner_settings,
        workdir=workdir,
        image=adapter.image(scanner_settings),
        read_only_root=adapter.read_only_root,
        work_mount=adapter.work_mount,
        run_as_user=adapter.run_as_user,
        environment=adapter.container_env,
    )
    assert sandbox["working_dir"] == adapter.work_mount
    assert sandbox["cap_drop"] == ["ALL"]
    assert str(sandbox["user"]).split(":", 1)[0] not in ("0", "root")


@pytest.mark.parametrize(("name", "adapter"), ADAPTERS, ids=ADAPTER_IDS)
def test_collect_tolerates_a_run_that_produced_nothing(
    name: ScannerName, adapter: ScannerAdapter, workdir: Path
) -> None:
    """``collect`` is called after timeouts and cancellations too.

    Raising there would replace a partial-result job with a crash, losing the evidence
    the scan did produce.
    """
    target = {
        ScannerName.PROWLER_AWS: "aws:123456789012",
        ScannerName.PROWLER_AZURE: "azure:11111111-2222-4333-8444-555555555555",
        ScannerName.PROWLER_GCP: "gcp:acme-project",
    }.get(name, "https://example.com")
    request = make_request(name, workdir, target)
    assert adapter.collect(request) == ()


@pytest.mark.parametrize(("name", "adapter"), ADAPTERS, ids=ADAPTER_IDS)
def test_adapters_reject_an_empty_target_list(
    name: ScannerName, adapter: ScannerAdapter, workdir: Path
) -> None:
    request = ScannerRequest(
        scanner=name, targets=(), workdir=workdir, timeout_seconds=60, options={}
    )
    with pytest.raises((ValueError, UnsafeScannerInvocationError)):
        adapter.validate(request)


def test_every_scanner_name_has_an_adapter() -> None:
    """The registry asserts this at import; restating it here makes the failure legible."""
    assert set(ALL_ADAPTERS) == set(ScannerName)


def test_nmap_does_not_request_capabilities_it_cannot_have() -> None:
    """``-sS`` needs NET_RAW, which the sandbox drops. A SYN scan would fail at runtime.

    ``--unprivileged`` is what makes Nmap fail at argument parsing instead of silently
    degrading half way through a scan.
    """
    adapter = ALL_ADAPTERS[ScannerName.NMAP]
    argv = adapter.build_argv(make_request(ScannerName.NMAP, Path.cwd(), "example.com"))
    assert "-sT" in argv
    assert "-sS" not in argv
    assert "--unprivileged" in argv


# ---------------------------------------------------------------------------
# Stream handling
# ---------------------------------------------------------------------------


def test_tail_keeps_the_end_of_a_stream() -> None:
    """The end is where the error is; a head-truncated scanner log is a version banner."""
    text = "banner\n" + "x" * 10_000 + "\nFATAL: could not resolve target"
    trimmed = tail(text, limit=200)
    assert trimmed.endswith("FATAL: could not resolve target")
    assert "truncated" in trimmed
    assert len(trimmed) < len(text)


def test_tail_leaves_short_streams_alone() -> None:
    assert tail("done") == "done"
