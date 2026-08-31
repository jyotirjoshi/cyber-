"""Container sandbox construction -- the security core of FR-014 and SEC-004.

Everything that keeps a scanner from becoming a foothold is decided in this one module, and
nothing outside it may pass options to the Docker API.  That is the whole design: there is
exactly one function that produces container kwargs, so "what constrains a scanner?" has a
single answer that can be read in one sitting and asserted on in a test.

What the sandbox denies, and why each one matters:

*   **No host environment.**  ``environment={}``, always.  The worker process holds the JWT
    signing key, the database URL, the DefectDojo token and every LLM provider key in its
    environment.  Docker does not inherit the parent environment by default, but passing
    ``os.environ`` is a two-character mistake in a hurry, so the empty dict is explicit and
    :func:`assert_sandbox_safe` fails the build if anything sensitive appears.
*   **No writable root.**  ``read_only=True`` with a ``tmpfs`` at ``/tmp``.  A scanner that
    downloads a template update cannot persist it into the image layer, and an exploit that
    writes a binary has nowhere to write it that survives.
*   **No capabilities.**  ``cap_drop=["ALL"]`` and ``no-new-privileges``.  This is why Nmap
    runs ``-sT`` connect scans rather than ``-sS``: SYN scanning needs ``NET_RAW``, and the
    capability is worth more than the speed.
*   **Not root.**  ``user="65534:65534"`` -- ``nobody:nogroup``.  Combined with the read-only
    root this means a compromised scanner image runs as an unprivileged user in a filesystem
    it cannot modify.
*   **A network that cannot reach us.**  ``network=settings.network``, which docker-compose
    defines as egress-only.  Postgres, Redis and MinIO are not on it.  This is SEC-004's
    "no direct database access" enforced by the network topology rather than by trusting the
    scanner not to try.
*   **Bounded resources.**  ``nano_cpus``, ``mem_limit`` and ``pids_limit``, so one scan cannot
    starve the host or fork-bomb it.

The returned dict is stored verbatim on ``ScannerJob.sandbox``.  An auditor asking "was this
scan constrained?" reads a database row, not a log line that may have rotated.

:data:`ARGV_SAFE` is the second half of the module's job.  Scanner argv is assembled from
targets, and targets originate with users and with an LLM-driven agent.  A shell is never
involved -- ``container.create`` takes a list -- but the allow-list is still enforced, because
defence that depends on a single downstream call being correct is defence that breaks the first
time somebody adds a convenience wrapper.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import structlog

from app.core.config import ScannerSettings
from app.core.errors import UnsafeScannerInvocationError

logger = structlog.get_logger(__name__)

#: Characters permitted in an argv element. Covers hostnames, IPs, CIDRs, URLs (including a
#: percent-encoded query string, which :func:`app.core.targets.validate_target` preserves),
#: container paths, flags and comma-separated severity lists -- and excludes every shell
#: metacharacter, whitespace and control byte. Anything a URL genuinely needs but this set
#: omits can be percent-encoded, which ``%`` allows.
ARGV_SAFE = re.compile(r"^[A-Za-z0-9._:/,=@+~?&%\-\[\]]+$")

#: Substrings that never legitimately appear in a Cynux scanner argv. Checked in addition to
#: :data:`ARGV_SAFE` so that the reason for a rejection is specific in the log.
FORBIDDEN_ARGV_SUBSTRINGS = (
    "$(",
    "${",
    "`",
    "..",
    "//..",
    "\n",
    "\r",
    "\x00",
)

#: Environment variable name fragments that must never be handed to a container (SEC-002). The
#: sandbox passes no environment at all; this is the assertion that keeps it that way.
_SECRET_ENV_FRAGMENTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "KEY",
    "DSN",
    "DATABASE",
    "REDIS",
    "CYNUX_",
    "AWS_",
    "ANTHROPIC",
    "OPENAI",
    "GOOGLE",
)

#: Host paths that must never be bind-mounted into a scanner (SEC-004: "no access to the host
#: filesystem unless explicitly required"). The Docker socket is the one that matters most --
#: mounting it makes the sandbox decorative, since a container with the socket can start a
#: privileged container.
_FORBIDDEN_MOUNT_SOURCES = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
)

#: Container paths a scanner's per-job workdir may be mounted at. ``/work`` is the norm;
#: ``/zap/wrk`` exists because ZAP's report writer joins report names onto that hard-coded
#: directory, so mounting anywhere else means no report reaches the host. An allow-list rather
#: than a free string: "where is the job directory mounted?" must have a bounded set of answers,
#: since a mount at ``/`` or ``/usr/bin`` would be a container escape dressed as a config value.
ALLOWED_WORK_MOUNTS = frozenset({"/work", "/zap/wrk"})

#: The *only* environment variables an adapter may set. Nuclei and ReconFTW resolve a home
#: directory on startup and abort if they cannot -- the upstream images assume root, and running
#: them as ``nobody`` means telling them where to write instead.
#:
#: This is an allow-list, not an exception to SEC-002. The property that matters is "no Cynux
#: credential and no host environment variable ever reaches a scanner", and an allow-list of six
#: names whose values are charset-checked enforces that more strictly than the previous
#: reject-if-it-looks-secret check did: a variable named ``SMTP_PASS`` passed the old check.
ALLOWED_ENV_NAMES = frozenset(
    {
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "LANG",
        "NO_COLOR",
    }
)


def validate_argv(argv: tuple[str, ...] | list[str], *, scanner: str) -> tuple[str, ...]:
    """Check every argv element, or refuse to run.

    Raises :class:`~app.core.errors.UnsafeScannerInvocationError`, which is deliberately not
    degradable: a rejected argv means something upstream constructed a command it should not
    have, and the correct response is a loud failure rather than a retry or a skipped scanner.
    """
    if not argv:
        raise UnsafeScannerInvocationError(
            "A scanner was about to be run with an empty argv.",
            context={"scanner": scanner},
        )

    checked: list[str] = []
    for index, element in enumerate(argv):
        if not isinstance(element, str):
            raise UnsafeScannerInvocationError(
                "Scanner argv contained a non-string element.",
                context={"scanner": scanner, "index": index, "type": type(element).__name__},
            )
        if not element:
            raise UnsafeScannerInvocationError(
                "Scanner argv contained an empty element.",
                context={"scanner": scanner, "index": index},
            )
        if len(element) > 2048:
            raise UnsafeScannerInvocationError(
                "Scanner argv element exceeded the length limit.",
                context={"scanner": scanner, "index": index, "length": len(element)},
            )
        for fragment in FORBIDDEN_ARGV_SUBSTRINGS:
            if fragment in element:
                logger.critical(
                    "scanner.unsafe_argv_blocked",
                    scanner=scanner,
                    index=index,
                    reason="forbidden_substring",
                )
                raise UnsafeScannerInvocationError(
                    "Scanner argv contained a forbidden sequence.",
                    context={"scanner": scanner, "index": index},
                )
        if not ARGV_SAFE.match(element):
            logger.critical(
                "scanner.unsafe_argv_blocked",
                scanner=scanner,
                index=index,
                reason="charset",
            )
            raise UnsafeScannerInvocationError(
                "Scanner argv contained characters outside the safe set.",
                context={"scanner": scanner, "index": index},
            )
        checked.append(element)
    return tuple(checked)


def validate_image(image: str, settings: ScannerSettings) -> str:
    """Refuse any image not in the settings allow-list.

    The agent chooses *which scanner* to run, from a fixed set of tools. It never chooses an
    image reference. This check is what makes that structural rather than aspirational: a
    model-supplied string cannot reach the Docker API even if it reaches an image field.
    """
    if image not in settings.allowed_images:
        logger.critical("scanner.image_not_allowed", image=image)
        raise UnsafeScannerInvocationError(
            "The requested scanner image is not on the allow-list.",
            context={"image": image, "allowed_count": len(settings.allowed_images)},
        )
    return image


def build_sandbox(
    settings: ScannerSettings,
    *,
    workdir: Path,
    image: str,
    read_only_root: bool = True,
    work_mount: str = "/work",
    run_as_user: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Container kwargs for one scanner run.

    Four parameters exist for images that cannot be run with the strictest defaults. Each is a
    documented, per-adapter decision, each is bounded by a check here rather than trusted, and
    each is recorded in :func:`sandbox_evidence` so the job row says what was actually applied:

    ``read_only_root``
        ``False`` for images that need a writable root (ZAP, ReconFTW). Every other restriction
        still applies and the writable layer dies with the container.
    ``work_mount``
        Must be in :data:`ALLOWED_WORK_MOUNTS`.
    ``run_as_user``
        Must not be root. See :func:`_assert_unprivileged`.
    ``environment``
        Names must be in :data:`ALLOWED_ENV_NAMES` and values must pass :data:`ARGV_SAFE`.
        Never ``os.environ``; see the module docstring.
    """
    validate_image(image, settings)

    if work_mount not in ALLOWED_WORK_MOUNTS:
        logger.critical("scanner.work_mount_not_allowed", work_mount=work_mount)
        raise UnsafeScannerInvocationError(
            "The requested container work mount is not on the allow-list.",
            context={"work_mount": work_mount},
        )

    user = run_as_user or settings.run_as_user
    _assert_unprivileged(user)
    env = _validate_environment(environment)

    host_workdir = Path(workdir).resolve()
    if not host_workdir.is_dir():
        raise UnsafeScannerInvocationError(
            "The scanner work directory does not exist.",
            context={"workdir": str(host_workdir)},
        )
    _assert_mount_source_allowed(host_workdir)

    sandbox: dict[str, Any] = {
        "image": image,
        #: Egress-only network. Not "none", because Nuclei and Nmap must reach the target;
        #: not the app network, because then they could reach Postgres (SEC-004).
        "network": settings.network,
        "read_only": read_only_root,
        #: Writable scratch that vanishes with the container. ``noexec`` because a scanner has
        #: no legitimate reason to execute something it just wrote to /tmp. S108 does not apply:
        #: this names a mount point in the container's own namespace, and the flags below are
        #: precisely the hardening the rule exists to ask for.
        "tmpfs": {
            "/tmp": f"size={settings.tmpfs_size_mb}m,mode=1777,noexec,nosuid,nodev",  # noqa: S108
        },
        "user": user,
        #: docker-py takes CPU quota in nanoseconds-of-CPU per second.
        "nano_cpus": int(settings.cpu_quota_cores * 1_000_000_000),
        "mem_limit": f"{settings.memory_limit_mb}m",
        #: Equal to mem_limit: swap is disabled rather than doubled, so a memory-hungry scan
        #: is killed instead of thrashing the host's disk.
        "memswap_limit": f"{settings.memory_limit_mb}m",
        "pids_limit": settings.pids_limit,
        "cap_drop": ["ALL"],
        "cap_add": [],
        "privileged": False,
        "security_opt": ["no-new-privileges:true"],
        #: SEC-002. Empty unless an adapter asked for an allow-listed name; never ``os.environ``.
        "environment": env,
        "volumes": {
            str(host_workdir): {"bind": work_mount, "mode": "rw"},
        },
        "working_dir": work_mount,
        #: The runner enforces the timeout and removes the container itself, in a ``finally``.
        #: ``auto_remove`` would race that: the container can vanish before its logs and exit
        #: code are read, which is exactly the evidence FR-014 requires.
        "auto_remove": False,
        "detach": True,
        "stdin_open": False,
        "tty": False,
        #: A scanner that dies must stay dead. Restarting it would re-scan a target without a
        #: job record and without an approval check.
        "restart_policy": {"Name": "no"},
        #: Cynux-owned labels, so an operator can find and clean up orphans after a crash.
        "labels": {
            "com.cynux.managed": "true",
            "com.cynux.component": "scanner",
        },
    }

    if read_only_root:
        #: Several scanner images expect a writable HOME. With a read-only root that has to be
        #: a tmpfs, or the tool fails on startup with an opaque permission error.
        sandbox["tmpfs"]["/home/nonroot"] = f"size=64m,mode=1777,uid={_uid_of(user)}"

    assert_sandbox_safe(sandbox)
    return sandbox


def _uid_of(user: str) -> int:
    raw = str(user).split(":", 1)[0]
    try:
        return int(raw)
    except ValueError:
        return 65534


def _assert_unprivileged(user: str) -> None:
    """Refuse uid 0, however it is spelled.

    An adapter may pick a different unprivileged uid because its image pre-creates directories
    owned by one, but "run this scanner as root" is never a legitimate adapter decision -- with
    a bind-mounted host directory, root in the container writes host files as root.
    """
    raw = str(user).strip()
    uid = raw.split(":", 1)[0]
    if not raw or uid in ("0", "root", ""):
        logger.critical("scanner.root_user_blocked", user=raw)
        raise UnsafeScannerInvocationError(
            "A scanner container must not run as root.",
            context={"user": raw},
        )


def _validate_environment(environment: Mapping[str, str] | None) -> dict[str, str]:
    """Allow-list check on adapter-supplied environment. See :data:`ALLOWED_ENV_NAMES`."""
    if not environment:
        return {}
    checked: dict[str, str] = {}
    for name, value in environment.items():
        if name not in ALLOWED_ENV_NAMES:
            logger.critical("scanner.env_name_not_allowed", name=name)
            raise UnsafeScannerInvocationError(
                "A scanner requested an environment variable that is not allow-listed.",
                context={"name": name},
            )
        text = str(value)
        if not text or not ARGV_SAFE.match(text):
            raise UnsafeScannerInvocationError(
                "A scanner environment value contained characters outside the safe set.",
                context={"name": name},
            )
        checked[name] = text
    return checked


def _assert_mount_source_allowed(source: Path) -> None:
    resolved = str(source).replace("\\", "/")
    for forbidden in _FORBIDDEN_MOUNT_SOURCES:
        if resolved == forbidden or resolved.startswith(forbidden.rstrip("/") + "/"):
            logger.critical("scanner.forbidden_mount_blocked", source=resolved)
            raise UnsafeScannerInvocationError(
                "Refused to bind-mount a sensitive host path into a scanner.",
                context={"source": resolved},
            )


def assert_sandbox_safe(sandbox: dict[str, Any]) -> None:
    """Re-check the invariants on the built dict.

    Belt and braces on purpose. :func:`build_sandbox` is the only place these are set, so this
    can only fail if someone edits that function or mutates the dict afterwards -- which is
    precisely the change most likely to quietly weaken the sandbox, and the one a unit test
    should catch.
    """
    problems: list[str] = []

    if sandbox.get("privileged"):
        problems.append("privileged")
    if sandbox.get("cap_add"):
        problems.append("cap_add")
    if sandbox.get("cap_drop") != ["ALL"]:
        problems.append("cap_drop")
    if "no-new-privileges:true" not in (sandbox.get("security_opt") or []):
        problems.append("no-new-privileges")
    if not sandbox.get("pids_limit"):
        problems.append("pids_limit")
    if not sandbox.get("mem_limit"):
        problems.append("mem_limit")
    if not sandbox.get("nano_cpus"):
        problems.append("nano_cpus")
    if sandbox.get("network") in (None, "", "host", "bridge"):
        #: ``host`` would put the scanner on the host's network stack, which reaches every
        #: internal service. ``bridge`` is the default network that other Compose services may
        #: also be on.
        problems.append("network")
    if sandbox.get("pid_mode") or sandbox.get("ipc_mode") == "host":
        problems.append("namespace_sharing")

    try:
        _assert_unprivileged(str(sandbox.get("user") or ""))
    except UnsafeScannerInvocationError:
        problems.append("user")

    environment = sandbox.get("environment")
    if environment:
        for name in environment:
            upper = str(name).upper()
            if name not in ALLOWED_ENV_NAMES or any(
                fragment in upper for fragment in _SECRET_ENV_FRAGMENTS
            ):
                problems.append(f"environment:{name}")

    for source in sandbox.get("volumes") or {}:
        try:
            _assert_mount_source_allowed(Path(str(source)))
        except UnsafeScannerInvocationError:
            problems.append("volume")
        binding = (sandbox["volumes"][source] or {}).get("bind")
        if binding not in ALLOWED_WORK_MOUNTS:
            problems.append(f"volume_bind:{binding}")

    if problems:
        logger.critical("scanner.sandbox_invariant_violated", problems=problems)
        raise UnsafeScannerInvocationError(
            "The scanner sandbox failed its own safety invariants.",
            context={"problems": problems},
        )


def sandbox_evidence(sandbox: dict[str, Any]) -> dict[str, Any]:
    """The subset of the sandbox worth storing as FR-014 evidence.

    Everything in :func:`build_sandbox` is already safe to persist -- there is no secret in it
    by construction -- but the stored form is trimmed to the security-relevant keys so the
    audit answer is readable rather than a wall of Docker defaults.
    """
    return {
        "image": sandbox.get("image"),
        "network": sandbox.get("network"),
        "read_only_root": sandbox.get("read_only"),
        "user": sandbox.get("user"),
        "nano_cpus": sandbox.get("nano_cpus"),
        "mem_limit": sandbox.get("mem_limit"),
        "memswap_limit": sandbox.get("memswap_limit"),
        "pids_limit": sandbox.get("pids_limit"),
        "cap_drop": sandbox.get("cap_drop"),
        "security_opt": sandbox.get("security_opt"),
        "privileged": sandbox.get("privileged"),
        "tmpfs": sandbox.get("tmpfs"),
        "mounts": sorted(
            f"{source}:{(spec or {}).get('bind')}"
            for source, spec in (sandbox.get("volumes") or {}).items()
        ),
        #: Names only. The values are charset-checked paths, but recording names alone keeps
        #: this an audit answer to "was anything injected?" rather than a copy of the config.
        "environment_names": sorted(sandbox.get("environment") or {}),
        "environment_passed": len(sandbox.get("environment") or {}),
    }


__all__ = [
    "ALLOWED_ENV_NAMES",
    "ALLOWED_WORK_MOUNTS",
    "ARGV_SAFE",
    "FORBIDDEN_ARGV_SUBSTRINGS",
    "assert_sandbox_safe",
    "build_sandbox",
    "sandbox_evidence",
    "validate_argv",
    "validate_image",
]
