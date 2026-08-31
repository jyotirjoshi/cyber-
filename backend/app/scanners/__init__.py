"""Scanner execution (FR-012, FR-013, FR-014, FR-015).

Two package-wide conventions, both of which exist because the alternative is a security bug
rather than an inconvenience:

**A scanner that ran and failed is a result, not an exception.**  ``DockerRunner.run`` returns a
:class:`~app.scanners.base.ScannerResult` with a non-zero ``exit_code`` for a Nuclei run that
crashed, a Nmap scan that timed out, and a ZAP baseline that reported warnings.  FR-040 requires
an assessment to degrade rather than collapse when one tool fails, and that is only possible if
the failure arrives as data.  Exceptions are reserved for "running this at all was wrong or
impossible": an argv that failed validation, an image outside the allow-list, an unreachable
Docker daemon.

**Nothing outside :mod:`app.scanners.sandbox` passes options to Docker.**  There is deliberately
no hook for an adapter to add a capability, a mount or an environment variable of its own
choosing.  An adapter declares *what to run*; the sandbox decides *what it may do*.  Adding a
fifth scanner therefore cannot weaken the isolation the other four run under, which is the whole
reason FR-014's guarantees are checkable.
"""

from __future__ import annotations

from app.scanners.artifacts import (
    MAX_ARTIFACT_BYTES,
    StoredArtifact,
    collect_dir,
    describe,
    hash_file,
    purge_workdir,
    upload_artifacts,
    write_stream_artifacts,
)
from app.scanners.base import (
    STREAM_TAIL_CHARS,
    WORK_MOUNT,
    ArtifactFile,
    ScannerAdapter,
    ScannerRequest,
    ScannerResult,
    tail,
)
from app.scanners.recon_assets import DiscoveredAsset, parse_recon_output
from app.scanners.registry import (
    ALL_ADAPTERS,
    PRE_APPROVAL_SCANNERS,
    active_scanners,
    get_adapter,
    scan_type_for,
)
from app.scanners.runner import DockerRunner
from app.scanners.sandbox import (
    ALLOWED_ENV_NAMES,
    ALLOWED_WORK_MOUNTS,
    ARGV_SAFE,
    assert_sandbox_safe,
    build_sandbox,
    sandbox_evidence,
    validate_argv,
    validate_image,
)

__all__ = [
    "ALLOWED_ENV_NAMES",
    "ALLOWED_WORK_MOUNTS",
    "ALL_ADAPTERS",
    "ARGV_SAFE",
    "MAX_ARTIFACT_BYTES",
    "PRE_APPROVAL_SCANNERS",
    "STREAM_TAIL_CHARS",
    "WORK_MOUNT",
    "ArtifactFile",
    "DiscoveredAsset",
    "DockerRunner",
    "ScannerAdapter",
    "ScannerRequest",
    "ScannerResult",
    "StoredArtifact",
    "active_scanners",
    "assert_sandbox_safe",
    "build_sandbox",
    "collect_dir",
    "describe",
    "get_adapter",
    "hash_file",
    "parse_recon_output",
    "purge_workdir",
    "sandbox_evidence",
    "scan_type_for",
    "tail",
    "upload_artifacts",
    "validate_argv",
    "validate_image",
    "write_stream_artifacts",
]
