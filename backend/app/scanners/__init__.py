"""Scanner execution (FR-012, FR-013, FR-014, FR-015).

Two package-wide conventions, both of which exist because the alternative is a security bug
rather than an inconvenience:

**A scanner that ran and failed is a result, not an exception.**  ``SubprocessRunner.run``
returns a :class:`~app.scanners.base.ScannerResult` with a non-zero ``exit_code`` for a
Nuclei run that crashed, a Nmap scan that timed out, and a ZAP baseline that reported warnings.
FR-040 requires an assessment to degrade rather than collapse when one tool fails, and that is
only possible if the failure arrives as data.  Exceptions are reserved for "running this at all
was wrong or impossible": an argv that failed validation, a binary outside the allow-list, or a
binary that is not installed.

**Argv validation guards every scanner invocation.**  There is no shell involved:
``asyncio.create_subprocess_exec`` takes a list. Every element is checked against
:data:`~app.scanners.sandbox.ARGV_SAFE` before execution, so a target that acquired a ``;``
still cannot become a second command.
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
from app.scanners.runner import DockerRunner, SubprocessRunner
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
    "DockerRunner",       # alias for SubprocessRunner
    "SubprocessRunner",
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
