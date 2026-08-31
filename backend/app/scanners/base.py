"""The scanner adapter contract (FR-012, FR-014).

An adapter knows three things about one scanner: what image runs it, what argv invokes it, and
which files it leaves behind.  It knows nothing about Docker, timeouts, cancellation or object
storage -- :class:`~app.scanners.runner.DockerRunner` owns all of that, once, for every
scanner.  The split exists so that adding a scanner cannot weaken the sandbox: there is no
place in an adapter to pass a container option.

Two things adapters deliberately do **not** do.

They do not parse vulnerabilities.  PRD §8 puts custom scanner parsers out of scope; the
report file goes to DefectDojo, which owns parsing and deduplication.  What an adapter
declares is :attr:`ScannerAdapter.defectdojo_scan_type`, the name DefectDojo knows the format
by -- and :mod:`app.scanners.recon_assets` extracts *assets* from recon output, which is
discovery, not vulnerability parsing.

They do not build shell strings.  :meth:`ScannerAdapter.build_argv` returns a tuple that is
handed to the container as a list. Every element is checked against
:data:`~app.scanners.sandbox.ARGV_SAFE` before execution, so a target that made it through
:func:`app.core.targets.validate_target` and then somehow acquired a ``;`` still cannot become
a second command.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from app.core.config import ScannerSettings
from app.db.enums import ArtifactKind, ScannerName

#: Where the per-job host directory is bind-mounted inside every scanner container. Adapters
#: write output here and nowhere else -- the container root filesystem is read-only.
WORK_MOUNT = "/work"

#: How much of a stream is kept on the job record. Full stdout goes to object storage as an
#: artifact; this is what an operator sees in the UI and what may reach an LLM prompt after
#: further truncation (SEC-006).
STREAM_TAIL_CHARS = 4000


@dataclass(frozen=True, slots=True)
class ScannerRequest:
    """One scanner execution, fully specified.

    ``targets`` are canonical strings from :func:`app.core.targets.validate_target`. An
    adapter may reshape them (a hostname list, a URL) but must never accept a raw user string:
    policy checks happen once, at validation, and re-deriving a target here would bypass them.
    """

    scanner: ScannerName
    targets: tuple[str, ...]
    #: Host directory bind-mounted at the adapter's :attr:`ScannerAdapter.work_mount`.
    #: Created and wiped by the caller.
    workdir: Path
    timeout_seconds: int
    options: Mapping[str, Any] = field(default_factory=dict)

    @property
    def out_dir(self) -> Path:
        """Sub-directory adapters write output into, on the host side."""
        return self.workdir / "out"

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    """One output file produced inside the container, seen from the host."""

    kind: ArtifactKind
    filename: str
    path: Path
    size_bytes: int
    sha256: str
    #: Set only on the file DefectDojo ingests. ``None`` on stdout/stderr captures and on
    #: recon output, which is not a findings format at all.
    defectdojo_scan_type: str | None = None

    @property
    def is_importable(self) -> bool:
        return bool(self.defectdojo_scan_type) and self.size_bytes > 0


@dataclass(frozen=True, slots=True)
class ScannerResult:
    """Everything the runner learned from one execution.

    ``sandbox`` is stored verbatim on ``ScannerJob.sandbox``: it is the FR-014 evidence that
    the limits were actually applied, rather than a claim in a docstring that they were.
    """

    scanner: ScannerName
    exit_code: int
    duration_seconds: float
    argv: tuple[str, ...]
    image: str
    container_id: str | None
    sandbox: Mapping[str, Any]
    artifacts: tuple[ArtifactFile, ...]
    stdout_tail: str
    stderr_tail: str
    timed_out: bool = False
    cancelled: bool = False

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled

    @property
    def importable_artifacts(self) -> tuple[ArtifactFile, ...]:
        return tuple(artifact for artifact in self.artifacts if artifact.is_importable)

    @property
    def produced_output(self) -> bool:
        """Whether anything usable came out.

        Distinct from :attr:`succeeded`: a timed-out Nuclei run that wrote 200 findings before
        being killed is a partial success worth importing, and a scanner that exits 0 having
        written nothing is a failure the caller needs to see.
        """
        return any(artifact.size_bytes > 0 for artifact in self.artifacts)


class ScannerAdapter(ABC):
    """Per-scanner knowledge. Stateless -- one instance is shared for the process."""

    #: Which scanner this is. Also the registry key.
    name: ScannerName
    #: Attribute on :class:`~app.core.config.ScannerSettings` holding the image reference.
    #: Read through the settings object so an operator can pin a different tag without a code
    #: change, while :attr:`ScannerSettings.allowed_images` still gates what may run.
    image_setting: str
    #: DefectDojo's name for this scanner's report format, or ``None`` when the scanner does
    #: not produce findings.
    defectdojo_scan_type: str | None = None
    #: Some images have an entrypoint that already is the tool; others need the binary named.
    #: Recorded per adapter because getting it wrong produces a container that exits 0 having
    #: done nothing.
    entrypoint_is_tool: bool = True

    #: Where the per-job host directory is bind-mounted for *this* scanner. Almost always
    #: :data:`WORK_MOUNT`. ZAP overrides it because its report writer resolves report names
    #: against a hard-coded ``/zap/wrk``, so the only way to get a report onto the host is to
    #: mount there. :func:`~app.scanners.sandbox.build_sandbox` allow-lists the permitted
    #: values -- an adapter cannot mount anywhere it likes.
    work_mount: str = WORK_MOUNT

    #: ``False`` for images that cannot start with a read-only root filesystem. A documented
    #: per-adapter decision: every other restriction still applies, and the sandbox evidence
    #: stored on the job records that the root was writable.
    read_only_root: bool = True

    #: Override the container uid:gid. ``None`` uses ``ScannerSettings.run_as_user``
    #: (``nobody``). ZAP overrides it because its image pre-creates a home directory owned by
    #: uid 1000 and fails on startup if it cannot write there. The sandbox refuses uid 0
    #: whatever an adapter asks for, so this can weaken the sandbox only from one unprivileged
    #: user to another.
    run_as_user: str | None = None

    #: Environment variables the container needs to start. Restricted to
    #: :data:`~app.scanners.sandbox.ALLOWED_ENV_NAMES`, which is enforced in
    #: :func:`~app.scanners.sandbox.build_sandbox`, not here. In practice this is ``HOME``: the
    #: upstream scanner images assume root, and running them as ``nobody`` means telling them
    #: where to write.
    container_env: Mapping[str, str] = MappingProxyType({})

    #: Exit codes that mean "this scanner did its job". Most tools use 0; ZAP's baseline
    #: reports findings through its exit code, so a "failure" there is a normal result. The
    #: job service consults this rather than assuming 0, so a scan that found something is
    #: not recorded as a failed job.
    success_exit_codes: frozenset[int] = frozenset({0})

    def container_path(self, *parts: str) -> str:
        """A path under this adapter's :attr:`work_mount`, as the container sees it."""
        return "/".join((self.work_mount, *(part.strip("/") for part in parts if part)))

    def image(self, settings: ScannerSettings) -> str:
        image = getattr(settings, self.image_setting, None)
        if not isinstance(image, str) or not image:
            raise ValueError(f"ScannerSettings has no image for {self.name}")
        return image

    @abstractmethod
    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        """The exact argv to run. Never a shell string."""

    @abstractmethod
    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        """Find and hash the files the run produced, on the host side.

        Called after the container exits -- including after a timeout or a cancellation,
        because partial output is still evidence. Must tolerate missing files and return an
        empty tuple rather than raising.
        """

    def validate(self, request: ScannerRequest) -> None:
        """Adapter-specific preconditions.

        The default checks only that there is something to scan. Overrides enforce
        scanner-specific rules -- notably :mod:`app.scanners.reconftw`, where FR-008 forbids
        active-mode flags outright.
        """
        if not request.targets:
            raise ValueError(f"{self.name} was given no targets")

    def prepare(self, request: ScannerRequest) -> None:  # noqa: B027
        """Write any input files the argv references, before the container starts.

        Nuclei and Nmap take target lists from a file rather than a long argv, and that file
        has to exist on the host side of the bind mount first.

        Deliberately concrete and empty rather than abstract: most adapters have nothing to
        stage, and forcing each to declare an empty override would add noise to every future
        scanner for the benefit of none.
        """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name}>"


def tail(text: str, limit: int = STREAM_TAIL_CHARS) -> str:
    """Keep the *end* of a stream.

    The end is where the error is. A head-truncated scanner log shows the banner and the
    version string and nothing about why it failed.
    """
    if len(text) <= limit:
        return text
    return "...[truncated]...\n" + text[-limit:]


__all__ = [
    "STREAM_TAIL_CHARS",
    "WORK_MOUNT",
    "ArtifactFile",
    "ScannerAdapter",
    "ScannerRequest",
    "ScannerResult",
    "tail",
]
