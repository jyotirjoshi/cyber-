"""Native subprocess execution of scanner binaries (FR-012, FR-013, FR-014, FR-039).

Replaces the former Docker-based runner. Each scanner (nmap, nuclei, zap, reconftw) must be
installed locally on the host running the worker. The runner resolves the binary path from
``ScannerSettings.bin_*`` settings, validates the argv through the same sandbox checks that
previously guarded Docker invocations, and executes the tool with
``asyncio.create_subprocess_exec`` -- no shell involved, so shell metacharacters in a target
can never become a second command.

The contract for callers is unchanged:

* Never raises for a scanner that ran and failed -- that is a :class:`ScannerResult` with a
  non-zero ``exit_code``.
* Raises :class:`~app.core.errors.UnsafeScannerInvocationError` for a blocked argv.
* Raises :class:`~app.core.errors.ScannerContainerError` when the binary could not be started
  (e.g. not installed).

Path rewriting: adapters were written for Docker and use container-internal paths like
``/work/out/nmap.xml``. The runner substitutes the local workdir for the container mount
prefix (``/work`` or ``/zap/wrk``) so the adapter argv needs no changes.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

import structlog

from app.core.config import Settings
from app.core.errors import (
    ScannerContainerError,
    UnsafeScannerInvocationError,
)
from app.scanners.base import ScannerAdapter, ScannerRequest, ScannerResult, tail
from app.scanners.sandbox import validate_argv

logger = structlog.get_logger(__name__)

#: How often the wait loop wakes to check cancellation and timeout.
POLL_INTERVAL_SECONDS = 1.0

#: Grace period: send SIGTERM, wait this many seconds, then SIGKILL.
GRACEFUL_STOP_SECONDS = 10

#: Cap on bytes read from stdout/stderr into memory for the job record tail.
MAX_LOG_BYTES = 4 * 1024 * 1024


class SubprocessRunner:
    """Runs one scanner binary at a time, per call, using asyncio subprocesses.

    Drop-in replacement for the former DockerRunner. The public interface
    (``run``, ``preflight``, ``aclose``, ``cancel``) is identical so all call sites
    continue to work without changes.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cfg = settings.scanner
        # pid -> asyncio.subprocess.Process, for out-of-band cancel
        self._processes: dict[int, asyncio.subprocess.Process] = {}

    # -- lifecycle -----------------------------------------------------------

    async def preflight(self) -> None:
        """Check that every scanner binary is present on PATH (or at its configured path).

        Missing binaries are warned but not fatal -- the same semantics as the old Docker image
        check. A scanner that is not installed produces a ScannerContainerError at run time
        rather than crashing the worker at startup.
        """
        missing: list[str] = []
        for name, path in self._cfg.scanner_bins.items():
            resolved = shutil.which(path)
            if resolved is None:
                missing.append(f"{name}={path}")
        if missing:
            logger.warning("scanner.binaries_missing", binaries=missing)
        else:
            logger.info("scanner.preflight_ok", scanners=len(self._cfg.scanner_bins))

    async def aclose(self) -> None:
        """No persistent resources to release."""

    # -- execution -----------------------------------------------------------

    async def run(
        self,
        adapter: ScannerAdapter,
        request: ScannerRequest,
        *,
        on_log: Callable[[str], Awaitable[None]] | None = None,
        cancel: Callable[[], Awaitable[bool]] | None = None,
    ) -> ScannerResult:
        """Execute one scanner binary and return everything observed."""
        adapter.validate(request)

        workdir = Path(request.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        request.out_dir.mkdir(parents=True, exist_ok=True)
        adapter.prepare(request)

        raw_argv = validate_argv(adapter.build_argv(request), scanner=str(adapter.name))
        # Resolve the binary and rewrite container-style paths to host paths.
        bin_path = self._resolve_binary(adapter)
        argv = self._rewrite_paths(raw_argv, adapter, workdir)

        timeout = max(1, min(request.timeout_seconds, self._cfg.max_timeout_seconds))
        if timeout < request.timeout_seconds:
            logger.info(
                "scanner.timeout_clamped",
                scanner=str(adapter.name),
                requested=request.timeout_seconds,
                applied=timeout,
            )

        # Build a minimal, safe environment: no host secrets, only what the tool needs.
        env = _build_env(adapter, workdir)

        logger.info(
            "scanner.starting",
            scanner=str(adapter.name),
            binary=bin_path,
            target_count=len(request.targets),
            timeout_seconds=timeout,
            argv=list(argv),
        )

        started = time.monotonic()
        process: asyncio.subprocess.Process | None = None
        timed_out = False
        cancelled = False
        exit_code = -1
        stdout_text = ""
        stderr_text = ""

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    bin_path,
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=str(workdir),
                )
            except (FileNotFoundError, PermissionError, OSError) as exc:
                raise ScannerContainerError(
                    f"Scanner binary '{bin_path}' could not be started.",
                    user_message=(
                        f"The scanner '{adapter.name}' is not installed or not executable "
                        "on this host."
                    ),
                    context={"scanner": str(adapter.name), "binary": bin_path},
                    cause=exc,
                ) from exc

            self._processes[process.pid] = process
            if on_log is not None:
                await on_log(f"{adapter.name} process started (pid {process.pid})")

            exit_code, timed_out, cancelled = await self._await_exit(
                process,
                timeout=timeout,
                cancel=cancel,
                scanner=str(adapter.name),
            )

            stdout_bytes, stderr_bytes = b"", b""
            if process.stdout:
                try:
                    stdout_bytes = await asyncio.wait_for(process.stdout.read(), timeout=10)
                except (asyncio.TimeoutError, Exception):
                    pass
            if process.stderr:
                try:
                    stderr_bytes = await asyncio.wait_for(process.stderr.read(), timeout=10)
                except (asyncio.TimeoutError, Exception):
                    pass
            stdout_text = stdout_bytes[-MAX_LOG_BYTES:].decode("utf-8", errors="replace")
            stderr_text = stderr_bytes[-MAX_LOG_BYTES:].decode("utf-8", errors="replace")
        finally:
            if process is not None:
                self._processes.pop(process.pid, None)
                _ensure_dead(process)

        duration = time.monotonic() - started
        artifacts = await asyncio.to_thread(adapter.collect, request)

        # Evidence stored on the job row -- analogous to the former sandbox_evidence dict.
        evidence: dict = {
            "binary": bin_path,
            "argv": list(argv),
            "workdir": str(workdir),
            "timeout_seconds": timeout,
        }

        result = ScannerResult(
            scanner=adapter.name,
            exit_code=exit_code,
            duration_seconds=round(duration, 3),
            argv=argv,
            image=bin_path,          # reuse the "image" slot for the binary path
            container_id=None,        # no container
            sandbox=evidence,
            artifacts=artifacts,
            stdout_tail=tail(stdout_text),
            stderr_tail=tail(stderr_text),
            timed_out=timed_out,
            cancelled=cancelled,
        )
        logger.info(
            "scanner.finished",
            scanner=str(adapter.name),
            exit_code=exit_code,
            duration_seconds=result.duration_seconds,
            artifacts=len(artifacts),
            timed_out=timed_out,
            cancelled=cancelled,
        )
        return result

    async def _await_exit(
        self,
        process: asyncio.subprocess.Process,
        *,
        timeout: int,
        cancel: Callable[[], Awaitable[bool]] | None,
        scanner: str,
    ) -> tuple[int, bool, bool]:
        """Poll until the process exits, the deadline passes, or a cancel arrives."""
        deadline = time.monotonic() + timeout
        cancel_every = 5
        tick = 0

        while True:
            if process.returncode is not None:
                return process.returncode, False, False

            if time.monotonic() >= deadline:
                logger.warning("scanner.timeout", scanner=scanner, timeout_seconds=timeout)
                await _stop_process(process, scanner=scanner)
                return process.returncode if process.returncode is not None else -1, True, False

            tick += 1
            if cancel is not None and tick % cancel_every == 0 and await cancel():
                logger.info("scanner.cancelled", scanner=scanner)
                await _stop_process(process, scanner=scanner)
                return process.returncode if process.returncode is not None else -1, False, True

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def cancel(self, container_id: str) -> None:
        """No-op in subprocess mode: out-of-band cancel is handled via the cancel callback.

        The ``container_id`` slot is unused (there is no container); the cooperative cancel
        path in ``_await_exit`` handles operator-initiated cancellations. This method exists
        only to satisfy the interface expected by callers that may pass a container_id.
        """
        logger.debug("scanner.subprocess_cancel_noop", container_id=container_id)

    # -- helpers -------------------------------------------------------------

    def _resolve_binary(self, adapter: ScannerAdapter) -> str:
        """Return the configured binary path for this adapter, or its name as a PATH fallback."""
        # adapter.image_setting is e.g. "image_nmap"; strip "image_" -> "nmap"
        key = adapter.image_setting.removeprefix("image_")
        return self._cfg.scanner_bins.get(key, key)

    def _rewrite_paths(
        self,
        argv: tuple[str, ...],
        adapter: ScannerAdapter,
        workdir: Path,
    ) -> tuple[str, ...]:
        """Substitute the container work-mount prefix with the real host workdir.

        Adapters were designed for Docker and emit paths like ``/work/out/nmap.xml``.
        This replaces the mount prefix (``/work`` or ``/zap/wrk``) with the real workdir
        so the binary writes to the correct location without any adapter changes.
        """
        mount = adapter.work_mount  # e.g. "/work" or "/zap/wrk"
        host = str(workdir)
        rewritten: list[str] = []
        for element in argv:
            if element.startswith(mount + "/") or element == mount:
                element = host + element[len(mount):]
            rewritten.append(element)
        return tuple(rewritten)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _build_env(adapter: ScannerAdapter, workdir: Path) -> dict[str, str]:
    """Build a minimal environment for the subprocess.

    Passes only what the tool actually needs: HOME and tmp/cache dirs pointing
    into the workdir so the process does not pollute the system home or /tmp.
    No Cynux secrets, no host environment variables.
    """
    import os
    scratch = str(workdir / ".scanner_home")
    Path(scratch).mkdir(parents=True, exist_ok=True)
    env: dict[str, str] = {
        "HOME": scratch,
        "TMPDIR": scratch,
        "XDG_CONFIG_HOME": scratch,
        "XDG_CACHE_HOME": scratch,
        "NO_COLOR": "1",
        # Some tools need PATH to find their own helpers.
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    }
    # Merge any adapter-declared env (allow-listed names only).
    for name, value in (adapter.container_env or {}).items():
        env[name] = value
    return env


async def _stop_process(process: asyncio.subprocess.Process, *, scanner: str) -> None:
    """Send SIGTERM, wait ``GRACEFUL_STOP_SECONDS``, then SIGKILL."""
    import os
    import signal as _signal

    if process.returncode is not None:
        return
    try:
        process.terminate()  # SIGTERM on POSIX, TerminateProcess on Windows
        try:
            await asyncio.wait_for(process.wait(), timeout=GRACEFUL_STOP_SECONDS)
        except asyncio.TimeoutError:
            try:
                process.kill()  # SIGKILL / TerminateProcess
            except (ProcessLookupError, OSError):
                pass
    except (ProcessLookupError, OSError):
        pass


def _ensure_dead(process: asyncio.subprocess.Process) -> None:
    """Best-effort synchronous kill for cleanup in finally blocks."""
    if process.returncode is None:
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass


# Keep the old name as an alias so any code that references DockerRunner still compiles.
DockerRunner = SubprocessRunner


__all__ = [
    "GRACEFUL_STOP_SECONDS",
    "MAX_LOG_BYTES",
    "POLL_INTERVAL_SECONDS",
    "SubprocessRunner",
    "DockerRunner",  # alias
]
