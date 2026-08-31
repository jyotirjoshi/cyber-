"""Docker execution of scanner containers (FR-012, FR-013, FR-014, FR-039).

The only module in Cynux that talks to the Docker API.  Everything security-relevant about how
a scanner runs is either in :mod:`app.scanners.sandbox` (what constrains it) or here (how it is
started, watched, killed and cleaned up).

``docker-py`` is synchronous, so every blocking call goes through ``asyncio.to_thread``.  This
is not cosmetic: the worker holds the Redis Streams consumer and publishes progress events on
the same loop, and a blocking ``container.wait()`` would freeze the progress stream for the
entire duration of a scan -- the user would watch a spinner for twenty minutes and conclude
Cynux had hung.

Four behaviours worth stating outright, because each is a place where the obvious
implementation is wrong:

**The runner owns the timeout, not the container.**  Docker has no per-container wall-clock
limit, and ``container.wait(timeout=...)`` only stops *waiting* -- the container keeps running.
So the wait is a poll loop, and on expiry the container is killed explicitly.  Artifacts are
still collected: a Nuclei run killed at the six-hour ceiling having written 300 findings has
produced real evidence, and discarding it because the process did not exit cleanly would throw
away the work and the target's exposure with it.

**Cancellation is cooperative and checked in the same loop.**  FR-039 requires a cancel to take
effect on a running scan.  The API sets ``cancel_requested`` on the job; the ``cancel`` callback
reads it; the loop kills the container and returns ``cancelled=True``.  A cancel is not a
failure and must not be retried, which is why it is a flag on the result rather than an
exception.

**Logs are read once, after the container stops.**  Streaming logs live would need a second
thread per container feeding a queue; reading them at the end is enough for a tail on the job
record and a full artifact in object storage, and it cannot deadlock on a container that never
writes to stdout.

**The container is always removed.**  ``finally: remove(force=True)``, even on an exception
path, even after a kill.  Orphaned containers hold their bind mount open, which blocks the
workdir purge, which leaks scan output onto the host disk -- and scan output contains the
target's exposure.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import structlog

from app.core.config import Settings
from app.core.errors import (
    DockerUnavailableError,
    ScannerContainerError,
    UnsafeScannerInvocationError,
)
from app.scanners.base import ScannerAdapter, ScannerRequest, ScannerResult, tail
from app.scanners.sandbox import build_sandbox, sandbox_evidence, validate_argv

logger = structlog.get_logger(__name__)

#: How often the wait loop wakes to check exit status, timeout and cancellation. A second is
#: responsive enough for a human clicking cancel and cheap enough to run for six hours.
POLL_INTERVAL_SECONDS = 1.0

#: Grace period between ``SIGTERM`` and ``SIGKILL``. Nmap and Nuclei flush partial output on
#: SIGTERM, so asking politely first is what makes partial artifacts possible at all.
GRACEFUL_STOP_SECONDS = 10

#: Cap on captured stream bytes. Scanner stdout can reach hundreds of megabytes (ZAP spider
#: logs); reading it all into the worker's memory to store a 4 KB tail would be absurd.
MAX_LOG_BYTES = 4 * 1024 * 1024


class DockerRunner:
    """Runs one scanner container at a time, per call.

    Concurrency is bounded above this class, by the job service's per-organization and global
    limits (PRD §57) -- the runner itself is stateless apart from the Docker client, so several
    calls may be in flight concurrently.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cfg = settings.scanner
        self._client: Any | None = None
        self._lock = asyncio.Lock()

    # -- client --------------------------------------------------------------

    async def _docker(self) -> Any:
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is not None:
                return self._client
            self._client = await asyncio.to_thread(self._connect)
            return self._client

    def _connect(self) -> Any:
        try:
            import docker
        except ImportError as exc:  # pragma: no cover - dependency is pinned
            raise DockerUnavailableError("The docker package is not installed.", cause=exc) from exc

        try:
            if self._cfg.docker_host:
                #: A socket proxy (e.g. tecnativa/docker-socket-proxy) is the recommended
                #: deployment: the worker gets container create/start/remove and nothing else,
                #: so a compromised worker cannot mount the host filesystem into a new
                #: container.
                client = docker.DockerClient(base_url=self._cfg.docker_host, timeout=60)
            else:
                client = docker.from_env(timeout=60)
            client.ping()
        except Exception as exc:
            raise DockerUnavailableError(
                "Could not reach the Docker daemon.",
                context={"docker_host": self._cfg.docker_host or "env"},
                cause=exc,
            ) from exc
        logger.info("scanner.docker_connected", docker_host=self._cfg.docker_host or "env")
        return client

    async def preflight(self) -> None:
        """Confirm Docker is reachable and every allow-listed image is present.

        Called at worker startup. A missing image is reported here rather than discovered
        mid-assessment, where the user has already approved a scan that cannot run. Missing
        images are logged and *not* fatal -- Docker pulls on first use, and failing startup
        because an optional scanner image has not been pulled yet would be worse.
        """
        client = await self._docker()

        def _check() -> list[str]:
            missing: list[str] = []
            for image in sorted(self._cfg.allowed_images):
                try:
                    client.images.get(image)
                except Exception:
                    missing.append(image)
            return missing

        missing = await asyncio.to_thread(_check)
        if missing:
            logger.warning("scanner.images_missing", images=missing)
        else:
            logger.info("scanner.preflight_ok", images=len(self._cfg.allowed_images))

    async def aclose(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await asyncio.to_thread(client.close)

    # -- execution -----------------------------------------------------------

    async def run(
        self,
        adapter: ScannerAdapter,
        request: ScannerRequest,
        *,
        on_log: Callable[[str], Awaitable[None]] | None = None,
        cancel: Callable[[], Awaitable[bool]] | None = None,
    ) -> ScannerResult:
        """Execute one scanner and return everything observed.

        Never raises for a scanner that ran and failed -- that is a :class:`ScannerResult` with
        a non-zero ``exit_code``, because a failed Nuclei run must not fail the assessment
        (FR-040 degradation). It *does* raise for conditions where running at all was wrong or
        impossible: :class:`~app.core.errors.UnsafeScannerInvocationError` for a blocked argv or
        image, :class:`~app.core.errors.DockerUnavailableError` for an unreachable daemon, and
        :class:`~app.core.errors.ScannerContainerError` when the container could not be created.
        """
        adapter.validate(request)

        workdir = Path(request.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        request.out_dir.mkdir(parents=True, exist_ok=True)
        adapter.prepare(request)
        _grant_container_access(workdir)

        image = adapter.image(self._cfg)
        argv = validate_argv(adapter.build_argv(request), scanner=str(adapter.name))
        sandbox = build_sandbox(
            self._cfg,
            workdir=workdir,
            image=image,
            read_only_root=adapter.read_only_root,
            work_mount=adapter.work_mount,
            run_as_user=adapter.run_as_user,
            environment=adapter.container_env,
        )
        evidence = sandbox_evidence(sandbox)

        timeout = max(1, min(request.timeout_seconds, self._cfg.max_timeout_seconds))
        if timeout < request.timeout_seconds:
            logger.info(
                "scanner.timeout_clamped",
                scanner=str(adapter.name),
                requested=request.timeout_seconds,
                applied=timeout,
            )

        client = await self._docker()
        logger.info(
            "scanner.starting",
            scanner=str(adapter.name),
            image=image,
            target_count=len(request.targets),
            timeout_seconds=timeout,
            #: The argv is logged in full. It contains targets and flags, never a credential --
            #: scanner containers receive no secrets at all (SEC-002/SEC-004).
            argv=list(argv),
        )

        started = time.monotonic()
        container: Any = None
        container_id: str | None = None
        timed_out = False
        cancelled = False
        exit_code = -1
        stdout_text = ""
        stderr_text = ""

        try:
            try:
                container = await asyncio.to_thread(
                    client.containers.run, command=list(argv), **sandbox
                )
            except UnsafeScannerInvocationError:
                raise
            except Exception as exc:
                raise self._container_error(exc, adapter=adapter, image=image) from exc

            container_id = getattr(container, "id", None)
            if on_log is not None:
                await on_log(f"{adapter.name} container started")

            exit_code, timed_out, cancelled = await self._await_exit(
                container,
                timeout=timeout,
                cancel=cancel,
                scanner=str(adapter.name),
            )

            stdout_text, stderr_text = await self._read_logs(container)
        finally:
            if container is not None:
                #: Shielded: a cancelled outer task must not skip the cleanup. Leaving the
                #: container alive would keep the bind mount busy and leak scan output.
                await asyncio.shield(self._remove(container))

        duration = time.monotonic() - started

        artifacts = await asyncio.to_thread(adapter.collect, request)

        result = ScannerResult(
            scanner=adapter.name,
            exit_code=exit_code,
            duration_seconds=round(duration, 3),
            argv=argv,
            image=image,
            container_id=container_id,
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
        container: Any,
        *,
        timeout: int,
        cancel: Callable[[], Awaitable[bool]] | None,
        scanner: str,
    ) -> tuple[int, bool, bool]:
        """Poll until the container exits, the deadline passes, or a cancel arrives."""
        deadline = time.monotonic() + timeout
        #: Cancellation is checked less often than exit status: it is a database or Redis read,
        #: and doing it every second for a six-hour scan is 21,600 pointless queries.
        cancel_every = 5
        tick = 0

        while True:
            state = await asyncio.to_thread(self._inspect_state, container)
            if state is None:
                #: The container vanished from under us -- an operator ran ``docker rm``, or
                #: the daemon restarted. Treat it as an abnormal exit rather than looping
                #: forever on a container that no longer exists.
                logger.warning("scanner.container_vanished", scanner=scanner)
                return -1, False, False
            if not state.get("Running", False):
                return int(state.get("ExitCode") or 0), False, False

            if time.monotonic() >= deadline:
                logger.warning("scanner.timeout", scanner=scanner, timeout_seconds=timeout)
                await self._stop(container, scanner=scanner)
                state = await asyncio.to_thread(self._inspect_state, container)
                return int((state or {}).get("ExitCode") or -1), True, False

            tick += 1
            if cancel is not None and tick % cancel_every == 0 and await cancel():
                logger.info("scanner.cancelled", scanner=scanner)
                await self._stop(container, scanner=scanner)
                state = await asyncio.to_thread(self._inspect_state, container)
                return int((state or {}).get("ExitCode") or -1), False, True

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    def _inspect_state(self, container: Any) -> dict[str, Any] | None:
        try:
            container.reload()
        except Exception as exc:
            if _is_not_found(exc):
                return None
            #: A transient daemon hiccup should not kill a six-hour scan. Report the container
            #: as still running and try again on the next tick; a persistent failure surfaces
            #: at the timeout.
            logger.warning("scanner.inspect_failed", error=type(exc).__name__)
            return {"Running": True, "ExitCode": None}
        attrs = getattr(container, "attrs", None) or {}
        state = attrs.get("State") or {}
        return {"Running": bool(state.get("Running")), "ExitCode": state.get("ExitCode")}

    async def _stop(self, container: Any, *, scanner: str) -> None:
        """SIGTERM, then SIGKILL. See :data:`GRACEFUL_STOP_SECONDS`."""

        def _op() -> None:
            try:
                container.stop(timeout=GRACEFUL_STOP_SECONDS)
            except Exception as exc:
                if _is_not_found(exc):
                    return
                logger.warning("scanner.stop_failed", scanner=scanner, error=type(exc).__name__)
                try:
                    container.kill()
                except Exception:
                    #: Nothing further to try. The ``finally`` in :meth:`run` still removes it
                    #: with ``force=True``, which the daemon implements as a kill.
                    logger.warning("scanner.kill_failed", scanner=scanner)

        await asyncio.to_thread(_op)

    async def cancel(self, container_id: str) -> None:
        """Kill a container by id.

        Used by the job service when it must stop a scan it did not start -- for instance when
        a different API replica handles the cancel request. The cooperative path in
        :meth:`_await_exit` is preferred, because it collects partial artifacts.
        """
        client = await self._docker()

        def _op() -> None:
            try:
                container = client.containers.get(container_id)
                container.kill()
            except Exception as exc:
                if _is_not_found(exc):
                    return
                logger.warning(
                    "scanner.remote_cancel_failed",
                    container_id=container_id[:12],
                    error=type(exc).__name__,
                )

        await asyncio.to_thread(_op)
        logger.info("scanner.remote_cancel_sent", container_id=container_id[:12])

    async def _read_logs(self, container: Any) -> tuple[str, str]:
        def _op() -> tuple[str, str]:
            def _decode(stream: bool) -> str:
                try:
                    raw = container.logs(
                        stdout=stream, stderr=not stream, tail="all", timestamps=False
                    )
                except Exception as exc:
                    if _is_not_found(exc):
                        return ""
                    logger.warning("scanner.log_read_failed", error=type(exc).__name__)
                    return ""
                if isinstance(raw, bytes):
                    return raw[-MAX_LOG_BYTES:].decode("utf-8", errors="replace")
                return str(raw)[-MAX_LOG_BYTES:]

            return _decode(True), _decode(False)

        return await asyncio.to_thread(_op)

    async def _remove(self, container: Any) -> None:
        def _op() -> None:
            try:
                container.remove(force=True, v=True)
            except Exception as exc:
                if _is_not_found(exc):
                    return
                logger.warning("scanner.remove_failed", error=type(exc).__name__)

        await asyncio.to_thread(_op)

    def _container_error(
        self, exc: Exception, *, adapter: ScannerAdapter, image: str
    ) -> ScannerContainerError | DockerUnavailableError:
        """Distinguish "the daemon is gone" from "this container would not start"."""
        text = str(exc)
        lowered = text.lower()
        if "connection" in lowered and ("refused" in lowered or "aborted" in lowered):
            return DockerUnavailableError(
                "Lost the connection to the Docker daemon while starting a scanner.",
                context={"scanner": str(adapter.name)},
                cause=exc,
            )
        if "no such image" in lowered or ("not found" in lowered and "image" in lowered):
            return ScannerContainerError(
                "The scanner image is not available on this host.",
                user_message=(
                    "A required scanner image has not been pulled on this host, so that "
                    "scanner was skipped."
                ),
                context={"scanner": str(adapter.name), "image": image},
                cause=exc,
            )
        return ScannerContainerError(
            "The scanner container could not be created.",
            context={
                "scanner": str(adapter.name),
                "image": image,
                #: Docker's message can be long and quotes the request body; the type is the
                #: useful part for triage and the full text is in the log above.
                "error": type(exc).__name__,
            },
            cause=exc,
        )


def _is_not_found(exc: Exception) -> bool:
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status == 404:
        return True
    return type(exc).__name__ in ("NotFound", "NullResource")


def _grant_container_access(workdir: Path) -> None:
    """Make the bind-mounted job directory writable by the container's unprivileged user.

    The worker creates this directory as its own uid; the scanner writes into it as ``nobody``
    (or, for ZAP, uid 1000). A bind mount carries host ownership straight through, so without
    this every scanner would start correctly, run correctly, and fail to write its report --
    the most expensive way possible to discover a permissions problem.

    ``0o777`` on a per-job directory that is deleted after upload, inside an artifact root the
    deployment creates as ``0o700``. Non-POSIX hosts ignore the mode bits, which is harmless:
    Docker Desktop's file sharing does not preserve them either.
    """
    for path in (workdir, workdir / "out"):
        try:
            path.chmod(0o777)
        except OSError as exc:  # pragma: no cover - platform dependent
            logger.debug("scanner.chmod_skipped", path=str(path), error=str(exc))


__all__ = [
    "GRACEFUL_STOP_SECONDS",
    "MAX_LOG_BYTES",
    "POLL_INTERVAL_SECONDS",
    "DockerRunner",
]
