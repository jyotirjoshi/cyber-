"""Worker process entry point: ``python -m app.worker`` (FR-020, FR-033).

One invocation is one :class:`~app.worker.worker.AgentWorker` process.  It owns the three
process-scoped resources a worker needs and tears them down in the right order:

* the **Redis** connection pool (shared with the graph's event bus and the run stream);
* the **LangGraph checkpointer** -- opened once, via :func:`checkpointer_for`, around every run
  the process will ever execute, because that saver is what lets a run survive this process
  dying (FR-033);
* the **Docker runner** and other collaborators bundled in :class:`AgentDeps`.

Startup refuses to proceed on a fatal misconfiguration: :func:`validate_runtime_configuration`
with ``role="worker"`` raises if the worker could not do its job (no object storage or
DefectDojo credentials to push results to), and a worker that cannot deliver results must not
consume runs (FR-020).  Non-fatal gaps come back as warnings and are logged, not fatal.

Shutdown is graceful where the platform allows it: ``SIGTERM``/``SIGINT`` ask the worker to
stop, which cancels any in-flight run and leaves its stream message pending for another worker
to reclaim from the checkpoint.  ``loop.add_signal_handler`` is POSIX-only; on Windows the
fallback is ordinary ``KeyboardInterrupt`` unwinding, which reaches the same end state.

Importing this module has no side effects -- ``main`` runs only under ``__main__`` -- so the
per-file import gate can load it without spawning a worker.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket

import structlog

from app.agent.registry import AgentDeps
from app.agent.runner import AgentRunner, checkpointer_for
from app.core.config import get_settings, validate_runtime_configuration
from app.core.logging_conf import configure_logging
from app.core.redis_client import close_redis, get_redis
from app.worker.worker import AgentWorker

log = structlog.get_logger(__name__)


def _worker_id() -> str:
    """A stable-per-process identity, also used as the Redis consumer name.

    ``host:pid`` is enough to attribute a pending stream entry to the process holding it and to
    tell two workers on one host apart, which is all reclaim needs.
    """
    return f"{socket.gethostname()}:{os.getpid()}"


def _install_signal_handlers(worker: AgentWorker) -> None:
    """Wire ``SIGTERM``/``SIGINT`` to a graceful stop where the event loop supports it.

    On Windows ``add_signal_handler`` raises ``NotImplementedError``; there we simply do not
    install a handler and rely on the default ``KeyboardInterrupt`` unwinding the ``async with``
    blocks in :func:`_amain`.  Either way an in-flight run's message is left pending for reclaim
    (FR-033), so no work is lost.
    """
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, worker.request_stop)
        except NotImplementedError:
            log.debug("worker.signal_handler_unsupported", signal=sig.name)


async def _amain() -> None:
    """Build the worker's resources, run it, and tear them down in reverse order."""
    settings = get_settings()
    configure_logging(settings)
    worker_id = _worker_id()
    for warning in validate_runtime_configuration(settings, role="worker"):
        log.warning("worker.config_warning", detail=warning)

    redis = get_redis(settings)
    try:
        async with checkpointer_for(settings) as checkpointer:
            deps = AgentDeps.create(settings, redis)
            runner = AgentRunner(deps, checkpointer, worker_id=worker_id)
            worker = AgentWorker(settings, redis, deps, runner, worker_id=worker_id)
            _install_signal_handlers(worker)
            try:
                await worker.run()
            finally:
                # Closes the Docker runner this process created; the checkpointer pool closes
                # with the ``async with`` and Redis closes in the outer ``finally``.
                await deps.aclose()
    finally:
        await close_redis()


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
