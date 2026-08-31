"""Out-of-band dependencies for graph nodes (PRD §54).

A LangGraph node is a plain ``async`` callable, and everything it *reads* comes from the
checkpointed state.  But the things it *acts through* -- the settings, the LLM gateway, the
Docker runner, the object store, the event bus -- are neither serializable nor safe to
checkpoint: they hold connection pools and SDK clients, and a stale one restored from a
day-old checkpoint would be a live handle to nothing.

So they travel out of band.  The graph builder binds one :class:`AgentDeps` into every node
with :func:`functools.partial` (see :func:`app.agent.graph.build_graph`), and the node
receives it as an argument the checkpointer never sees.  This is the standard LangGraph
separation of *state* (persisted, serializable) from *dependencies* (injected, live).

:class:`AgentDeps` is built once per worker process and reused across runs -- the runner's
Docker client and the gateway's provider pools are expensive to create and safe to share.
Per-tenant clients (DefectDojo, Jira, Slack, intel) are deliberately absent: those carry
credentials scoped to one organization and are resolved inside a node from that node's
session and principal via :func:`app.services.integration.resolve_settings`, so a run can
never act through another tenant's integration.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import structlog
from redis.asyncio.client import Redis

from app.core.config import Settings
from app.integrations.storage import ObjectStorage
from app.llm.gateway import LLMGateway, get_gateway
from app.scanners.runner import DockerRunner
from app.services.events import EventBus, EventEmitter

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class AgentDeps:
    """The live services a node acts through.

    Frozen so a node cannot swap a dependency out from under the run, and the graph builder
    can close over a single instance safely.  Built with :meth:`create`.
    """

    settings: Settings
    #: Process-wide LLM gateway. Shared, not owned: :meth:`aclose` does not close it, because
    #: the gateway is a singleton other components (the API health check, other runs) hold.
    gateway: LLMGateway
    #: Tenant-agnostic object store handle. Every operation re-checks the ``org/{id}/`` key
    #: prefix, so sharing one handle across tenants cannot cross an isolation boundary.
    storage: ObjectStorage
    #: The sandboxed Docker runner. Owned by this instance and closed by :meth:`aclose`.
    runner: DockerRunner
    #: Redis connection pool. Shared with the worker, which owns its lifecycle; not closed
    #: here.
    redis: Redis
    event_bus: EventBus

    @classmethod
    def create(
        cls,
        settings: Settings,
        redis: Redis,
        *,
        gateway: LLMGateway | None = None,
        storage: ObjectStorage | None = None,
        runner: DockerRunner | None = None,
        event_bus: EventBus | None = None,
    ) -> AgentDeps:
        """Assemble the default dependency set for a worker.

        Each collaborator can be supplied explicitly -- the seam tests inject fakes through --
        and otherwise is constructed from ``settings`` (and ``redis`` for the event bus).
        """
        return cls(
            settings=settings,
            gateway=gateway or get_gateway(settings),
            storage=storage or ObjectStorage(settings),
            runner=runner or DockerRunner(settings),
            redis=redis,
            event_bus=event_bus or EventBus(redis, settings),
        )

    def emitter(
        self,
        *,
        session_id: uuid.UUID,
        assessment_id: uuid.UUID | None = None,
        run_id: uuid.UUID | None = None,
    ) -> EventEmitter:
        """A session-bound event emitter for a node.

        Every node builds its emitter here rather than constructing one, so a node can never
        publish under the wrong session id and the typed, summary-only emitter methods stay
        the only way an event reaches the socket (SEC-002).
        """
        return EventEmitter(
            self.event_bus,
            session_id=session_id,
            assessment_id=assessment_id,
            run_id=run_id,
        )

    async def aclose(self) -> None:
        """Release what this instance owns. Called at worker shutdown, never mid-run.

        Closes only the Docker runner it created.  The gateway is a shared singleton and the
        Redis pool belongs to the worker, so both are left to their owners; closing them
        here would break other users in the same process.
        """
        try:
            await self.runner.aclose()
        except Exception as exc:  # pragma: no cover - shutdown must not raise
            log.warning("agent.deps.runner_close_failed", error=type(exc).__name__)


__all__ = ["AgentDeps"]
