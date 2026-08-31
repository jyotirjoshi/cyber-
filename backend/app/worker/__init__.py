"""The agent worker: the background process that actually runs assessments (FR-033; §54, §57).

The API is the front door -- it authenticates, validates targets, records authorizations and
creates rows -- but it never runs a graph in a request.  It hands work to this package over a
Redis Stream (:mod:`app.worker.protocol`), and a pool of these workers consumes that stream,
drives each run through the LangGraph pipeline, checkpoints it, pauses it at the human approval
gate and resumes it, and reclaims a run whose worker crashed.

Only the queue contract is re-exported here, because that is the sole surface the API depends
on: it publishes :class:`RunRequest` messages and never imports the runtime (which pulls in
LangGraph).  The worker runtime itself -- the consumer loop and its entry point -- is imported
directly from :mod:`app.worker.worker` and :mod:`app.worker.__main__` by the process that runs
it, not through this namespace.
"""

from __future__ import annotations

from app.worker.protocol import RunAction, RunRequest, publish_run_request

__all__ = [
    "RunAction",
    "RunRequest",
    "publish_run_request",
]
