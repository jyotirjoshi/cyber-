"""The graph's channel state (FR-033, FR-034; PRD §54).

LangGraph checkpoints this object after every node, keyed by ``thread_id``, and that
snapshot is what lets a run pause at the approval interrupt for up to
``agent.approval_ttl_hours`` and resume -- possibly in a different worker process, possibly
after a restart -- without replaying anything.  Two rules follow from that, and they are the
whole reason this module is small and boring:

**Everything here is JSON-serializable.**  The checkpointer serializes the state; an ORM
row, a ``UUID``, a ``datetime`` or a service object placed here would either fail to
serialize or, worse, be silently pickled and then be stale on resume.  Ids are ``str``,
enums are their ``.value`` string, timestamps are ISO strings.  The non-serializable
dependencies a node needs -- the settings, the LLM gateway, the Docker runner, the event
bus -- travel out-of-band in :class:`~app.agent.registry.AgentDeps`, bound into each node by
the graph builder and never checkpointed.

**The database is authoritative; this state is a cursor.**  A node re-reads the assessment,
the approval and the assets it operates on from Postgres inside its own transaction -- it
does not trust a scope, an approval id or a finding count carried in the channel, because a
checkpoint can be hours stale and an approval can be granted, customized or revoked in the
gap.  The security-critical example is the scanner node, which re-reads the granting
approval from the database and drives its target set from ``approved_payload`` alone; the
``approval_id`` here is a convenience for logging and events, never authority.  See
:mod:`app.agent.nodes.scan`.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any, TypedDict

from app.db.enums import (
    AgentRunStatus,
    AssessmentDepth,
    AssessmentStage,
    Scope,
)
from app.services.context import Principal


class AgentError(TypedDict):
    """The user-safe shape of a failure carried in :data:`AssessmentState.error`.

    Built from :class:`~app.core.errors.CynuxError` fields that are safe to show an
    operator -- never ``str(exc)``, which can quote a provider response or an internal
    host (SEC-002).  The runner reads this to fail the run and the assessment with a
    message a person can act on.
    """

    code: str
    category: str
    user_message: str
    stage: str | None


class AssessmentState(TypedDict, total=False):
    """Channels for the ``assessment`` graph.

    ``total=False`` because a node returns only the keys it changed and LangGraph merges
    that partial delta over the checkpoint; requiring every key on every return would make
    each node restate the whole state.  The keys the runner seeds before the first node are
    documented in :func:`initial_state`.
    """

    # -- identity (seeded once, never reassigned) ----------------------------
    #: The assessment this run drives. Created by the API caller with validated targets and
    #: a recorded authorization (FR-006) *before* the graph starts, so it always exists.
    assessment_id: str
    organization_id: str
    #: The conversation the run belongs to; the WebSocket and event replay key on it.
    session_id: str
    run_id: str
    #: LangGraph checkpoint key. Stable for the life of the run, which is what makes a
    #: resume after the approval interrupt a re-entry rather than a replay.
    thread_id: str
    #: :meth:`Principal.to_dict` output -- JSON-safe, credential-free. Re-hydrated by each
    #: node with :func:`principal_from`. The agent principal inherits the initiating user's
    #: role, so a node's authorization checks are the operator's, not a superuser's.
    principal: dict[str, Any]

    # -- request shape (seeded from the assessment row) ----------------------
    #: The operator's free-text intent (FR-004). Untrusted: fenced before it reaches any
    #: prompt (SEC-005). May be empty when the assessment was created from a bare target.
    objective: str
    depth: str
    scope: str
    #: FR-010 asset-selection budget: the most assets the agent will propose for scanning.
    scope_budget: int

    # -- progress cursor -----------------------------------------------------
    #: The stage most recently entered, as an :class:`AssessmentStage` value. Advisory: the
    #: durable progress checklist is derived from recorded ``agent_steps`` rows by
    #: :mod:`app.services.progress`, never from this field (FR-038).
    stage: str
    status: str

    # -- accumulated results (each a cursor into the database) ---------------
    #: The declared plan (FR-036), as a list of step dicts matching ``PlanStepOut``. Shown
    #: to the operator; the graph's topology, not this list, is what actually executes.
    plan: list[dict[str, Any]]
    #: The agent's structured reading of ``objective`` (FR-004).
    request_interpretation: dict[str, Any]
    #: Assets the agent selected for scanning (FR-010), as string ids. The approval the
    #: operator grants -- not this list -- is what the scanner node ultimately trusts.
    selected_asset_ids: list[str]
    #: The scope approval the run is blocked on or was resumed from. A convenience for
    #: events and logging; authority is re-read from the database (see the module docstring).
    approval_id: str | None
    #: True once the scanner node has run to completion, so a resume cannot re-scan.
    scanned: bool
    findings_total: int
    report_id: str | None

    # -- degradation and failure --------------------------------------------
    #: FR-039 degradations recorded so far, mirrored from the assessment row for events.
    degradations: list[dict[str, Any]]
    #: Set only on a fatal node failure. Its presence is how the runner distinguishes a run
    #: that failed from one that completed or is merely paused.
    error: AgentError | None


def initial_state(
    *,
    assessment_id: uuid.UUID,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    run_id: uuid.UUID,
    thread_id: str,
    principal: Principal,
    objective: str,
    depth: AssessmentDepth,
    scope: Scope,
    scope_budget: int,
) -> AssessmentState:
    """Build the seed state the runner hands to the graph's first invocation.

    Every id is stringified and every enum reduced to its value here, at the one boundary
    where the caller still holds the typed objects, so nothing downstream has to remember
    that the channel is JSON-only.
    """
    return AssessmentState(
        assessment_id=str(assessment_id),
        organization_id=str(organization_id),
        session_id=str(session_id),
        run_id=str(run_id),
        thread_id=thread_id,
        principal=principal.to_dict(),
        objective=objective,
        depth=depth.value,
        scope=scope.value,
        scope_budget=scope_budget,
        stage=AssessmentStage.QUEUED.value,
        status=AgentRunStatus.RUNNING.value,
        plan=[],
        request_interpretation={},
        selected_asset_ids=[],
        approval_id=None,
        scanned=False,
        findings_total=0,
        report_id=None,
        degradations=[],
        error=None,
    )


def state_uuid(state: Mapping[str, Any], key: str) -> uuid.UUID:
    """Read a required id channel back into a :class:`uuid.UUID`.

    Raises rather than returning ``None``: the identity keys are seeded before the first
    node, so their absence is a programming error in the runner, not a runtime condition a
    node should paper over.

    Takes a plain ``Mapping`` rather than :class:`AssessmentState`: the runner reads these
    channels back out of LangGraph's loosely-typed ``StateSnapshot.values`` (a ``dict``),
    and this helper needs only ``.get`` -- not the TypedDict's key contract.
    """
    raw = state.get(key)
    if not raw:
        raise KeyError(f"assessment state is missing required id {key!r}")
    return uuid.UUID(str(raw))


def optional_state_uuid(state: Mapping[str, Any], key: str) -> uuid.UUID | None:
    """Read an optional id channel (e.g. ``approval_id``) back into a ``UUID`` or ``None``.

    Accepts a plain ``Mapping`` for the same reason as :func:`state_uuid`: the runner passes
    ``StateSnapshot.values`` straight through when settling an interrupted or completed run.
    """
    raw = state.get(key)
    return uuid.UUID(str(raw)) if raw else None


__all__ = [
    "AgentError",
    "AssessmentState",
    "initial_state",
    "optional_state_uuid",
    "state_uuid",
]
