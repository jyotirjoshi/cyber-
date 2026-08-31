"""The assessment pipeline as a LangGraph state machine (FR-036, PRD §54).

This module is the single source of truth for *control flow*: which node runs, in what
order, and where the one human gate sits.  Every step the pipeline performs is a node in
:mod:`app.agent.nodes`; this file wires those nodes into the fixed graph the runner
executes, interrupts and resumes.

**The topology is deterministic -- the model never decides what runs next.**  A plan the
LLM could author at will could drop the approval gate, skip the import, or reorder recon
after scanning; instead the edges here are hard-coded and the *only* branch is
:func:`route_after_discovery`, which chooses between two fixed continuations from data (the
assessment depth and what discovery selected), never from model output.  The declared plan
the operator sees (:mod:`app.agent.nodes.plan`) is built from the same
:func:`~app.scanners.registry.active_scanners` signal this router reads, so the plan shown
is exactly the graph that will run.

**The active-scan block sits behind an interrupt (FR-008, FR-011).**  Recon and asset
discovery are passive and always run.  Active work -- ``request_approval``, then the
scanners, the DefectDojo import and the intelligence enrichment -- is entered only when the
depth offers a scanner *and* discovery selected something to scan.  The graph is compiled
with ``interrupt_before=["execute_scanners"]``: once ``request_approval`` has recorded the
pending scope and LangGraph has checkpointed, the graph pauses *before* the first active
tool can touch a target.  The runner turns that pause into an ``interrupted`` run; only a
granted approval row and a resume (``ainvoke(None, config)``) carry execution into the
scanners.  A passive assessment -- or one where discovery found nothing to scan -- skips the
whole block and still produces an analyzed, prioritized report of what recon found.

**Dependencies are bound, not checkpointed.**  Each node is an ``async def
node(state, *, deps)``; :func:`build_graph` binds the live
:class:`~app.agent.registry.AgentDeps` onto every node with :func:`functools.partial`, so
only the JSON-serializable ``state`` ever crosses a checkpoint (see
:mod:`app.agent.registry` for why a pooled client must never be serialized into one).  The
checkpointer itself is owned by the runner and passed in, because its lifecycle -- a
Postgres connection pool -- outlives any single graph build and is shared across runs.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable
from typing import Protocol

import structlog
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agent.nodes.actions import create_actions
from app.agent.nodes.analyze import analyze_findings
from app.agent.nodes.approval import request_approval
from app.agent.nodes.discover_assets import discover_assets
from app.agent.nodes.enrich import enrich_intelligence
from app.agent.nodes.importer import import_findings
from app.agent.nodes.plan import plan
from app.agent.nodes.prioritize import prioritize_findings
from app.agent.nodes.recon import recon
from app.agent.nodes.remediate import remediate_findings
from app.agent.nodes.report import generate_report
from app.agent.nodes.scan import execute_scanners
from app.agent.nodes.understand import understand
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState
from app.db.enums import AssessmentDepth
from app.scanners.registry import active_scanners

log = structlog.get_logger(__name__)

#: The node the graph pauses *before* for human approval (FR-011). It is both the
#: ``interrupt_before`` target at compile and the destination of ``request_approval``'s
#: outgoing edge, so once approval has checkpointed the graph stops here until a granted
#: approval row and a resume drive it forward.
_SCANNER_NODE = "execute_scanners"

#: The two fixed continuations out of ``discover_assets`` (see :func:`route_after_discovery`).
#: ``request_approval`` opens the active-scan block; ``analyze_findings`` is the join point
#: the passive path jumps straight to.
_APPROVAL_NODE = "request_approval"
_ANALYSIS_NODE = "analyze_findings"


class _NodeFn(Protocol):
    """The shape every pipeline node shares: ``async def node(state, *, deps) -> delta``.

    Nodes read from the checkpointed state and return the partial delta LangGraph merges
    over the checkpoint; the ``deps`` are bound by :func:`build_graph` and never serialized.
    """

    def __call__(self, state: AssessmentState, *, deps: AgentDeps) -> Awaitable[dict[str, object]]:
        ...


#: Every node in the pipeline, keyed by its graph name.  The name is also the string each
#: node records on its ``agent_steps`` rows and on ``AgentRun.current_node``, so the live
#: cursor and the graph agree on where execution is.  Order here is documentation only --
#: control flow is the edges in :func:`build_graph`, not this tuple.
_NODES: tuple[tuple[str, _NodeFn], ...] = (
    ("understand", understand),
    ("plan", plan),
    ("recon", recon),
    ("discover_assets", discover_assets),
    (_APPROVAL_NODE, request_approval),
    (_SCANNER_NODE, execute_scanners),
    ("import_findings", import_findings),
    ("enrich_intelligence", enrich_intelligence),
    (_ANALYSIS_NODE, analyze_findings),
    ("prioritize_findings", prioritize_findings),
    ("remediate_findings", remediate_findings),
    ("create_actions", create_actions),
    ("generate_report", generate_report),
)


def route_after_discovery(state: AssessmentState) -> str:
    """Decide whether the active-scan block runs, from data rather than model output.

    This is the pipeline's only branch, and it mirrors exactly the decision
    :func:`app.agent.nodes.plan` made when it declared the plan, so the graph never runs a
    stage the operator was not shown:

    * If the depth offers no active scanner (a ``passive`` assessment),
      :func:`~app.scanners.registry.active_scanners` is empty and there is nothing to
      approve or scan -- go straight to analysis.
    * If discovery selected nothing to scan, the approval gate would ask the operator to
      approve an empty scope -- there is likewise nothing to do actively, so skip to
      analysis.
    * Otherwise there is a real scope to scan, so route into ``request_approval`` and the
      interrupt that follows it (FR-008/FR-011).

    ``depth`` is coerced defensively -- a missing or hand-edited checkpoint value falls back
    to the standard depth, and :func:`active_scanners` itself maps an unknown value to the
    standard set -- so this branch cannot raise on a malformed state.
    """
    depth = state.get("depth") or AssessmentDepth.STANDARD.value
    if not active_scanners(depth):
        return _ANALYSIS_NODE
    if not state.get("selected_asset_ids"):
        return _ANALYSIS_NODE
    return _APPROVAL_NODE


def build_graph(
    deps: AgentDeps, checkpointer: BaseCheckpointSaver | None = None
) -> CompiledStateGraph:
    """Wire the nodes into the pipeline graph and compile it for the runner.

    ``deps`` is bound onto every node with :func:`functools.partial`, leaving each a
    ``(state) -> delta`` callable whose only checkpointed argument is the JSON state.
    ``checkpointer`` is supplied by the runner (its Postgres pool outlives one build) and
    defaults to ``None`` so the graph can still be constructed for inspection or a unit test
    that does not persist -- but a real run needs one, because the ``execute_scanners``
    interrupt can only pause and resume against a checkpoint.

    The edges encode the fixed pipeline: a passive prefix (understand -> plan -> recon ->
    discover_assets) that always runs, a conditional into the active-scan block guarded by
    :func:`route_after_discovery`, and a cognitive tail (analysis -> prioritize -> remediate
    -> actions -> report) that always runs and terminates the graph.
    """
    builder = StateGraph(AssessmentState)

    for name, node in _NODES:
        builder.add_node(name, functools.partial(node, deps=deps))

    # Passive prefix: always runs, touches no target actively (FR-008).
    builder.add_edge(START, "understand")
    builder.add_edge("understand", "plan")
    builder.add_edge("plan", "recon")
    builder.add_edge("recon", "discover_assets")

    # The one branch: into the active-scan block, or straight to analysis.
    builder.add_conditional_edges(
        "discover_assets",
        route_after_discovery,
        [_APPROVAL_NODE, _ANALYSIS_NODE],
    )

    # Active-scan block: entered only via the branch above, and paused before the scanners
    # by ``interrupt_before`` until a human approves (FR-011).
    builder.add_edge(_APPROVAL_NODE, _SCANNER_NODE)
    builder.add_edge(_SCANNER_NODE, "import_findings")
    builder.add_edge("import_findings", "enrich_intelligence")
    builder.add_edge("enrich_intelligence", _ANALYSIS_NODE)

    # Cognitive tail: always runs, whichever path reached it, and ends the graph.
    builder.add_edge(_ANALYSIS_NODE, "prioritize_findings")
    builder.add_edge("prioritize_findings", "remediate_findings")
    builder.add_edge("remediate_findings", "create_actions")
    builder.add_edge("create_actions", "generate_report")
    builder.add_edge("generate_report", END)

    compiled = builder.compile(checkpointer=checkpointer, interrupt_before=[_SCANNER_NODE])
    log.debug(
        "agent.graph.compiled",
        nodes=len(_NODES),
        interrupt_before=_SCANNER_NODE,
        checkpointed=checkpointer is not None,
    )
    return compiled


__all__ = ["build_graph", "route_after_discovery"]
