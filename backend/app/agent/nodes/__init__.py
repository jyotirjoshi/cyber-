"""Graph node implementations for the assessment pipeline (PRD §54).

Each module here is one LangGraph node: an ``async def <name>(state, *, deps)`` that the
graph builder binds to its :class:`~app.agent.registry.AgentDeps` with
:func:`functools.partial`.  A node reads what it needs from the checkpointed
:class:`~app.agent.state.AssessmentState`, opens its own transaction with
:func:`~app.db.session.session_scope`, re-reads the database rows it operates on (the
state is a cursor, not the source of truth), does its work, and returns the partial state
delta LangGraph merges over the checkpoint.

The shared machinery every node uses -- the per-node timeline recorder, the principal and
emitter re-hydration helpers, the tenant-safe assessment loader -- lives in
:mod:`app.agent.nodes._common`.
"""
