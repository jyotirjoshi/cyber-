"""Node: request_approval -- the FR-011 human-in-the-loop gate before any active scan.

By the time this node runs, ``discover_assets`` has selected a scan scope and written it to
the database.  This node turns that selection into an *approval*: a durable row that is
authority, not a notification (see :mod:`app.services.approval`).  It does three things and
nothing else:

*   **Opens the approval.**  :func:`~app.services.approval.open_approval` is idempotent on
    the pending ``(assessment, scan_scope)`` pair, so a graph resumed from its checkpoint
    re-enters this node without opening a second gate.  The ``requested_payload`` it writes
    -- the selected asset ids, the depth's active scanners, the depth itself -- is the only
    thing the operator can later approve or narrow; the scanner node is driven from the
    *approved* payload alone, never from this one.
*   **Blocks the run.**  It transitions the assessment ``DISCOVERY -> WAITING_FOR_APPROVAL``.
    The graph is compiled with ``interrupt_before=["execute_scanners"]``, so the run then
    pauses at the scan boundary until a human resolves the approval and the runner resumes
    it -- possibly hours later, possibly in another process.
*   **Publishes it.**  ``agent_approval_required`` is the one event whose loss strands the
    run, so it is emitted from a fully-built :class:`~app.schemas.assessment.ApprovalOut`
    only *after* the transaction commits: an operator must never be shown a gate that rolled
    back, nor be able to act on one before it is durable.

The scanners offered come from :func:`~app.scanners.registry.active_scanners`, the same fixed
depth policy the plan declared -- this node proposes exactly what the plan promised, so the
operator is never asked to approve a tool the plan never mentioned.
"""

from __future__ import annotations

import structlog

from app.agent.nodes._common import load_assessment, record_step
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.db.enums import (
    ApprovalDecision,
    ApprovalKind,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    Criticality,
    RiskLevel,
    ScannerName,
)
from app.db.models.assessment import Approval
from app.db.models.asset import Asset
from app.db.session import session_scope
from app.scanners.registry import active_scanners
from app.schemas.assessment import ApprovalOut, ProposedAssetOut
from app.services.approval import open_approval
from app.services.assessment import transition
from app.services.asset import selected_assets

log = structlog.get_logger(__name__)

#: Operator-facing tool names, so the approval prompt reads "Nmap, Nuclei" rather than the
#: internal enum values. Mirrors the labels the report uses (``app.reporting.context``).
_SCANNER_LABELS: dict[ScannerName, str] = {
    ScannerName.NMAP: "Nmap",
    ScannerName.NUCLEI: "Nuclei",
    ScannerName.ZAP: "OWASP ZAP",
}

#: Criticalities that make an internet-exposed asset a higher-risk thing to scan (FR-034).
_ELEVATED_CRITICALITY: frozenset[str] = frozenset(
    {Criticality.CRITICAL.value, Criticality.HIGH.value}
)


async def request_approval(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Open the scope approval, block the run on it, and publish it to the operator."""
    async with record_step(
        deps,
        state,
        node="request_approval",
        stage=AssessmentStage.APPROVAL,
        label="Requesting approval to scan",
    ) as step:
        approval_out = await _open_and_stage(deps, state)

        await step.thinking(
            "I have proposed a scan scope and am waiting for your approval. No active "
            "scanning will run until you approve it."
        )
        # The one event whose loss strands the run: emitted after the commit above, from a
        # pre-built wire object so the emitter never lazy-loads under ``raise_on_sql``.
        await step.emitter.approval_required(approval_out)

        step.record_output(
            {
                "approval_id": str(approval_out.id),
                "proposed_assets": len(approval_out.proposed_assets),
                "proposed_scanners": [s.value for s in approval_out.proposed_scanners],
                "risk_level": approval_out.risk_level.value,
            }
        )

    log.info(
        "agent.awaiting_approval",
        assessment_id=state.get("assessment_id"),
        approval_id=str(approval_out.id),
        proposed_assets=len(approval_out.proposed_assets),
    )

    # ``status`` is the runner's to set (the interrupt turns the run INTERRUPTED); this node
    # owns only the stage cursor and the approval-id convenience channel. The assessment's
    # WAITING_FOR_APPROVAL status was persisted durably by ``transition`` above.
    return {
        "stage": AssessmentStage.APPROVAL.value,
        "approval_id": str(approval_out.id),
    }


async def _open_and_stage(deps: AgentDeps, state: AssessmentState) -> ApprovalOut:
    """Open (or reuse) the pending approval, block the assessment, and project the wire shape.

    Everything happens in one transaction: the approval is opened, the assessment is moved
    to ``WAITING_FOR_APPROVAL``, and the row is projected into an :class:`ApprovalOut` while
    still attached.  ``created_at`` is a server default, so under async it is refreshed onto
    the row before projection rather than triggering an implicit read mid-attribute-access.
    """
    depth = _depth_from(state)
    scanners = list(active_scanners(depth))
    assessment_id = state_uuid(state, "assessment_id")
    run_id = state_uuid(state, "run_id")

    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        assets = await selected_assets(session, assessment_id)

        approval = await open_approval(
            session,
            assessment,
            kind=ApprovalKind.SCAN_SCOPE,
            prompt=_prompt(assets, scanners),
            rationale=_rationale(assets),
            requested_payload=_requested_payload(assets, scanners, depth),
            risk_level=_risk_level(assets),
            agent_run_id=run_id,
            settings=deps.settings,
        )
        await transition(
            session,
            assessment,
            AssessmentStatus.WAITING_FOR_APPROVAL,
            stage=AssessmentStage.APPROVAL,
        )
        await session.refresh(approval, attribute_names=["created_at"])
        return _approval_out(approval, assets, scanners)


def _approval_out(
    approval: Approval, assets: list[Asset], scanners: list[ScannerName]
) -> ApprovalOut:
    """Project a loaded approval row into its wire shape.

    Built by hand rather than ``model_validate(approval)``: ``proposed_assets`` and
    ``proposed_scanners`` are derived from the request and the selected asset rows, not
    columns, and ``resolved_by`` is the resolver's email rather than the ``User`` relationship
    the row carries -- validating straight off the ORM object would raise under
    ``raise_on_sql`` or publish the wrong field.  The row stores the enum fields as their
    string values, so they are coerced back to their enum types here.
    """
    return ApprovalOut(
        id=approval.id,
        assessment_id=approval.assessment_id,
        agent_run_id=approval.agent_run_id,
        kind=ApprovalKind(approval.kind),
        decision=ApprovalDecision(approval.decision),
        prompt=approval.prompt,
        rationale=approval.rationale,
        risk_level=RiskLevel(approval.risk_level),
        requested_payload=approval.requested_payload or {},
        approved_payload=approval.approved_payload or {},
        expires_at=approval.expires_at,
        resolved_at=approval.resolved_at,
        resolved_by=None,
        resolution_note=approval.resolution_note,
        proposed_assets=[_proposed_asset(asset, scanners) for asset in assets],
        proposed_scanners=scanners,
        created_at=approval.created_at,
    )


def _proposed_asset(asset: Asset, scanners: list[ScannerName]) -> ProposedAssetOut:
    """One row of the scope card: what the agent proposes to scan, and why it was chosen."""
    return ProposedAssetOut(
        asset_id=asset.id,
        name=asset.name,
        endpoint=asset.endpoint,
        criticality=asset.criticality_enum,
        risk_score=asset.risk_score,
        internet_exposed=asset.internet_exposed,
        scanners=scanners,
        rationale=asset.selection_rationale,
    )


def _requested_payload(
    assets: list[Asset], scanners: list[ScannerName], depth: AssessmentDepth
) -> dict[str, object]:
    """The scope the operator will approve or narrow: asset ids, scanners, and the depth.

    The shape matches what :mod:`app.services.approval` reads back
    (``asset_ids``/``scanners``) and carries forward (``depth``), so nothing here is
    reinterpreted at resolution time.
    """
    return {
        "asset_ids": [str(asset.id) for asset in assets],
        "scanners": [scanner.value for scanner in scanners],
        "depth": depth.value,
    }


def _prompt(assets: list[Asset], scanners: list[ScannerName]) -> str:
    """The one-line question shown on the approval card. Count-based, no asset names."""
    tools = ", ".join(_SCANNER_LABELS.get(s, s.value) for s in scanners) or "the proposed scanners"
    return (
        f"Approve active scanning of {len(assets)} asset(s) using {tools}? Active scans send "
        "traffic to these targets, so they run only with your approval. Review the proposed "
        "assets below -- you can approve the full scope, narrow the selection, or reject it."
    )


def _rationale(assets: list[Asset]) -> str:
    """Why this scope: a name-free summary; each asset's own rationale rides on its row."""
    if not assets:
        return "No assets were selected for scanning."
    exposed = sum(1 for asset in assets if asset.internet_exposed)
    tail = f", of which {exposed} are reachable from the internet" if exposed else ""
    return (
        f"These {len(assets)} asset(s) scored highest for scanning{tail}. Each asset's "
        "individual selection rationale is shown alongside it."
    )


def _risk_level(assets: list[Asset]) -> RiskLevel:
    """Higher when the scope includes an internet-exposed critical or high asset (FR-034)."""
    for asset in assets:
        if asset.internet_exposed and str(asset.criticality) in _ELEVATED_CRITICALITY:
            return RiskLevel.HIGH
    return RiskLevel.MEDIUM


def _depth_from(state: AssessmentState) -> AssessmentDepth:
    """The assessment depth from the channel, defaulting to ``standard`` on anything unknown."""
    try:
        return AssessmentDepth(state.get("depth") or AssessmentDepth.STANDARD.value)
    except ValueError:
        return AssessmentDepth.STANDARD


__all__ = ["request_approval"]
