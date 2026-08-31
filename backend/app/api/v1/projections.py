"""ORM rows into the v1 wire schemas (FR-011, FR-038, SEC-002).

WHY a dedicated layer: the assessment and approval *services* return ORM rows, not wire
types.  An assessment is far too connected to hand every router a pre-built DTO from the
service, and the service layer is where the security decisions live, not the presentation.
So the mapping from a loaded row to its ``*Out`` shape lives here, in one place, where
three rules hold uniformly:

*   **A person relationship is projected to their email, never the ``User`` row.**
    ``created_by`` and ``resolved_by`` are ``str | None`` on the wire; letting
    ``model_validate`` read the relationship would publish the whole user record or raise
    under ``lazy="raise_on_sql"`` (SEC-002).
*   **Enum columns are coerced back to their enum type.**  The database stores each as its
    string value; a caller gets ``AssessmentStatus.SCANNING``, not ``"SCANNING"``.
*   **Derived fields are computed from their real source, not trusted from a column.**  The
    FR-038 stage checklist comes from recorded ``agent_steps`` via
    :func:`app.services.progress.stage_checklist`, and the proposed-asset cards come from
    the selected ``assets`` rows -- never from something the agent could author at will.

The synchronous projections assume the relationships they read were eager-loaded by the
service that produced the row (``_LIST_OPTIONS``/``_DETAIL_OPTIONS`` in
:mod:`app.services.assessment` and :mod:`app.services.finding`), so they never trigger a
lazy load.  The ``async`` builders exist because a detail view needs data the list
projection has no reason to pay for -- a full :class:`~app.schemas.assessment.ApprovalOut`
needs the proposed-asset rows, an assessment detail needs its recorded steps, and a finding
detail needs its reviewer emails and tag-loaded asset, none carried by the detail options.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import IntegrationNotConfiguredError, StorageError
from app.db.enums import (
    ApprovalDecision,
    ApprovalKind,
    ArtifactKind,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    Criticality,
    FindingStatus,
    JobStatus,
    Priority,
    RiskLevel,
    ScannerName,
    Scope,
    Severity,
)
from app.db.models.agent import AgentStep
from app.db.models.assessment import Approval, Assessment, AssessmentTarget
from app.db.models.asset import Asset
from app.db.models.finding import Finding, Remediation
from app.db.models.identity import User
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.db.repository import tenant_select
from app.integrations.storage import ObjectStorage
from app.schemas.assessment import (
    ApprovalOut,
    AssessmentDetailOut,
    AssessmentOut,
    DegradationOut,
    PlanStepOut,
    ProposedAssetOut,
    TargetOut,
)
from app.schemas.asset import AssetOut
from app.schemas.finding import (
    EnrichmentOut,
    FindingDetailOut,
    FindingOut,
    RemediationOut,
    TicketLinkOut,
)
from app.schemas.job import ArtifactOut, ScannerJobOut
from app.services.approval import pending_approval
from app.services.asset import get_asset, selected_assets
from app.services.context import Principal
from app.services.progress import stage_checklist
from app.services.remediation import list_remediations


def _email(user: User | None) -> str | None:
    """A person relationship projected to their email address (SEC-002).

    Never the ``User`` row: the wire field is ``str | None`` and the rest of the user
    record has no business riding on an assessment or approval projection.
    """
    return user.email if user is not None else None


def _proposed_scanners(payload: dict[str, Any] | None) -> list[ScannerName]:
    """The scanners named in an approval's ``requested_payload``, as enum members.

    Filtered against the enum's own values rather than coerced blindly, so a payload that
    was hand-edited or written by an older build cannot raise here -- an unknown scanner
    name is dropped, matching :func:`app.services.approval` reading the same field back.
    """
    valid = set(ScannerName.values())
    return [ScannerName(name) for name in (payload or {}).get("scanners", []) if name in valid]


def target_out(target: AssessmentTarget) -> TargetOut:
    """One validated target row."""
    return TargetOut(
        id=target.id,
        raw_value=target.raw_value,
        canonical_value=target.canonical_value,
        target_type=target.target_type,
        host=target.host,
        port=target.port,
        host_count=target.host_count,
    )


def proposed_asset_out(asset: Asset, scanners: list[ScannerName]) -> ProposedAssetOut:
    """One scope-card row: what the agent proposes to scan, and why it was chosen.

    Mirrors ``app.agent.nodes.approval._proposed_asset`` so the card an operator approves
    over REST is identical to the one pushed over the socket at proposal time.
    """
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


def approval_out(
    approval: Approval,
    *,
    proposed_assets: list[ProposedAssetOut],
    proposed_scanners: list[ScannerName],
    resolved_by: str | None = None,
) -> ApprovalOut:
    """Project a loaded approval row into its wire shape.

    Built by hand rather than ``model_validate(approval)``: ``proposed_assets`` and
    ``proposed_scanners`` are derived, ``resolved_by`` is the resolver's email rather than
    the ``User`` relationship, and the enum columns are stored as strings and coerced back
    here.  This is the same projection ``app.agent.nodes.approval`` performs -- kept in step
    so a REST read and a socket push of one approval never disagree.
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
        resolved_by=resolved_by,
        resolution_note=approval.resolution_note,
        proposed_assets=proposed_assets,
        proposed_scanners=proposed_scanners,
        created_at=approval.created_at,
    )


async def load_approval_out(
    session: AsyncSession,
    approval: Approval,
    *,
    resolved_by: str | None = None,
) -> ApprovalOut:
    """Build a full :class:`ApprovalOut`, loading the proposed-asset cards it carries.

    The proposed scope is read from ``selected_assets`` -- the assessment's chosen assets,
    persisted at discovery -- so the card shows what the agent proposed regardless of what
    the operator later narrowed it to (that lives in ``approved_payload``).  ``resolved_by``
    is passed in rather than read off the row so this never lazy-loads the resolver under
    ``raise_on_sql``: a caller that loaded it (``get_approval``) supplies the email, and a
    pending approval -- which has no resolver -- supplies nothing.
    """
    scanners = _proposed_scanners(approval.requested_payload)
    assets = await selected_assets(session, approval.assessment_id)
    return approval_out(
        approval,
        proposed_assets=[proposed_asset_out(asset, scanners) for asset in assets],
        proposed_scanners=scanners,
        resolved_by=resolved_by,
    )


def _base_fields(assessment: Assessment) -> dict[str, Any]:
    """The fields shared by the list row and the detail view.

    One source for both so :func:`assessment_out` and :func:`assessment_detail_out` cannot
    drift on how a status or a target is projected.  ``duration_seconds`` is an ORM
    ``@property`` (computed against ``now`` while a run is live), and ``created_by`` is the
    requester's email -- both handled here so neither projection re-implements them.
    """
    return {
        "id": assessment.id,
        "reference": assessment.reference,
        "title": assessment.title,
        "status": AssessmentStatus(assessment.status),
        "current_stage": AssessmentStage(assessment.current_stage),
        "progress_percent": assessment.progress_percent,
        "scope": Scope(assessment.scope),
        "depth": AssessmentDepth(assessment.depth),
        "findings_total": assessment.findings_total,
        "findings_critical": assessment.findings_critical,
        "findings_high": assessment.findings_high,
        "findings_medium": assessment.findings_medium,
        "findings_low": assessment.findings_low,
        "findings_info": assessment.findings_info,
        "assets_discovered": assessment.assets_discovered,
        "assets_in_scope": assessment.assets_in_scope,
        "created_at": assessment.created_at,
        "started_at": assessment.started_at,
        "completed_at": assessment.completed_at,
        "duration_seconds": assessment.duration_seconds,
        "targets": [target_out(target) for target in assessment.targets],
        "created_by": _email(assessment.created_by),
    }


def assessment_out(assessment: Assessment) -> AssessmentOut:
    """One assessment as a list row.  Reads only ``_LIST_OPTIONS`` relationships."""
    return AssessmentOut(**_base_fields(assessment))


async def assessment_detail_out(
    session: AsyncSession, assessment: Assessment
) -> AssessmentDetailOut:
    """The full detail view: the list row plus plan, checklist, degradations and gate.

    Loaded against a ``detail=True`` assessment (``_DETAIL_OPTIONS`` eager-loads
    ``agent_runs`` and ``approvals``).  Two extra reads happen here rather than in the
    service: the recorded ``agent_steps`` that drive the FR-038 checklist, and the full
    projection of any pending approval (its proposed-asset cards).  Both are detail-only,
    so the list endpoint never pays for them.
    """
    steps = await _assessment_steps(session, assessment)
    pending = await pending_approval(session, assessment.id)
    pending_out = await load_approval_out(session, pending) if pending is not None else None

    return AssessmentDetailOut(
        **_base_fields(assessment),
        plan=[PlanStepOut.model_validate(step) for step in (assessment.plan or [])],
        request_interpretation=assessment.request_interpretation or {},
        stages=stage_checklist(assessment, steps),  # type: ignore[arg-type]
        degradations=[
            DegradationOut.model_validate(entry) for entry in (assessment.degradations or [])
        ],
        pending_approval=pending_out,
        failure_reason=assessment.failure_reason,
        failure_category=assessment.failure_category,
        agent_session_id=assessment.agent_session_id,
        defectdojo_engagement_id=assessment.defectdojo_engagement_id,
        defectdojo_product_id=assessment.defectdojo_product_id,
    )


async def _assessment_steps(session: AsyncSession, assessment: Assessment) -> Sequence[AgentStep]:
    """Every recorded step across the assessment's agent runs, ordered by sequence.

    The runs are already loaded (``_DETAIL_OPTIONS``); their ``steps`` are not, and touching
    them would raise under ``raise_on_sql``.  So the ids are read off the loaded runs and
    the steps fetched in one tenant-scoped query -- passed straight to
    :func:`~app.services.progress.stage_checklist`, whose ``_StepLike`` protocol the ORM row
    satisfies structurally.
    """
    run_ids = [run.id for run in assessment.agent_runs]
    if not run_ids:
        return []
    stmt = (
        tenant_select(AgentStep, assessment.organization_id)
        .where(AgentStep.run_id.in_(run_ids))
        .order_by(AgentStep.seq)
    )
    return (await session.execute(stmt)).scalars().all()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _in_kev_from_factors(finding: Finding) -> bool | None:
    """KEV state as recorded on the finding's risk factors, tri-state (FR-020).

    Read from ``risk_factors["inputs"]["in_kev"]`` -- the snapshot the prioritization step
    wrote -- rather than the ``enrichment`` relationship, which the list query does not load
    and which would raise under ``raise_on_sql`` if touched.  ``None`` when the finding was
    never prioritized or KEV was undetermined; never coerced to ``False``, so a KEV outage
    cannot masquerade as "not exploited".  Matches ``app.services.finding.risk_summary``.
    """
    inputs = (finding.risk_factors or {}).get("inputs") or {}
    state = inputs.get("in_kev")
    return state if isinstance(state, bool) else None


def _scanner(value: str | None) -> ScannerName | None:
    """Coerce the stored scanner name to its enum, tolerating an unknown value.

    ``findings.scanner`` carries no CHECK constraint -- a DefectDojo import can name any scan
    type -- so a value outside :class:`ScannerName` is projected as ``None`` rather than
    raising, the same defensive stance :func:`_proposed_scanners` takes on approval payloads.
    """
    if not value:
        return None
    try:
        return ScannerName(value)
    except ValueError:
        return None


def _finding_base(finding: Finding, *, in_kev: bool | None) -> dict[str, Any]:
    """The columns shared by the list row and the detail view.

    One source for both so :func:`finding_out` and :func:`finding_detail_out` cannot drift
    on how a status, priority or scanner is projected.  ``in_kev`` is supplied by the caller
    rather than read here because the two projections source it differently: the list row
    reads the ``risk_factors`` snapshot (no enrichment loaded), the detail view reads the
    authoritative enrichment row.  Touches only columns, never a relationship, so it is safe
    whatever was eager-loaded.
    """
    return {
        "id": finding.id,
        "assessment_id": finding.assessment_id,
        "asset_id": finding.asset_id,
        "defectdojo_finding_id": finding.defectdojo_finding_id,
        "title": finding.title,
        "severity": Severity(finding.severity),
        "status": FindingStatus(finding.status),
        "scanner": _scanner(finding.scanner),
        "endpoint": finding.endpoint,
        "component": finding.component,
        "component_version": finding.component_version,
        "cve_ids": list(finding.cve_ids or []),
        "cwe": finding.cwe,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "is_duplicate": finding.is_duplicate,
        "is_false_positive": finding.is_false_positive,
        "priority": Priority(finding.priority) if finding.priority else None,
        "risk_score": finding.risk_score,
        "risk_factors": finding.risk_factors or {},
        "asset_criticality": (
            Criticality(finding.asset_criticality) if finding.asset_criticality else None
        ),
        "in_kev": in_kev,
        "first_seen_at": finding.first_seen_at,
        "last_seen_at": finding.last_seen_at,
        "created_at": finding.created_at,
    }


def finding_out(finding: Finding) -> FindingOut:
    """One finding as a list row.

    Reads only columns -- ``_LIST_OPTIONS`` loads the asset, but the list row does not need
    it -- so it never triggers a lazy load.  ``in_kev`` comes from the ``risk_factors``
    snapshot because the list query does not load enrichment.
    """
    return FindingOut(**_finding_base(finding, in_kev=_in_kev_from_factors(finding)))


def remediation_out(remediation: Remediation) -> RemediationOut:
    """One remediation candidate, with the reviewer projected to their email (SEC-002).

    Built by hand rather than ``model_validate`` because the wire ``reviewed_by`` is
    ``str | None`` while the ORM attribute is a ``User`` relationship: letting Pydantic read
    it would fail validation, and it must have been eager-loaded
    (``list_remediations``/``get_remediation`` do ``selectinload(Remediation.reviewed_by)``)
    or reading it would raise under ``raise_on_sql``.
    """
    return RemediationOut(
        id=remediation.id,
        finding_id=remediation.finding_id,
        approach=remediation.approach,
        summary=remediation.summary,
        steps=list(remediation.steps or []),
        code_patch=remediation.code_patch,
        patch_language=remediation.patch_language,
        configuration_change=remediation.configuration_change,
        verification=remediation.verification,
        side_effects=remediation.side_effects,
        effort=remediation.effort,
        references=list(remediation.references or []),
        ai_model=remediation.ai_model,
        generated_at=remediation.generated_at,
        reviewed_at=remediation.reviewed_at,
        reviewed_by=_email(remediation.reviewed_by),
    )


async def finding_detail_out(
    session: AsyncSession,
    principal: Principal,
    finding: Finding,
) -> FindingDetailOut:
    """The full finding view: list row plus AI analysis, enrichment, remediations, tickets
    and the affected asset.

    Built against a ``detail=True`` finding (``_DETAIL_OPTIONS`` eager-loads ``asset``,
    ``enrichment``, ``remediations`` and ``tickets``).  Two of those need a second read
    rather than the loaded row:

    *   ``remediations`` carry ``reviewed_by`` as a ``User`` relationship the detail options
        do not load, so they are re-read through :func:`list_remediations`, which
        ``selectinload``s the reviewer -- the email projection then never lazy-loads.
    *   ``asset`` is projected with its ``tags`` (``AssetOut`` carries them), which the
        detail options do not load, so it is re-read through :func:`get_asset`, which does.
        The caller holds ``FINDING_READ`` and ``ASSET_READ`` is granted alongside it in the
        same read-only baseline, so the inner authorization always passes.

    ``in_kev`` is read from the loaded enrichment row -- the authoritative value -- falling
    back to the ``risk_factors`` snapshot for a finding analyzed but not yet enriched.
    """
    remediations = await list_remediations(session, principal, finding.id)
    asset_out: AssetOut | None = None
    if finding.asset_id is not None:
        asset = await get_asset(session, principal, finding.asset_id)
        asset_out = AssetOut.model_validate(asset)

    in_kev = (
        finding.enrichment.in_kev
        if finding.enrichment is not None
        else _in_kev_from_factors(finding)
    )
    return FindingDetailOut(
        **_finding_base(finding, in_kev=in_kev),
        ai_explanation=finding.ai_explanation,
        ai_business_impact=finding.ai_business_impact,
        ai_attack_scenario=finding.ai_attack_scenario,
        ai_evidence=list(finding.ai_evidence or []),
        ai_model=finding.ai_model,
        ai_analyzed_at=finding.ai_analyzed_at,
        ai_skipped_reason=finding.ai_skipped_reason,
        severity_raw=finding.severity_raw,
        defectdojo_test_id=finding.defectdojo_test_id,
        synced_at=finding.synced_at,
        enrichment=(
            EnrichmentOut.model_validate(finding.enrichment)
            if finding.enrichment is not None
            else None
        ),
        remediations=[remediation_out(item) for item in remediations],
        tickets=[TicketLinkOut.model_validate(ticket) for ticket in finding.tickets],
        asset=asset_out,
    )


# ---------------------------------------------------------------------------
# Scanner jobs
# ---------------------------------------------------------------------------


def _artifact_out(artifact: ScannerArtifact, *, download_url: str | None) -> ArtifactOut:
    """One stored scanner output, with a presigned link injected by the caller.

    The bytes themselves never enter this projection or an LLM prompt (SEC-006); only the
    metadata and a short-lived ``download_url`` do.
    """
    return ArtifactOut(
        id=artifact.id,
        kind=ArtifactKind(artifact.kind),
        filename=artifact.filename,
        size_bytes=artifact.size_bytes,
        sha256=artifact.sha256,
        content_type=artifact.content_type,
        download_url=download_url,
        created_at=artifact.created_at,
    )


async def _artifact_download_url(
    storage: ObjectStorage, artifact: ScannerArtifact, *, organization_id: uuid.UUID
) -> str | None:
    """A short-lived presigned link for one artifact, or ``None`` if storage cannot sign it.

    Best-effort by design (FR-015): a job listing must not fail because object storage is
    unconfigured or briefly unreachable, so a signing failure degrades the one link to
    ``None`` rather than the whole response to a 500. The link points straight at storage so a
    multi-hundred-megabyte scanner output never streams through the API.
    """
    if not storage.configured:
        return None
    try:
        return await storage.presign_get(
            artifact.storage_key,
            organization_id=organization_id,
            download_name=artifact.filename,
        )
    except (StorageError, IntegrationNotConfiguredError):
        return None


async def job_out(
    job: ScannerJob, *, storage: ObjectStorage, organization_id: uuid.UUID
) -> ScannerJobOut:
    """One scanner job with its artifacts and the sandbox profile it actually ran with.

    Hand-built rather than ``model_validate`` because three wire fields are named for the PRD
    job contract, not the column: ``finished_at`` is the model's ``completed_at``,
    ``error_message`` is the user-safe ``failure_detail`` (container stderr is an artifact,
    never an error string -- SEC-002), and each artifact's ``download_url`` is a presigned link
    minted here, not stored (FR-015). The ``artifacts`` relationship must have been
    eager-loaded by the service (``get_job``/``list_jobs`` ``selectinload`` it) or reading it
    would raise under ``lazy="raise_on_sql"``.
    """
    artifacts = [
        _artifact_out(
            artifact,
            download_url=await _artifact_download_url(
                storage, artifact, organization_id=organization_id
            ),
        )
        for artifact in job.artifacts
    ]
    return ScannerJobOut(
        id=job.id,
        assessment_id=job.assessment_id,
        scanner=ScannerName(job.scanner),
        status=JobStatus(job.status),
        targets=list(job.targets or []),
        image=job.image,
        started_at=job.started_at,
        finished_at=job.completed_at,
        exit_code=job.exit_code,
        duration_seconds=job.duration_seconds,
        imported_finding_count=job.imported_finding_count,
        sandbox=dict(job.sandbox or {}),
        artifacts=artifacts,
        error_message=job.failure_detail,
        failure_code=job.failure_code,
        retry_count=job.retry_count,
        timeout_seconds=job.timeout_seconds,
        cancel_requested=job.cancel_requested,
        defectdojo_test_id=job.defectdojo_test_id,
        created_at=job.created_at,
    )


__all__ = [
    "approval_out",
    "assessment_detail_out",
    "assessment_out",
    "finding_detail_out",
    "finding_out",
    "job_out",
    "load_approval_out",
    "proposed_asset_out",
    "remediation_out",
    "target_out",
]
