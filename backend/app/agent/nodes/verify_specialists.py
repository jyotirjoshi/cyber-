"""Post-import evidence verification for autonomous specialist work."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select

from app.agent.nodes._common import record_step
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.db.enums import AssessmentStage, JobStatus
from app.db.models.agent import AgentSpecialistTask
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.db.session import session_scope

_NODE = "verify_specialists"


async def verify_specialists(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Reconcile every specialist claim against durable scanner artifacts after import."""
    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.IMPORT,
        label="Verifying specialist evidence",
        tool_name="evidence_verifier",
    ) as step:
        verified = degraded = failed = 0
        async with session_scope(deps.settings) as session:
            tasks = list(
                (
                    await session.scalars(
                        select(AgentSpecialistTask)
                        .where(
                            AgentSpecialistTask.organization_id == state_uuid(state, "organization_id"),
                            AgentSpecialistTask.run_id == state_uuid(state, "run_id"),
                        )
                        .order_by(AgentSpecialistTask.plan_index)
                        .with_for_update()
                    )
                ).all()
            )
            for task in tasks:
                job = await session.get(ScannerJob, task.scanner_job_id) if task.scanner_job_id else None
                artifact_count = 0
                if job is not None and job.organization_id == task.organization_id:
                    artifact_count = int(
                        await session.scalar(
                            select(func.count(ScannerArtifact.id)).where(
                                ScannerArtifact.organization_id == task.organization_id,
                                ScannerArtifact.job_id == job.id,
                            )
                        )
                        or 0
                    )
                proof_valid = bool(
                    job is not None
                    and job.status == JobStatus.COMPLETED.value
                    and job.artifacts_archived
                    and artifact_count > 0
                )
                evidence = dict(task.evidence or {})
                evidence.update(
                    {
                        "verification_status": "passed" if proof_valid else "failed",
                        "verified_at": dt.datetime.now(dt.UTC).isoformat(),
                        "artifact_count": artifact_count,
                        "imported_finding_count": int(job.imported_finding_count) if job else 0,
                    }
                )
                task.evidence = evidence
                if proof_valid:
                    task.status = "completed"
                    verified += 1
                elif task.status == "failed":
                    failed += 1
                else:
                    task.status = "degraded"
                    task.failure_code = task.failure_code or "specialist_evidence_unverified"
                    degraded += 1
        step.record_output(
            {"verified": verified, "degraded": degraded, "failed": failed}
        )
        if degraded or failed:
            step.degrade("Some specialist results could not be verified from archived scanner evidence.")
    return {"stage": AssessmentStage.IMPORT.value}


__all__ = ["verify_specialists"]
