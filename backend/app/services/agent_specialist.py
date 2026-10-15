"""Durable specialist work records for autonomous assessment execution."""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import JobStatus, ScannerName
from app.db.models.agent import AgentSpecialistTask
from app.db.models.scanner import ScannerJob


class SpecialistOutcome(StrEnum):
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"


_ROLES: dict[ScannerName, str] = {
    ScannerName.NMAP: "network",
    ScannerName.NUCLEI: "web",
    ScannerName.ZAP: "web",
    ScannerName.TRIVY_REPO: "supply_chain",
    ScannerName.SEMGREP_REPO: "code",
    ScannerName.GITLEAKS_REPO: "secrets",
    ScannerName.TRIVY_IMAGE: "container",
    ScannerName.SYFT_IMAGE: "supply_chain",
    ScannerName.PROWLER_AWS: "cloud",
    ScannerName.PROWLER_AZURE: "cloud",
    ScannerName.PROWLER_GCP: "cloud",
}


def specialist_for_scanner(scanner: ScannerName) -> str:
    return _ROLES[scanner]


def specialist_fingerprint(scanner: ScannerName, targets: list[str]) -> str:
    material = f"{scanner.value}\x1f" + "\x1f".join(sorted(set(targets)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def evidence_gate(status: str, *, artifacts_archived: bool, artifact_count: int) -> SpecialistOutcome:
    """Translate a scanner result into a supervisor outcome using proof, not assertion."""
    if status != JobStatus.COMPLETED.value:
        return SpecialistOutcome.FAILED
    if not artifacts_archived or artifact_count < 1:
        return SpecialistOutcome.DEGRADED
    return SpecialistOutcome.COMPLETED


async def ensure_tasks(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    assessment_id: uuid.UUID,
    jobs: list[tuple[ScannerName, list[str]]],
) -> list[AgentSpecialistTask]:
    """Create the immutable specialist plan once and return it in plan order."""
    existing = {
        row.fingerprint: row
        for row in (
            await session.scalars(
                select(AgentSpecialistTask).where(
                    AgentSpecialistTask.organization_id == organization_id,
                    AgentSpecialistTask.run_id == run_id,
                )
            )
        ).all()
    }
    planned: list[AgentSpecialistTask] = []
    for index, (scanner, targets) in enumerate(jobs):
        fingerprint = specialist_fingerprint(scanner, targets)
        task = existing.get(fingerprint)
        if task is None:
            task = AgentSpecialistTask(
                organization_id=organization_id,
                run_id=run_id,
                assessment_id=assessment_id,
                plan_index=index,
                specialist=specialist_for_scanner(scanner),
                scanner=scanner.value,
                fingerprint=fingerprint,
                target_count=len(set(targets)),
                status="pending",
                max_attempts=3,
            )
            session.add(task)
            existing[fingerprint] = task
        planned.append(task)
    await session.flush()
    return planned


async def mark_running(
    session: AsyncSession, task_id: uuid.UUID, *, worker_id: str | None
) -> AgentSpecialistTask:
    task = await session.get(AgentSpecialistTask, task_id, with_for_update=True)
    if task is None:
        raise RuntimeError("specialist task disappeared")
    if task.status in {"completed", "degraded", "failed"}:
        return task
    task.status = "running"
    task.attempts += 1
    task.worker_id = worker_id
    task.heartbeat_at = utcnow()
    task.started_at = task.started_at or utcnow()
    return task


async def mark_terminal(
    session: AsyncSession,
    task_id: uuid.UUID,
    *,
    outcome: SpecialistOutcome,
    scanner_job_id: uuid.UUID | None,
    evidence: dict[str, Any],
    failure_code: str | None = None,
) -> AgentSpecialistTask:
    task = await session.get(AgentSpecialistTask, task_id, with_for_update=True)
    if task is None:
        raise RuntimeError("specialist task disappeared")
    task.status = outcome.value
    task.scanner_job_id = scanner_job_id
    task.evidence = evidence
    task.failure_code = failure_code
    task.completed_at = utcnow()
    task.heartbeat_at = utcnow()
    return task


async def bind_scanner_job(
    session: AsyncSession,
    task_id: uuid.UUID,
    *,
    scanner_job_id: uuid.UUID,
) -> None:
    task = await session.get(AgentSpecialistTask, task_id, with_for_update=True)
    if task is None:
        raise RuntimeError("specialist task disappeared")
    if task.scanner_job_id not in {None, scanner_job_id}:
        raise RuntimeError("specialist task was rebound to a different scanner job")
    task.scanner_job_id = scanner_job_id
    task.heartbeat_at = utcnow()


async def recover_stale_tasks(
    session: AsyncSession,
    *,
    run_id: uuid.UUID,
    organization_id: uuid.UUID,
    stale_before: dt.datetime,
) -> int:
    tasks = list(
        (
            await session.scalars(
                select(AgentSpecialistTask).where(
                    AgentSpecialistTask.organization_id == organization_id,
                    AgentSpecialistTask.run_id == run_id,
                    AgentSpecialistTask.status == "running",
                    AgentSpecialistTask.heartbeat_at < stale_before,
                ).with_for_update(skip_locked=True)
            )
        ).all()
    )
    recovered = 0
    for task in tasks:
        job = await session.get(ScannerJob, task.scanner_job_id) if task.scanner_job_id else None
        if (
            job is not None
            and job.status == JobStatus.RUNNING.value
            and job.heartbeat_at is not None
            and job.heartbeat_at >= stale_before
        ):
            task.heartbeat_at = job.heartbeat_at
            task.worker_id = job.worker_id
            continue
        task.status = "pending" if task.attempts < task.max_attempts else "failed"
        task.worker_id = None
        task.failure_code = "specialist_lease_expired"
        if task.status == "failed":
            task.completed_at = utcnow()
        recovered += 1
    return recovered


__all__ = [
    "SpecialistOutcome",
    "bind_scanner_job",
    "ensure_tasks",
    "evidence_gate",
    "mark_running",
    "mark_terminal",
    "recover_stale_tasks",
    "specialist_fingerprint",
    "specialist_for_scanner",
]
