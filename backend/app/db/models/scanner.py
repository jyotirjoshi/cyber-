"""Scanner jobs and artifacts (FR-012 .. FR-015).

A job is the durable record of one scanner container execution.  It stores the exact
argv used and a snapshot of the sandbox limits that were applied, so the question
"which image executed this, with what constraints?" has a database answer rather
than living only in a log line.  Raw output survives in object storage, referenced
by :class:`ScannerArtifact`.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk
from app.db.enums import ArtifactKind, JobStatus

if TYPE_CHECKING:
    from app.db.models.assessment import Assessment


class ScannerJob(Base, TenantMixin, TimestampMixin):
    __tablename__ = "scanner_jobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=JobStatus.QUEUED.value, index=True
    )

    #: Canonical targets this job scanned -- never raw user strings.
    targets: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    #: Full argv actually passed into the container.
    argv: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    #: Image reference, always taken from the settings allow list (SEC-004).
    image: Mapped[str | None] = mapped_column(String(500))
    container_id: Mapped[str | None] = mapped_column(String(128))
    exit_code: Mapped[int | None] = mapped_column(Integer)

    #: Snapshot of the limits applied: cpu quota, memory, pids, network, user, caps.
    #: This is the FR-014 evidence that the run was constrained.
    sandbox: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    #: Machine-readable failure code from the error taxonomy; user-safe (SEC-002).
    failure_code: Mapped[str | None] = mapped_column(String(60))
    failure_detail: Mapped[str | None] = mapped_column(Text)

    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Identifies the worker process that owns the job; NULL while queued. Makes
    #: orphaned jobs visible after a worker crash instead of hanging forever.
    worker_id: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)

    #: Cancellation is cooperative: the API sets the flag, the runner kills the
    #: container. Storing the request separately from the terminal status means a
    #: cancel that arrives after completion is recorded but does not rewrite history.
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cancel_requested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    #: True once raw artifacts were uploaded to object storage (FR-015).
    artifacts_archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Findings imported into DefectDojo from this job's output (FR-016).
    imported_finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    defectdojo_test_id: Mapped[int | None] = mapped_column(Integer)

    assessment: Mapped[Assessment] = relationship(back_populates="scanner_jobs", lazy=LAZY)
    artifacts: Mapped[list[ScannerArtifact]] = relationship(
        back_populates="job", cascade="all, delete-orphan", lazy=LAZY
    )

    __table_args__ = (
        # ``scanner`` selects the adapter that will build the argv and the sandbox, so an
        # unrecognized value is not a display bug -- it is a job the worker cannot
        # dispatch, discovered only after the row is already queued.
        CheckConstraint("scanner IN ('reconftw','nmap','nuclei','zap')", name="valid_scanner_name"),
        CheckConstraint(
            "status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED','TIMEOUT')",
            name="valid_job_status",
        ),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 86400", name="timeout_bounds"),
        Index("ix_scanner_jobs_assessment_id_scanner", "assessment_id", "scanner"),
        Index("ix_scanner_jobs_organization_id_status", "organization_id", "status"),
        Index("ix_scanner_jobs_worker_id_status", "worker_id", "status"),
    )

    @property
    def status_enum(self) -> JobStatus:
        return JobStatus(self.status)

    @property
    def is_active(self) -> bool:
        return self.status in (JobStatus.QUEUED.value, JobStatus.RUNNING.value)


class ScannerArtifact(Base, TenantMixin, TimestampMixin):
    """Pointer to one stored output file (nmap.xml, nuclei.jsonl, zap.json, ...).

    The file itself never enters the database and never enters an LLM prompt
    (SEC-006); only the metadata below and a bounded summary do.
    """

    __tablename__ = "scanner_artifacts"

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scanner_jobs.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(
        String(30), nullable=False, default=ArtifactKind.RAW_OUTPUT.value
    )
    #: File name as produced inside the container.
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    #: Object storage key. Namespaced by organization so a bucket policy can enforce
    #: tenant separation independently of application logic (SEC-003).
    storage_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(120))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    #: Checksum of the stored bytes, so a report can prove the artifact it cites is
    #: the artifact that was produced.
    sha256: Mapped[str | None] = mapped_column(String(64))

    job: Mapped[ScannerJob] = relationship(back_populates="artifacts", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("job_id", "filename", name="unique_artifact_filename"),
        CheckConstraint(
            "kind IN ('raw_output','stdout','stderr','report')", name="valid_artifact_kind"
        ),
        Index("ix_scanner_artifacts_organization_id_kind", "organization_id", "kind"),
    )


__all__ = ["ScannerArtifact", "ScannerJob"]
