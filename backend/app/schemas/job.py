"""Scanner job and artifact wire types (FR-013, FR-014, FR-015).

``sandbox`` is echoed to the client on purpose.  FR-014 makes the isolation profile --
CPU and memory ceilings, dropped capabilities, read-only rootfs, network mode -- a
functional requirement, and the Definition of Done requires it to be *verified*.  A
profile that is only visible in worker logs cannot be checked by an operator or asserted
against by a test, so the effective profile is part of the job's public representation.

Artifacts are never inlined.  ``download_url`` is a short-lived presigned link to object
storage; streaming a multi-hundred-megabyte Nuclei output through the API (or into the
LLM context, SEC-006) is precisely what the storage layer exists to avoid.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import ArtifactKind, JobStatus, ScannerName


class ArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: ArtifactKind
    filename: str
    size_bytes: int | None = None
    #: Content hash, so a downloaded artifact can be tied to the one that was imported.
    sha256: str | None = None
    content_type: str | None = None
    #: Presigned and short-lived. ``None`` when storage is unavailable or the caller
    #: lacks the permission to download.
    download_url: str | None = None
    created_at: dt.datetime


class SandboxOut(BaseModel):
    """Effective container isolation profile (FR-014, SEC-004).

    Recorded per job rather than read from config at display time: config changes, and an
    audit needs the profile the container *actually ran with*.
    """

    model_config = ConfigDict(from_attributes=True)

    image: str | None = None
    cpu_limit: float | None = None
    memory_limit_mb: int | None = None
    pids_limit: int | None = None
    network_mode: str | None = None
    read_only_rootfs: bool | None = None
    user: str | None = None
    cap_drop: list[str] = Field(default_factory=list)
    security_opt: list[str] = Field(default_factory=list)
    tmpfs: list[str] = Field(default_factory=list)
    timeout_seconds: int | None = None


class ScannerJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    scanner: ScannerName
    status: JobStatus
    targets: list[str] = Field(default_factory=list)
    image: str | None = None
    started_at: dt.datetime | None = None
    finished_at: dt.datetime | None = Field(
        default=None,
        description="Alias of the model's completed_at; named for the PRD's job contract.",
    )
    exit_code: int | None = None
    duration_seconds: int | None = None
    imported_finding_count: int = 0
    #: See ``SandboxOut``. Free-form dict on the model; typed here.
    sandbox: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[ArtifactOut] = Field(default_factory=list)
    #: User-safe failure text from the error taxonomy. Container stderr is an artifact,
    #: not an error message -- scanner output routinely contains hostnames and tokens.
    error_message: str | None = None
    failure_code: str | None = None
    retry_count: int = 0
    timeout_seconds: int | None = None
    cancel_requested: bool = False
    defectdojo_test_id: int | None = None
    created_at: dt.datetime


class JobFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID | None = None
    scanner: ScannerName | None = None
    status: JobStatus | None = None
    active: bool | None = None


__all__ = ["ArtifactOut", "JobFilter", "SandboxOut", "ScannerJobOut"]
