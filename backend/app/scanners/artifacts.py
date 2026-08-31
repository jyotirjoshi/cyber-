"""Artifact hashing, upload and workdir purge (FR-015).

The chain this module implements is deliberate and ordered: **hash, upload, verify, purge.**

Hashing first means the checksum recorded on ``scanner_artifacts`` describes the bytes as the
scanner wrote them.  Uploading second puts them somewhere durable.  Purging last means the host
workdir -- which holds a complete picture of a customer's exposure, in cleartext, on a shared
worker -- does not outlive the job.  Skipping the purge is the failure mode that matters: a
worker that runs a thousand assessments accumulates a thousand organizations' scan output on one
disk, which is SEC-003 defeated by housekeeping rather than by a bug.

The purge is therefore best-effort but *always attempted*, including on the failure path. An
upload that fails leaves the job marked un-archived and the workdir deleted: the artifacts are
lost, which is visible and recorded, rather than retained on disk where they are invisible and
forgotten.
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import structlog

from app.db.enums import ArtifactKind
from app.integrations.storage import (
    ObjectStorage,
    StoredObject,
    artifact_key,
    guess_content_type,
)
from app.scanners.base import ArtifactFile

logger = structlog.get_logger(__name__)

#: Files above this are not uploaded. A 2 GB ZAP session file is not evidence anybody reads,
#: and object storage costs are real. The job records that it was skipped, so the omission is
#: visible rather than silent.
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

#: Names that appear in scanner workdirs and are never worth keeping.
_IGNORED_NAMES = frozenset({".DS_Store", "Thumbs.db", ".gitkeep"})


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    """An :class:`~app.scanners.base.ArtifactFile` after upload.

    Field names line up with the ``scanner_artifacts`` columns so the service layer can build
    the row directly.
    """

    kind: ArtifactKind
    filename: str
    storage_key: str
    content_type: str
    size_bytes: int
    sha256: str
    defectdojo_scan_type: str | None = None


def hash_file(path: Path) -> tuple[str, int]:
    """SHA-256 and size, streamed.

    Streamed rather than ``read()``-then-hash because scanner output is routinely larger than
    the worker's comfortable memory budget, and a worker may be finishing several scans at once.
    """
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def describe(
    path: Path,
    *,
    kind: ArtifactKind = ArtifactKind.RAW_OUTPUT,
    defectdojo_scan_type: str | None = None,
    filename: str | None = None,
) -> ArtifactFile | None:
    """Build an :class:`ArtifactFile` for one file, or ``None`` if it is not usable.

    ``None`` rather than an exception because adapters call this over a glob of files a scanner
    may or may not have written, and a missing file is the normal case for a scan that found
    nothing.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        sha256, size = hash_file(file_path)
    except OSError as exc:
        logger.warning("artifact.hash_failed", filename=file_path.name, error=str(exc))
        return None
    if size == 0:
        #: An empty output file is not evidence of anything and DefectDojo rejects it. The
        #: caller learns the scan produced nothing from ``ScannerResult.produced_output``.
        logger.debug("artifact.empty_skipped", filename=file_path.name)
        return None
    return ArtifactFile(
        kind=kind,
        filename=filename or file_path.name,
        path=file_path,
        size_bytes=size,
        sha256=sha256,
        defectdojo_scan_type=defectdojo_scan_type,
    )


def collect_dir(
    directory: Path,
    *,
    kind: ArtifactKind = ArtifactKind.RAW_OUTPUT,
    patterns: Iterable[str] = ("*",),
    recursive: bool = True,
    limit: int = 200,
) -> tuple[ArtifactFile, ...]:
    """Every usable file under ``directory``.

    Used by the recon adapter, whose output is a directory tree rather than one report file.
    ``limit`` is a guard: ReconFTW's output directory can contain thousands of small files, and
    turning each into a database row and an S3 object would be a denial of service against
    ourselves.
    """
    root = Path(directory)
    if not root.is_dir():
        return ()

    found: list[ArtifactFile] = []
    seen: set[Path] = set()
    for pattern in patterns:
        glob = root.rglob(pattern) if recursive else root.glob(pattern)
        for path in sorted(glob):
            if len(found) >= limit:
                logger.warning("artifact.collect_truncated", directory=str(root), limit=limit)
                return tuple(found)
            if path in seen or not path.is_file() or path.name in _IGNORED_NAMES:
                continue
            seen.add(path)
            #: Flattened relative path, so ``subdomains/subdomains.txt`` and
            #: ``hosts/subdomains.txt`` do not collide on the ``(job_id, filename)`` unique
            #: constraint.
            relative = path.relative_to(root).as_posix().replace("/", "__")
            artifact = describe(path, kind=kind, filename=relative)
            if artifact is not None:
                found.append(artifact)
    return tuple(found)


async def upload_artifacts(
    storage: ObjectStorage,
    *,
    organization_id: UUID | str,
    assessment_id: UUID | str,
    job_id: UUID | str,
    artifacts: Iterable[ArtifactFile],
) -> list[StoredArtifact]:
    """Upload each artifact and return the rows to persist.

    Uploads are sequential. Parallelism here would compete with the scanner containers for the
    worker's bandwidth and, more importantly, would make a partial failure harder to reason
    about: sequential means the returned list is exactly the prefix that succeeded.
    """
    stored: list[StoredArtifact] = []
    for artifact in artifacts:
        if artifact.size_bytes > MAX_ARTIFACT_BYTES:
            logger.warning(
                "artifact.too_large_skipped",
                filename=artifact.filename,
                size_bytes=artifact.size_bytes,
            )
            continue

        key = artifact_key(organization_id, assessment_id, job_id, artifact.kind, artifact.filename)
        content_type = guess_content_type(artifact.filename)
        result: StoredObject = await storage.put_file(
            key,
            artifact.path,
            content_type=content_type,
            organization_id=organization_id,
        )
        if result.sha256 != artifact.sha256:
            #: The bytes changed between hashing and upload. Not expected -- the container is
            #: gone by now -- but recording the *uploaded* hash and flagging the mismatch is
            #: the honest outcome, since the stored object is what a report would cite.
            logger.warning(
                "artifact.hash_mismatch",
                filename=artifact.filename,
                collected=artifact.sha256[:16],
                uploaded=result.sha256[:16],
            )
        stored.append(
            StoredArtifact(
                kind=artifact.kind,
                filename=artifact.filename,
                storage_key=result.storage_key,
                content_type=result.content_type,
                size_bytes=result.size_bytes,
                sha256=result.sha256,
                defectdojo_scan_type=artifact.defectdojo_scan_type,
            )
        )

    logger.info(
        "artifact.upload_complete",
        job_id=str(job_id),
        uploaded=len(stored),
    )
    return stored


def write_stream_artifacts(workdir: Path, *, stdout: str, stderr: str) -> tuple[ArtifactFile, ...]:
    """Persist captured stdout/stderr as files so they can be uploaded like any artifact.

    The tails live on the job row for the UI; the full streams belong in object storage, because
    the answer to "why did this scanner exit 2?" is usually in the last few hundred lines of
    stderr and is worth keeping longer than a log retention window.
    """
    out: list[ArtifactFile] = []
    for name, content, kind in (
        ("stdout.log", stdout, ArtifactKind.STDOUT),
        ("stderr.log", stderr, ArtifactKind.STDERR),
    ):
        if not content.strip():
            continue
        path = Path(workdir) / name
        try:
            path.write_text(content, encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("artifact.stream_write_failed", filename=name, error=str(exc))
            continue
        artifact = describe(path, kind=kind)
        if artifact is not None:
            out.append(artifact)
    return tuple(out)


def purge_workdir(path: Path) -> None:
    """Delete the host workdir. Best-effort, never raises.

    See the module docstring: this runs on every path, including failures. It never raises,
    because a purge failure must not mask the scan result that the caller is in the middle of
    recording -- it is logged at warning so the leftover is visible to an operator.
    """
    target = Path(path)
    if not target.exists():
        return
    try:
        shutil.rmtree(target, ignore_errors=False)
        logger.debug("artifact.workdir_purged", workdir=str(target))
    except OSError as exc:
        logger.warning("artifact.workdir_purge_failed", workdir=str(target), error=str(exc))
        #: Second attempt ignoring errors: on Linux the common cause is a file owned by the
        #: container's uid, and partial removal is better than none.
        shutil.rmtree(target, ignore_errors=True)


__all__ = [
    "MAX_ARTIFACT_BYTES",
    "StoredArtifact",
    "collect_dir",
    "describe",
    "hash_file",
    "purge_workdir",
    "upload_artifacts",
    "write_stream_artifacts",
]
