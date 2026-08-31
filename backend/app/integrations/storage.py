"""S3-compatible object storage for scanner artifacts and reports (FR-015).

Raw scanner output does not belong in Postgres.  A single Nuclei run against a large surface
produces megabytes of JSON, ZAP produces more, and the database is the wrong place for blobs
nobody queries -- the ``scanner_artifacts`` row holds the metadata and a ``storage_key``, and
the bytes live here.

Three properties this module is responsible for:

**Keys are tenant-scoped by construction.**  Every key produced by :func:`artifact_key` and
:func:`report_key` begins ``org/{organization_id}/``, and :meth:`ObjectStorage.get_bytes` and
friends take an ``organization_id`` they verify the key against.  A service that has an
attacker-supplied key and the wrong organization gets
:class:`~app.core.errors.TenantIsolationError`, not somebody else's scan output (SEC-003).
The prefix is also what makes an S3 bucket policy per organization possible later without a
data migration.

**boto3 is synchronous, so every call goes through a worker thread.**  ``asyncio.to_thread``
wrapping is not a nicety: a multi-megabyte ``put_object`` on the event loop stalls every
WebSocket the API is holding open, and the agent's whole value is the stream of progress
updates on those sockets.

**Failures are not degradable.**  :class:`~app.core.errors.StorageError` sets
``degradable = False`` deliberately.  If artifacts cannot be stored, the assessment's evidence
chain is broken -- a report citing an artifact that was never written is worse than a failed
assessment, because it looks complete.

One deployment note.  :meth:`presign_get` signs against ``storage.endpoint_url``, which in the
Docker Compose topology is the internal MinIO hostname and is not resolvable from a browser.
The API therefore streams artifacts through :meth:`get_bytes` for the MVP; presigning is here
for deployments pointed at real S3, where the signed host is public.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

from app.core.config import Settings
from app.core.errors import (
    IntegrationNotConfiguredError,
    ResourceNotFoundError,
    StorageError,
    TenantIsolationError,
)
from app.db.enums import ArtifactKind
from app.integrations.http import reveal

#: boto3's client is dynamically generated, so there is no import-time class to annotate
#: against without pulling in stub-only packages at runtime.
S3Client = Any

logger = structlog.get_logger(__name__)

PROVIDER = "Object storage"

#: Object keys are built from scanner filenames, which come from scanner output. Anything
#: outside this set is replaced, which also rules out the ``..`` and leading-``/`` tricks that
#: would let a crafted filename escape its organization prefix.
_KEY_SAFE_RE = re.compile(r"[^A-Za-z0-9._\-/]")

#: S3 permits 1024 bytes; the ``storage_key`` column is ``String(1000)``, so that is the
#: binding limit.
MAX_KEY_LENGTH = 1000

#: Multipart upload threshold. Below this a single ``put_object`` is cheaper; above it boto3's
#: managed transfer splits the upload so one flaky connection does not restart the whole thing.
MULTIPART_THRESHOLD = 8 * 1024 * 1024

_CONTENT_TYPES: dict[str, str] = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".xml": "application/xml",
    ".txt": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".csv": "text/csv",
    ".pdf": "application/pdf",
    ".gz": "application/gzip",
    ".zip": "application/zip",
}


def guess_content_type(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return _CONTENT_TYPES.get(suffix, "application/octet-stream")


def sanitize_segment(value: str) -> str:
    """Make one path segment safe to interpolate into an object key."""
    cleaned = _KEY_SAFE_RE.sub("_", str(value)).replace("/", "_").strip("._")
    return cleaned[:120] or "unnamed"


def tenant_prefix(organization_id: UUID | str) -> str:
    return f"org/{organization_id}/"


def artifact_key(
    organization_id: UUID | str,
    assessment_id: UUID | str,
    job_id: UUID | str,
    kind: ArtifactKind | str,
    filename: str,
) -> str:
    """The canonical key for a scanner artifact.

    ``org/<org>/assessments/<assessment>/jobs/<job>/<kind>/<filename>`` -- hierarchical so an
    operator can browse a bucket by organization then assessment, and so deleting an
    assessment's evidence is a single prefix delete.
    """
    key = (
        f"{tenant_prefix(organization_id)}"
        f"assessments/{assessment_id}/jobs/{job_id}/"
        f"{sanitize_segment(str(kind))}/{sanitize_segment(filename)}"
    )
    return key[:MAX_KEY_LENGTH]


def report_key(
    organization_id: UUID | str,
    assessment_id: UUID | str,
    report_id: UUID | str,
    filename: str,
) -> str:
    key = (
        f"{tenant_prefix(organization_id)}"
        f"assessments/{assessment_id}/reports/{report_id}/{sanitize_segment(filename)}"
    )
    return key[:MAX_KEY_LENGTH]


@dataclass(frozen=True, slots=True)
class StoredObject:
    """What :meth:`ObjectStorage.put_bytes` records.

    The field names match the ``scanner_artifacts`` and ``reports`` columns so the service
    layer can persist it without a translation step.
    """

    storage_key: str
    bucket: str
    size_bytes: int
    sha256: str
    content_type: str
    etag: str | None = None


class ObjectStorage:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cfg = settings.storage
        self._s3: S3Client | None = None
        #: boto3 client construction loads botocore's service-model JSON from disk and is not
        #: reentrant. Clients are thread-safe once built; building them is not.
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self._cfg.configured)

    @property
    def bucket(self) -> str:
        return self._cfg.bucket

    # -- client --------------------------------------------------------------

    def _require(self) -> None:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint=(
                    "Set CYNUX_STORAGE__ACCESS_KEY_ID, CYNUX_STORAGE__SECRET_ACCESS_KEY "
                    "and CYNUX_STORAGE__BUCKET."
                ),
            )

    def _client(self) -> S3Client:
        """Build (once) and return the boto3 S3 client. Call from a worker thread."""
        if self._s3 is not None:
            return self._s3
        with self._lock:
            if self._s3 is not None:
                return self._s3
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:  # pragma: no cover - dependency is pinned
                raise IntegrationNotConfiguredError(
                    PROVIDER, hint="The boto3 package is not installed."
                ) from exc

            self._s3 = boto3.client(
                "s3",
                endpoint_url=self._cfg.endpoint_url,
                region_name=self._cfg.region,
                aws_access_key_id=reveal(self._cfg.access_key_id),
                aws_secret_access_key=reveal(self._cfg.secret_access_key),
                config=Config(
                    #: MinIO does not support virtual-host addressing without wildcard DNS,
                    #: so path style is the default. Real S3 accepts it too.
                    s3={"addressing_style": "path" if self._cfg.force_path_style else "auto"},
                    signature_version="s3v4",
                    retries={"max_attempts": 3, "mode": "standard"},
                    connect_timeout=10,
                    read_timeout=120,
                ),
            )
            logger.info(
                "storage.client_built",
                endpoint=self._cfg.endpoint_url or "aws",
                bucket=self.bucket,
            )
            return self._s3

    def _put_extra(self, content_type: str) -> dict[str, Any]:
        extra: dict[str, Any] = {"ContentType": content_type}
        if self._cfg.sse:
            #: SEC-001 at rest. ``AES256`` is bucket-managed SSE, which MinIO also implements;
            #: ``aws:kms`` would additionally need a key id, so it is not offered here.
            extra["ServerSideEncryption"] = self._cfg.sse
        return extra

    # -- tenant guard --------------------------------------------------------

    def _verify_tenant(self, key: str, organization_id: UUID | str | None) -> None:
        """SEC-003. Refuse a key that is not inside the caller's organization prefix.

        This is a bug guard on the same footing as
        :func:`app.db.tenancy.tenant_select` -- reaching it means a key arrived from
        somewhere other than :func:`artifact_key`, and the safe answer is the one a
        nonexistent object would give.
        """
        if organization_id is None:
            return
        expected = tenant_prefix(organization_id)
        if not key.startswith(expected):
            logger.critical(
                "storage.cross_tenant_access_blocked",
                organization_id=str(organization_id),
                key_prefix=key[:40],
            )
            raise TenantIsolationError(
                "Object key does not belong to the requesting organization.",
                context={"organization_id": str(organization_id)},
            )

    # -- operations ----------------------------------------------------------

    async def ensure_bucket(self) -> None:
        """Create the bucket when it does not exist.

        Idempotent, and tolerant of the two ways a bucket can already be ours:
        ``BucketAlreadyOwnedByYou`` from S3 and ``BucketAlreadyExists`` from MinIO.
        """
        self._require()

        def _op() -> None:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                client.head_bucket(Bucket=self.bucket)
                return
            except ClientError as exc:
                status = _status_of(exc)
                if status not in (403, 404):
                    raise _wrap(exc, operation="head_bucket", key=self.bucket) from exc
                if status == 403:
                    #: The bucket exists and belongs to somebody else, or our credentials
                    #: cannot see it. Creating it will not help and would mask the real cause.
                    raise _wrap(exc, operation="head_bucket", key=self.bucket) from exc
            except BotoCoreError as exc:
                raise _wrap(exc, operation="head_bucket", key=self.bucket) from exc

            params: dict[str, Any] = {"Bucket": self.bucket}
            if self._cfg.region and self._cfg.region != "us-east-1":
                #: ``us-east-1`` must *not* be sent as a location constraint; S3 rejects it.
                params["CreateBucketConfiguration"] = {"LocationConstraint": self._cfg.region}
            try:
                client.create_bucket(**params)
            except ClientError as exc:
                code = _code_of(exc)
                if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                    return
                raise _wrap(exc, operation="create_bucket", key=self.bucket) from exc
            except BotoCoreError as exc:
                raise _wrap(exc, operation="create_bucket", key=self.bucket) from exc

        await asyncio.to_thread(_op)
        logger.info("storage.bucket_ready", bucket=self.bucket)

    async def put_bytes(
        self,
        key: str,
        data: bytes,
        *,
        content_type: str | None = None,
        organization_id: UUID | str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> StoredObject:
        self._require()
        self._verify_tenant(key, organization_id)
        resolved_type = content_type or guess_content_type(key)
        digest = hashlib.sha256(data).hexdigest()

        def _op() -> str | None:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            extra = self._put_extra(resolved_type)
            if metadata:
                #: S3 user metadata must be ASCII header-safe. Scanner-derived values reach
                #: this, so they are sanitized rather than trusted.
                extra["Metadata"] = {
                    sanitize_segment(k): sanitize_segment(v)[:200] for k, v in metadata.items()
                }
            try:
                response = client.put_object(Bucket=self.bucket, Key=key, Body=data, **extra)
            except (BotoCoreError, ClientError) as exc:
                raise _wrap(exc, operation="put_object", key=key) from exc
            etag = response.get("ETag")
            return etag.strip('"') if isinstance(etag, str) else None

        etag = await asyncio.to_thread(_op)
        logger.info(
            "storage.object_stored", key=key, size_bytes=len(data), content_type=resolved_type
        )
        return StoredObject(
            storage_key=key,
            bucket=self.bucket,
            size_bytes=len(data),
            sha256=digest,
            content_type=resolved_type,
            etag=etag,
        )

    async def put_file(
        self,
        key: str,
        path: Path | str,
        *,
        content_type: str | None = None,
        organization_id: UUID | str | None = None,
    ) -> StoredObject:
        """Upload from disk, streaming when the file is large.

        Scanner artifacts arrive as files in the sandbox's output directory. Reading a 200 MB
        ZAP report into memory to hand it to :meth:`put_bytes` would be a needless spike in
        a worker that may be running several scanners at once.
        """
        self._require()
        self._verify_tenant(key, organization_id)
        source = Path(path)
        if not source.is_file():
            raise StorageError(
                "The artifact file to upload does not exist.",
                context={"path": str(source), "key": key},
            )
        resolved_type = content_type or guess_content_type(source.name)
        size = source.stat().st_size

        def _op() -> tuple[str, str | None]:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            digest = hashlib.sha256()
            with source.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)

            extra = self._put_extra(resolved_type)
            try:
                if size >= MULTIPART_THRESHOLD:
                    from boto3.s3.transfer import TransferConfig

                    client.upload_file(
                        Filename=str(source),
                        Bucket=self.bucket,
                        Key=key,
                        ExtraArgs=extra,
                        Config=TransferConfig(multipart_threshold=MULTIPART_THRESHOLD),
                    )
                    #: ``upload_file`` returns nothing, and a multipart ETag is not the
                    #: object's MD5 anyway, so there is no useful ETag to record here. The
                    #: SHA-256 above is the integrity anchor the reports rely on.
                    return digest.hexdigest(), None
                with source.open("rb") as handle:
                    response = client.put_object(Bucket=self.bucket, Key=key, Body=handle, **extra)
            except (BotoCoreError, ClientError) as exc:
                raise _wrap(exc, operation="upload_file", key=key) from exc
            etag = response.get("ETag")
            return digest.hexdigest(), etag.strip('"') if isinstance(etag, str) else None

        sha256, etag = await asyncio.to_thread(_op)
        logger.info("storage.file_stored", key=key, size_bytes=size)
        return StoredObject(
            storage_key=key,
            bucket=self.bucket,
            size_bytes=size,
            sha256=sha256,
            content_type=resolved_type,
            etag=etag,
        )

    async def get_bytes(self, key: str, *, organization_id: UUID | str | None = None) -> bytes:
        """Download an object.

        Raises :class:`~app.core.errors.ResourceNotFoundError` when the object is absent --
        a missing artifact is a 404 to the caller, not a storage outage.
        """
        self._require()
        self._verify_tenant(key, organization_id)

        def _op() -> bytes:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                response = client.get_object(Bucket=self.bucket, Key=key)
                return response["Body"].read()
            except ClientError as exc:
                if _is_missing(exc):
                    raise ResourceNotFoundError(
                        "The requested artifact is not in object storage.",
                        user_message="That artifact is no longer available.",
                        context={"key": key},
                        cause=exc,
                    ) from exc
                raise _wrap(exc, operation="get_object", key=key) from exc
            except BotoCoreError as exc:
                raise _wrap(exc, operation="get_object", key=key) from exc

        return await asyncio.to_thread(_op)

    async def exists(self, key: str, *, organization_id: UUID | str | None = None) -> bool:
        self._require()
        self._verify_tenant(key, organization_id)

        def _op() -> bool:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                client.head_object(Bucket=self.bucket, Key=key)
                return True
            except ClientError as exc:
                if _is_missing(exc):
                    return False
                raise _wrap(exc, operation="head_object", key=key) from exc
            except BotoCoreError as exc:
                raise _wrap(exc, operation="head_object", key=key) from exc

        return await asyncio.to_thread(_op)

    async def presign_get(
        self,
        key: str,
        *,
        ttl_seconds: int | None = None,
        organization_id: UUID | str | None = None,
        download_name: str | None = None,
    ) -> str:
        """A time-limited download URL.

        See the module docstring: only useful when ``endpoint_url`` is reachable by the
        browser. The signature is computed locally, so this makes no network call and cannot
        confirm the object exists.
        """
        self._require()
        self._verify_tenant(key, organization_id)
        ttl = max(60, min(int(ttl_seconds or self._cfg.presign_ttl_seconds), 7 * 24 * 3600))

        def _op() -> str:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            params: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
            if download_name:
                safe = sanitize_segment(download_name)
                params["ResponseContentDisposition"] = f'attachment; filename="{safe}"'
            try:
                return client.generate_presigned_url("get_object", Params=params, ExpiresIn=ttl)
            except (BotoCoreError, ClientError) as exc:
                raise _wrap(exc, operation="presign", key=key) from exc

        url = await asyncio.to_thread(_op)
        logger.debug("storage.presigned", key=key, ttl_seconds=ttl)
        return url

    async def delete(self, key: str, *, organization_id: UUID | str | None = None) -> None:
        self._require()
        self._verify_tenant(key, organization_id)

        def _op() -> None:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                #: S3 ``delete_object`` on a missing key succeeds, which is the behaviour we
                #: want: deletion is idempotent.
                client.delete_object(Bucket=self.bucket, Key=key)
            except (BotoCoreError, ClientError) as exc:
                raise _wrap(exc, operation="delete_object", key=key) from exc

        await asyncio.to_thread(_op)
        logger.info("storage.object_deleted", key=key)

    async def list_keys(
        self,
        prefix: str,
        *,
        organization_id: UUID | str | None = None,
        max_keys: int = 1000,
    ) -> list[str]:
        """Keys under ``prefix``.

        The prefix is tenant-verified, so this cannot be used to enumerate the bucket: an
        empty or foreign prefix is refused rather than answered.
        """
        self._require()
        self._verify_tenant(prefix, organization_id)

        def _op() -> list[str]:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            keys: list[str] = []
            try:
                paginator = client.get_paginator("list_objects_v2")
                for page in paginator.paginate(
                    Bucket=self.bucket,
                    Prefix=prefix,
                    PaginationConfig={"MaxItems": max_keys},
                ):
                    for item in page.get("Contents") or []:
                        key = item.get("Key")
                        if key:
                            keys.append(str(key))
            except (BotoCoreError, ClientError) as exc:
                raise _wrap(exc, operation="list_objects_v2", key=prefix) from exc
            return keys

        return await asyncio.to_thread(_op)

    async def ping(self) -> bool:
        """Confirm the bucket is reachable and the credentials work."""
        self._require()

        def _op() -> bool:
            client = self._client()
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                client.head_bucket(Bucket=self.bucket)
                return True
            except (BotoCoreError, ClientError) as exc:
                raise _wrap(exc, operation="head_bucket", key=self.bucket) from exc

        return await asyncio.to_thread(_op)


# ---------------------------------------------------------------------------
# botocore error translation
# ---------------------------------------------------------------------------

_MISSING_CODES = frozenset({"NoSuchKey", "NoSuchBucket", "404", "NotFound"})

_AUTH_CODES = frozenset(
    {
        "AccessDenied",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
        "ExpiredToken",
        "InvalidToken",
        "AccountProblem",
    }
)


def _code_of(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str((response.get("Error") or {}).get("Code") or "")
    return ""


def _status_of(exc: Exception) -> int:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        meta = response.get("ResponseMetadata") or {}
        try:
            return int(meta.get("HTTPStatusCode") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def _is_missing(exc: Exception) -> bool:
    return _code_of(exc) in _MISSING_CODES or _status_of(exc) == 404


def _wrap(exc: Exception, *, operation: str, key: str) -> StorageError:
    """Turn a botocore exception into a :class:`StorageError`.

    The botocore message can echo the request URL, which for a presigned or path-style
    request carries the access key id in a query parameter. It is deliberately *not*
    interpolated into the error -- only the S3 error code, which names the problem without
    naming the credential (SEC-002).
    """
    code = _code_of(exc) or type(exc).__name__
    status = _status_of(exc)
    context = {"operation": operation, "key": key, "s3_code": code}

    if code in _AUTH_CODES or status == 403:
        message = "Object storage rejected our credentials."
        user_message = (
            "Artifact storage is not accepting Cynux's credentials. "
            "An administrator needs to check the storage configuration."
        )
    elif status == 0:
        message = "Object storage is unreachable."
        user_message = "Artifact storage is unreachable. The assessment cannot store evidence."
    else:
        message = f"Object storage refused a {operation}."
        user_message = "Artifact storage returned an error."

    logger.warning("storage.operation_failed", operation=operation, s3_code=code, status=status)
    return StorageError(
        message,
        user_message=user_message,
        context=context,
        #: Credentials and unreachable endpoints are not fixed by trying again immediately;
        #: a 5xx from the storage service might be.
        retryable=status >= 500,
        cause=exc,
    )


__all__ = [
    "MAX_KEY_LENGTH",
    "MULTIPART_THRESHOLD",
    "PROVIDER",
    "ObjectStorage",
    "StoredObject",
    "artifact_key",
    "guess_content_type",
    "report_key",
    "sanitize_segment",
    "tenant_prefix",
]
