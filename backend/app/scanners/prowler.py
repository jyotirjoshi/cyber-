"""Prowler OCSF output sanitization before scanner artifact upload."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from app.core.cloud_identity import resource_within_account
from app.core.errors import UnsafeScannerInvocationError
from app.core.logging_conf import redact_text
from app.db.enums import ArtifactKind, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest

_MAX_RAW_BYTES = 64 * 1024 * 1024
_MAX_SAFE_BYTES = 10 * 1024 * 1024
_MAX_FINDINGS = 10_000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_REGION = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def _text(value: Any, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("invalid Prowler field")
    return value.strip()


def _safe_finding(
    item: Any,
    *,
    expected_provider: str | None,
    expected_account: str | None,
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("invalid Prowler finding")
    cloud = item.get("cloud")
    info = item.get("finding_info")
    metadata = item.get("metadata")
    resources = item.get("resources")
    if not all(isinstance(value, dict) for value in (cloud, info, metadata)):
        raise ValueError("incomplete Prowler finding")
    if not isinstance(resources, list) or not 1 <= len(resources) <= 20:
        raise ValueError("invalid Prowler resources")
    account = cloud.get("account")
    if not isinstance(account, dict):
        raise ValueError("invalid Prowler account")
    provider = _text(cloud.get("provider"), 16).lower()
    if provider not in {"aws", "azure", "gcp"}:
        raise ValueError("unsupported Prowler provider")
    account_uid = _text(account.get("uid"), 128)
    if not _IDENTIFIER.fullmatch(account_uid):
        raise ValueError("invalid Prowler account")
    if (expected_provider and provider != expected_provider) or (
        expected_account and account_uid.casefold() != expected_account.casefold()
    ):
        raise ValueError("Prowler result is outside the approved account")
    uid = _text(info.get("uid"), 1000)
    title = redact_text(_text(info.get("title"), 1000))
    event_code = _text(metadata.get("event_code"), 200)
    if not _IDENTIFIER.fullmatch(event_code):
        raise ValueError("invalid Prowler check")
    status = item.get("status_code")
    if status not in {"FAIL", "PASS", "MANUAL"}:
        raise ValueError("invalid Prowler status")
    severity = _text(item.get("severity"), 20)
    if severity.lower() not in {"critical", "high", "medium", "low", "info", "informational"}:
        raise ValueError("invalid Prowler severity")
    safe_resources = []
    for resource in resources:
        if not isinstance(resource, dict):
            raise ValueError("invalid Prowler resource")
        resource_uid = _text(resource.get("uid"), 2000)
        if any(char in resource_uid for char in "?#") or redact_text(resource_uid) != resource_uid:
            raise ValueError("unsafe Prowler resource identity")
        if not resource_within_account(provider, account_uid, resource_uid):
            raise ValueError("Prowler resource is outside approved account")
        safe_resources.append({"uid": resource_uid})
    safe_cloud: dict[str, Any] = {"provider": provider, "account": {"uid": account_uid}}
    region = cloud.get("region")
    if isinstance(region, str) and _REGION.fullmatch(region):
        safe_cloud["region"] = region
    return {
        "cloud": safe_cloud,
        "finding_info": {
            "uid": hashlib.sha256(uid.encode("utf-8")).hexdigest(),
            "title": title,
        },
        "metadata": {"event_code": event_code},
        "resources": safe_resources,
        "severity": severity,
        "status_code": status,
    }


def sanitize_ocsf_report(
    report: Path,
    *,
    expected_provider: str | None = None,
    expected_account: str | None = None,
) -> Path:
    """Keep only importer-required fields; never archive raw resource metadata."""
    report = Path(report)
    safe_path = report.with_name("prowler.safe.json")
    failed = False
    try:
        if report.is_symlink() or report.stat().st_size > _MAX_RAW_BYTES:
            raise ValueError("unsafe Prowler report")
        document = json.loads(report.read_text(encoding="utf-8"))
        if not isinstance(document, list) or len(document) > _MAX_FINDINGS:
            raise ValueError("invalid Prowler report")
        safe = [
            _safe_finding(
                item,
                expected_provider=expected_provider,
                expected_account=expected_account,
            )
            for item in document
        ]
        with safe_path.open("x", encoding="utf-8") as handle:
            json.dump(safe, handle, separators=(",", ":"), ensure_ascii=True)
        if safe_path.stat().st_size > _MAX_SAFE_BYTES:
            raise ValueError("Prowler report exceeds safe import limit")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        failed = True
    finally:
        report.unlink(missing_ok=True)
    if failed:
        safe_path.unlink(missing_ok=True)
        raise UnsafeScannerInvocationError(
            "Prowler produced a report that could not be safely imported."
        )
    return safe_path


class ProwlerAwsAdapter(ScannerAdapter):
    name = ScannerName.PROWLER_AWS
    image_setting = "image_prowler"
    container_env = MappingProxyType({"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp"})  # noqa: S108 - container-private tmpfs
    credential_environment_names = frozenset(
        {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        }
    )
    capture_logs = False
    requires_output = True

    def validate(self, request: ScannerRequest) -> None:
        if len(request.targets) != 1 or not re.fullmatch(r"aws:\d{12}", request.targets[0]):
            raise UnsafeScannerInvocationError(
                "Prowler requires one approved AWS account target.",
                context={"scanner": self.name.value},
            )

    def verify_credential_scope(
        self,
        request: ScannerRequest,
        credentials: Mapping[str, str],
    ) -> None:
        self.validate(request)
        access_key = credentials.get("AWS_ACCESS_KEY_ID")
        secret_key = credentials.get("AWS_SECRET_ACCESS_KEY")
        if not access_key or not secret_key:
            raise UnsafeScannerInvocationError("Prowler requires per-run AWS credentials.")
        import boto3
        from botocore.config import Config

        verified = False
        try:
            client = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=credentials.get("AWS_SESSION_TOKEN"),
                region_name="us-east-1",
                config=Config(connect_timeout=5, read_timeout=5, retries={"max_attempts": 0}),
            )
            verified = client.get_caller_identity().get("Account") == request.targets[0][4:]
        except Exception:
            # Cloud SDK errors can echo credentials or account details. Do not chain or log.
            verified = False
        if not verified:
            raise UnsafeScannerInvocationError(
                "AWS credentials could not be verified for the approved account."
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        self.validate(request)
        return (
            "aws",
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            self.container_path("out"),
            "--output-filename",
            "prowler",
            "--no-banner",
            "--ignore-exit-code-3",
        )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        self.validate(request)
        if request.workdir.is_symlink() or request.out_dir.is_symlink():
            raise UnsafeScannerInvocationError("Prowler output directory is unsafe.")
        report = request.out_dir / "prowler.ocsf.json"
        if not report.exists():
            return ()
        safe = sanitize_ocsf_report(
            report,
            expected_provider="aws",
            expected_account=request.targets[0][4:],
        )
        artifact = describe(safe, kind=ArtifactKind.RAW_OUTPUT)
        return (artifact,) if artifact is not None else ()


AWS_ADAPTER = ProwlerAwsAdapter()


class ProwlerAzureAdapter(ScannerAdapter):
    name = ScannerName.PROWLER_AZURE
    image_setting = "image_prowler"
    container_env = MappingProxyType({"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp"})  # noqa: S108 - container-private tmpfs
    credential_environment_names = frozenset(
        {
            "AZURE_CLIENT_ID",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_SECRET",
        }
    )
    capture_logs = False
    requires_output = True

    def validate(self, request: ScannerRequest) -> None:
        if len(request.targets) != 1 or not re.fullmatch(
            r"azure:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
            request.targets[0],
        ):
            raise UnsafeScannerInvocationError("Prowler requires one approved Azure subscription.")

    def verify_credential_scope(
        self,
        request: ScannerRequest,
        credentials: Mapping[str, str],
    ) -> None:
        self.validate(request)
        client_id = credentials.get("AZURE_CLIENT_ID")
        tenant_id = credentials.get("AZURE_TENANT_ID")
        secret = credentials.get("AZURE_CLIENT_SECRET")
        if not all((client_id, tenant_id, secret)) or not all(
            re.fullmatch(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", value)
            for value in (client_id, tenant_id)
        ):
            raise UnsafeScannerInvocationError(
                "Prowler requires Azure service-principal credentials."
            )

        import httpx

        verified = False
        try:
            with httpx.Client(timeout=5, trust_env=False) as client:
                token_response = client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "client_id": client_id,
                        "client_secret": secret,
                        "scope": "https://management.azure.com/.default",
                        "grant_type": "client_credentials",
                    },
                )
                token = (
                    token_response.json().get("access_token")
                    if token_response.status_code == 200
                    else None
                )
                if isinstance(token, str) and token:
                    subscription = request.targets[0][6:]
                    response = client.get(
                        f"https://management.azure.com/subscriptions/{subscription}"
                        "?api-version=2020-01-01",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    verified = (
                        response.status_code == 200
                        and response.json().get("subscriptionId", "").lower() == subscription
                    )
        except Exception:
            verified = False
        if not verified:
            raise UnsafeScannerInvocationError(
                "Azure credentials could not be verified for the approved subscription."
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        self.validate(request)
        return (
            "azure",
            "--sp-env-auth",
            "--subscription-ids",
            request.targets[0][6:],
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            self.container_path("out"),
            "--output-filename",
            "prowler",
            "--no-banner",
            "--ignore-exit-code-3",
        )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        self.validate(request)
        if request.workdir.is_symlink() or request.out_dir.is_symlink():
            raise UnsafeScannerInvocationError("Prowler output directory is unsafe.")
        report = request.out_dir / "prowler.ocsf.json"
        if not report.exists():
            return ()
        safe = sanitize_ocsf_report(
            report,
            expected_provider="azure",
            expected_account=request.targets[0][6:],
        )
        artifact = describe(safe, kind=ArtifactKind.RAW_OUTPUT)
        return (artifact,) if artifact is not None else ()


AZURE_ADAPTER = ProwlerAzureAdapter()


class ProwlerGcpAdapter(ScannerAdapter):
    name = ScannerName.PROWLER_GCP
    image_setting = "image_prowler"
    container_env = MappingProxyType({"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp"})  # noqa: S108 - container-private tmpfs
    credential_environment_names = frozenset(
        {
            "CLOUDSDK_AUTH_ACCESS_TOKEN",
            "GOOGLE_CLOUD_PROJECT",
        }
    )
    capture_logs = False
    requires_output = True

    def validate(self, request: ScannerRequest) -> None:
        if (
            len(request.targets) != 1
            or not re.fullmatch(r"gcp:[a-z][a-z0-9-]{4,28}[a-z0-9]", request.targets[0])
            or request.timeout_seconds > 2400
        ):
            raise UnsafeScannerInvocationError(
                "Prowler requires one approved GCP project and a scan under 40 minutes."
            )

    def verify_credential_scope(
        self,
        request: ScannerRequest,
        credentials: Mapping[str, str],
    ) -> None:
        self.validate(request)
        project = request.targets[0][4:]
        token = credentials.get("CLOUDSDK_AUTH_ACCESS_TOKEN")
        if not token or credentials.get("GOOGLE_CLOUD_PROJECT") != project:
            raise UnsafeScannerInvocationError(
                "Prowler requires a project-scoped GCP access token."
            )

        import httpx

        verified = False
        try:
            with httpx.Client(timeout=5, trust_env=False) as client:
                response = client.get(
                    f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                verified = (
                    response.status_code == 200 and response.json().get("projectId") == project
                )
        except Exception:
            verified = False
        if not verified:
            raise UnsafeScannerInvocationError(
                "GCP credentials could not be verified for the approved project."
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        self.validate(request)
        return (
            "gcp",
            "--project-ids",
            request.targets[0][4:],
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            self.container_path("out"),
            "--output-filename",
            "prowler",
            "--no-banner",
            "--ignore-exit-code-3",
        )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        self.validate(request)
        if request.workdir.is_symlink() or request.out_dir.is_symlink():
            raise UnsafeScannerInvocationError("Prowler output directory is unsafe.")
        report = request.out_dir / "prowler.ocsf.json"
        if not report.exists():
            return ()
        safe = sanitize_ocsf_report(
            report,
            expected_provider="gcp",
            expected_account=request.targets[0][4:],
        )
        artifact = describe(safe, kind=ArtifactKind.RAW_OUTPUT)
        return (artifact,) if artifact is not None else ()


GCP_ADAPTER = ProwlerGcpAdapter()

__all__ = [
    "AWS_ADAPTER",
    "AZURE_ADAPTER",
    "GCP_ADAPTER",
    "ProwlerAwsAdapter",
    "ProwlerAzureAdapter",
    "ProwlerGcpAdapter",
    "sanitize_ocsf_report",
]
