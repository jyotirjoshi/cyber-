"""One-target Trivy repository and image scans using the shared container sandbox."""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType

from app.core.crypto import Secret
from app.core.errors import UnsafeScannerInvocationError
from app.core.targets import TargetType, classify
from app.db.enums import ArtifactKind, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest
from app.scanners.repo_snapshot import stage_repository_snapshot

_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_RESULTS = 20_000
_SECRET_FIELDS = ("RuleID", "Category", "Severity", "StartLine", "EndLine")


def _sanitize_report(report: Path) -> None:
    safe_path = report.with_name("trivy.safe.json")
    try:
        if report.is_symlink() or report.stat().st_size > _MAX_REPORT_BYTES:
            raise ValueError("unsafe Trivy report")
        document = json.loads(report.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("invalid Trivy report")
        results = document.get("Results")
        if not isinstance(results, list) or len(results) > _MAX_RESULTS:
            raise ValueError("invalid Trivy results")
        safe_results = []
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("invalid Trivy result")
            safe = {key: result[key] for key in ("Target", "Class", "Type") if key in result}
            for name in ("Vulnerabilities", "Misconfigurations", "Secrets"):
                if name not in result:
                    continue
                entries = result[name]
                if not isinstance(entries, list) or len(entries) > _MAX_RESULTS:
                    raise ValueError("invalid Trivy findings")
                if name == "Secrets":
                    if not all(isinstance(item, dict) for item in entries):
                        raise ValueError("invalid Trivy secret")
                    safe[name] = [
                        {
                            **{key: item[key] for key in _SECRET_FIELDS if key in item},
                            "Match": "REDACTED",
                        }
                        for item in entries
                    ]
                elif name == "Misconfigurations":
                    if not all(isinstance(item, dict) for item in entries):
                        raise ValueError("invalid Trivy misconfiguration")
                    safe[name] = [
                        {
                            **{key: value for key, value in item.items() if key != "CauseMetadata"},
                            "CauseMetadata": {
                                key: value
                                for key, value in item.get("CauseMetadata", {}).items()
                                if key in {"StartLine", "EndLine", "Resource"}
                            },
                        }
                        for item in entries
                    ]
                else:
                    safe[name] = entries
            safe_results.append(safe)
        sanitized = {
            **{
                key: document[key]
                for key in ("SchemaVersion", "ArtifactName", "ArtifactType")
                if key in document
            },
            "Results": safe_results,
        }
        with safe_path.open("x", encoding="utf-8") as handle:
            json.dump(sanitized, handle, separators=(",", ":"))
        safe_path.replace(report)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        safe_path.unlink(missing_ok=True)
        report.unlink(missing_ok=True)
        raise UnsafeScannerInvocationError(
            "Trivy produced a report that could not be safely imported."
        ) from exc


class _TrivyAdapter(ScannerAdapter):
    image_setting = "image_trivy"
    defectdojo_scan_type = "Trivy Scan"
    entrypoint_is_tool = True
    container_env = MappingProxyType({"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp"})  # noqa: S108 - container-private tmpfs
    capture_logs = False
    requires_output = True

    REPORT_NAME = "trivy.json"
    mode: str
    target_type: TargetType

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if len(request.targets) != 1 or classify(request.targets[0]) is not self.target_type:
            raise UnsafeScannerInvocationError(
                "Trivy requires one approved target of the matching type.",
                context={"scanner": self.name.value, "target_count": len(request.targets)},
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        self.validate(request)
        mode, target = self._mode_and_target(request)
        return (
            mode,
            "--format",
            "json",
            "--output",
            self.container_path("out", self.REPORT_NAME),
            "--scanners",
            "vuln,misconfig,secret",
            "--cache-dir",
            "/tmp/trivy-cache",  # noqa: S108 - container-private tmpfs
            target,
        )

    def _mode_and_target(self, request: ScannerRequest) -> tuple[str, str]:
        return self.mode, request.targets[0]

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        if request.workdir.is_symlink() or request.out_dir.is_symlink():
            raise UnsafeScannerInvocationError("Trivy output directory is not safe to import.")
        report_path = request.out_dir / self.REPORT_NAME
        if not report_path.is_file():
            return ()
        _sanitize_report(report_path)
        report = describe(
            report_path,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        return (report,) if report is not None else ()


class TrivyRepoAdapter(_TrivyAdapter):
    name = ScannerName.TRIVY_REPO
    mode = "repo"
    target_type = TargetType.REPOSITORY

    def prepare(self, request: ScannerRequest) -> None:
        self.validate(request)
        token = request.option("repo_token")
        if token is not None and not isinstance(token, Secret):
            raise UnsafeScannerInvocationError("Repository credential has an invalid type.")
        if request.targets[0].startswith("https://bitbucket.org/"):
            email = request.option("repo_account_email")
            if not isinstance(email, str) or not isinstance(token, Secret):
                raise UnsafeScannerInvocationError("Bitbucket requires a tenant repository credential.")
            stage_repository_snapshot(
                request.targets[0], request.workdir, token, account_email=email
            )
        elif token is None:
            stage_repository_snapshot(request.targets[0], request.workdir)
        else:
            stage_repository_snapshot(request.targets[0], request.workdir, token)

    def _mode_and_target(self, request: ScannerRequest) -> tuple[str, str]:
        return "fs", self.container_path("src")


class TrivyImageAdapter(_TrivyAdapter):
    name = ScannerName.TRIVY_IMAGE
    mode = "image"
    target_type = TargetType.CONTAINER_IMAGE


REPO_ADAPTER = TrivyRepoAdapter()
IMAGE_ADAPTER = TrivyImageAdapter()

__all__ = ["TrivyRepoAdapter", "TrivyImageAdapter", "REPO_ADAPTER", "IMAGE_ADAPTER"]
