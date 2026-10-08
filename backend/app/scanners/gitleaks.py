"""Secret scan of an approved repository with report sanitization before import."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from app.core.crypto import Secret
from app.core.errors import UnsafeScannerInvocationError
from app.core.targets import TargetType, classify
from app.db.enums import ArtifactKind, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest
from app.scanners.repo_snapshot import repository_coordinates, stage_repository_snapshot

_RULE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_FINDINGS = 50_000


def _safe_path(raw: object) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw) > 512
        or "\\" in raw
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        raise ValueError("invalid finding path")
    if raw.startswith("/work/src/"):
        raw = raw[len("/work/src/") :]
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in raw.split("/")):
        raise ValueError("invalid finding path")
    return str(path)


def _sanitize_report(report: Path) -> None:
    safe_path = report.with_name("gitleaks.safe.json")
    try:
        if report.is_symlink():
            raise ValueError("report is a symlink")
        if report.stat().st_size > _MAX_REPORT_BYTES:
            raise ValueError("report too large")
        rows = json.loads(report.read_text(encoding="utf-8"))
        if rows is None:
            rows = []
        if not isinstance(rows, list) or len(rows) > _MAX_FINDINGS:
            raise ValueError("invalid report shape")
        safe: list[dict[str, object]] = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("invalid finding")
            rule_id = row.get("RuleID")
            line = row.get("StartLine")
            if (
                not isinstance(rule_id, str)
                or not _RULE_ID.fullmatch(rule_id)
                or not isinstance(line, int)
                or isinstance(line, bool)
                or line < 1
                or line > 10_000_000
            ):
                raise ValueError("invalid finding coordinates")
            safe.append(
                {
                    "Description": f"Potential hard-coded secret ({rule_id})",
                    "RuleID": rule_id,
                    "File": _safe_path(row.get("File")),
                    "StartLine": line,
                    "Secret": "REDACTED",
                }
            )
        with safe_path.open("x", encoding="utf-8") as handle:
            json.dump(safe, handle, separators=(",", ":"))
        safe_path.replace(report)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        safe_path.unlink(missing_ok=True)
        report.unlink(missing_ok=True)
        raise UnsafeScannerInvocationError(
            "Gitleaks produced a report that could not be safely imported."
        ) from exc


class GitleaksRepoAdapter(ScannerAdapter):
    name = ScannerName.GITLEAKS_REPO
    image_setting = "image_gitleaks"
    defectdojo_scan_type = "Gitleaks Scan"
    capture_logs = False
    requires_output = True
    REPORT_NAME = "gitleaks.json"

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if len(request.targets) != 1 or classify(request.targets[0]) is not TargetType.REPOSITORY:
            raise UnsafeScannerInvocationError("Gitleaks requires one approved repository.")
        repository_coordinates(request.targets[0])

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
            return
        if token is None:
            stage_repository_snapshot(request.targets[0], request.workdir)
        else:
            stage_repository_snapshot(request.targets[0], request.workdir, token)

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        self.validate(request)
        return (
            "dir",
            "--no-banner",
            "--redact=100",
            "--exit-code=0",
            "--report-format",
            "json",
            "--report-path",
            self.container_path("out", self.REPORT_NAME),
            self.container_path("src"),
        )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        if request.workdir.is_symlink() or request.out_dir.is_symlink():
            raise UnsafeScannerInvocationError("Gitleaks output directory is not safe to import.")
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


ADAPTER = GitleaksRepoAdapter()

__all__ = ["ADAPTER", "GitleaksRepoAdapter"]
