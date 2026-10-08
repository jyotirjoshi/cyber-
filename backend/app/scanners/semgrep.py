"""Run Semgrep SAST on an approved GitHub source snapshot."""

from __future__ import annotations

from types import MappingProxyType

from app.core.crypto import Secret
from app.core.errors import UnsafeScannerInvocationError
from app.core.targets import TargetType, classify
from app.db.enums import ArtifactKind, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest
from app.scanners.repo_snapshot import repository_coordinates, stage_repository_snapshot


class SemgrepRepoAdapter(ScannerAdapter):
    name = ScannerName.SEMGREP_REPO
    image_setting = "image_semgrep"
    defectdojo_scan_type = "SARIF"
    requires_output = True
    container_env = MappingProxyType({"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp"})  # noqa: S108 - container-private tmpfs
    REPORT_NAME = "semgrep.sarif"

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if len(request.targets) != 1 or classify(request.targets[0]) is not TargetType.REPOSITORY:
            raise UnsafeScannerInvocationError("Semgrep requires one approved repository.")
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
            "semgrep",
            "scan",
            "--config",
            "p/default",
            "--metrics=off",
            "--sarif",
            "--output",
            self.container_path("out", self.REPORT_NAME),
            "--quiet",
            "--max-target-bytes",
            "1000000",
            self.container_path("src"),
        )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        report = describe(
            request.out_dir / self.REPORT_NAME,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        return (report,) if report is not None else ()


ADAPTER = SemgrepRepoAdapter()

__all__ = ["ADAPTER", "SemgrepRepoAdapter"]
