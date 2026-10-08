"""Generate a CycloneDX SBOM for one approved image directly from its registry."""

from __future__ import annotations

from types import MappingProxyType

from app.core.errors import UnsafeScannerInvocationError
from app.core.targets import TargetType, classify
from app.db.enums import ArtifactKind, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest


class SyftImageAdapter(ScannerAdapter):
    name = ScannerName.SYFT_IMAGE
    image_setting = "image_syft"
    defectdojo_scan_type = "CycloneDX Scan"
    requires_output = True
    entrypoint_is_tool = True
    container_env = MappingProxyType({"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp"})  # noqa: S108 - container-private tmpfs

    REPORT_NAME = "syft.cdx.json"

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if (
            len(request.targets) != 1
            or classify(request.targets[0]) is not TargetType.CONTAINER_IMAGE
        ):
            raise UnsafeScannerInvocationError(
                "Syft requires one approved container image.",
                context={"target_count": len(request.targets)},
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        self.validate(request)
        return (
            "scan",
            f"registry:{request.targets[0]}",
            "-o",
            f"cyclonedx-json={self.container_path('out', self.REPORT_NAME)}",
            "--quiet",
        )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        report = describe(
            request.out_dir / self.REPORT_NAME,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        return (report,) if report is not None else ()


ADAPTER = SyftImageAdapter()

__all__ = ["ADAPTER", "SyftImageAdapter"]
