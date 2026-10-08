"""Approval cards offer only scanners capable of handling selected assets."""

from app.agent.nodes.approval import _compatible_scanners_for_target
from app.db.enums import ScannerName


def test_repository_approval_offers_trivy_but_not_web_scanners() -> None:
    offered = _compatible_scanners_for_target(
        "https://github.com/acme/api",
        [
            ScannerName.NMAP,
            ScannerName.NUCLEI,
            ScannerName.ZAP,
            ScannerName.TRIVY_REPO,
            ScannerName.TRIVY_IMAGE,
        ],
    )
    assert offered == [ScannerName.TRIVY_REPO]


def test_image_approval_offers_only_image_scanner() -> None:
    offered = _compatible_scanners_for_target(
        "docker.io/acme/api:1.0",
        [ScannerName.NMAP, ScannerName.TRIVY_REPO, ScannerName.TRIVY_IMAGE],
    )
    assert offered == [ScannerName.TRIVY_IMAGE]
