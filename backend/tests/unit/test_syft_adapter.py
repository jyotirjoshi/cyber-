"""Syft SBOM generation is scoped to one approved image and kept in the sandbox."""

import importlib

import pytest

from app.core.config import ScannerSettings, Settings
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ScannerName
from app.scanners.base import ScannerRequest
from app.scanners.sandbox import build_sandbox, validate_argv


def _request(tmp_path, target):
    return ScannerRequest(
        scanner=ScannerName("syft_image"),
        targets=(target,),
        workdir=tmp_path,
        timeout_seconds=1800,
    )


def test_syft_generates_cyclonedx_from_only_the_approved_registry_image(tmp_path) -> None:
    from app.agent.nodes.approval import _compatible_scanners_for_target
    from app.agent.nodes.scan import _jobs_for_scope
    from app.integrations.defectdojo import scan_type_for as dojo_scan_type
    from app.scanners.registry import scan_type_for

    adapter = importlib.import_module("app.scanners.syft").ADAPTER
    target = "docker.io/acme/api:1.0"
    request = _request(tmp_path, target)
    adapter.validate(request)
    argv = adapter.build_argv(request)
    assert argv == (
        "scan",
        "registry:docker.io/acme/api:1.0",
        "-o",
        "cyclonedx-json=/work/out/syft.cdx.json",
        "--quiet",
    )
    assert validate_argv(argv, scanner="syft_image") == argv
    assert _jobs_for_scope([target], [ScannerName.SYFT_IMAGE]) == [
        (ScannerName.SYFT_IMAGE, [target]),
    ]
    assert _compatible_scanners_for_target(target, [ScannerName.SYFT_IMAGE]) == [
        ScannerName.SYFT_IMAGE,
    ]
    assert scan_type_for(ScannerName.SYFT_IMAGE) == "CycloneDX Scan"
    assert dojo_scan_type(ScannerName.SYFT_IMAGE) == "CycloneDX Scan"


def test_syft_rejects_non_image_and_multiple_targets(tmp_path) -> None:
    adapter = importlib.import_module("app.scanners.syft").ADAPTER
    with pytest.raises(UnsafeScannerInvocationError):
        adapter.validate(_request(tmp_path, "https://github.com/acme/api"))
    with pytest.raises(UnsafeScannerInvocationError):
        adapter.validate(
            ScannerRequest(
                scanner=ScannerName("syft_image"),
                targets=("docker.io/acme/api:1.0", "docker.io/acme/web:1.0"),
                workdir=tmp_path,
                timeout_seconds=1800,
            )
        )


@pytest.mark.asyncio
async def test_syft_runs_in_sandbox_and_collects_sbom(tmp_path, monkeypatch) -> None:
    from app.scanners.runner import DockerRunner

    adapter = importlib.import_module("app.scanners.syft").ADAPTER
    request = _request(tmp_path, "docker.io/acme/api:1.0")
    settings = ScannerSettings()
    sandbox = build_sandbox(
        settings,
        workdir=tmp_path,
        image=adapter.image(settings),
        read_only_root=adapter.read_only_root,
        work_mount=adapter.work_mount,
        run_as_user=adapter.run_as_user,
        environment=adapter.container_env,
    )
    assert sandbox["user"] != "0"
    assert sandbox["read_only"] is True
    assert not any("TOKEN" in key or "PASSWORD" in key for key in sandbox["environment"])

    observed = []

    class _Container:
        id = "syft-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            return b""

        def remove(self, **kwargs):
            return None

    class _Containers:
        def run(self, **kwargs):
            observed.append(kwargs)
            (tmp_path / "out" / "syft.cdx.json").write_bytes(
                b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'
            )
            return _Container()

    async def fake_docker(self):
        return type("Docker", (), {"containers": _Containers()})()

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(adapter, request)
    assert result.exit_code == 0
    assert len(result.artifacts) == 1
    assert result.artifacts[0].defectdojo_scan_type == "CycloneDX Scan"
    assert observed[0]["privileged"] is False
    assert observed[0]["command"][1] == "registry:docker.io/acme/api:1.0"
