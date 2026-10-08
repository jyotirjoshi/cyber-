"""Trivy repository/image runs stay within one approved target and sandbox."""

import importlib
import json

import pytest

from app.core.config import ScannerSettings, Settings
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ScannerName
from app.scanners.base import ScannerRequest
from app.scanners.registry import scan_type_for
from app.scanners.sandbox import build_sandbox, validate_argv


def test_trivy_reports_are_importable_by_defectdojo() -> None:
    from app.integrations.defectdojo import scan_type_for as dojo_scan_type

    assert dojo_scan_type(ScannerName.TRIVY_REPO) == "Trivy Scan"
    assert dojo_scan_type(ScannerName.TRIVY_IMAGE) == "Trivy Scan"


def _request(tmp_path, scanner: str, target: str) -> ScannerRequest:
    return ScannerRequest(
        scanner=ScannerName(scanner),
        targets=(target,),
        workdir=tmp_path,
        timeout_seconds=1800,
    )


def test_trivy_repository_scans_staged_source_and_archives_json(tmp_path) -> None:
    trivy = importlib.import_module("app.scanners.trivy")
    adapter = trivy.REPO_ADAPTER
    request = _request(tmp_path, "trivy_repo", "https://github.com/acme/api")
    adapter.validate(request)
    argv = adapter.build_argv(request)
    assert argv == (
        "fs",
        "--format",
        "json",
        "--output",
        "/work/out/trivy.json",
        "--scanners",
        "vuln,misconfig,secret",
        "--cache-dir",
        "/tmp/trivy-cache",
        "/work/src",
    )
    assert validate_argv(argv, scanner="trivy_repo") == argv
    report = request.out_dir / "trivy.json"
    report.parent.mkdir(parents=True)
    report.write_bytes(b'{"Results":[]}')
    artifacts = adapter.collect(request)
    assert len(artifacts) == 1
    assert artifacts[0].defectdojo_scan_type == "Trivy Scan"
    assert scan_type_for(ScannerName.TRIVY_REPO) == "Trivy Scan"
    assert scan_type_for(ScannerName.TRIVY_IMAGE) == "Trivy Scan"
    assert artifacts[0].size_bytes == report.stat().st_size


def test_trivy_report_does_not_archive_secret_values_or_source_snippets(tmp_path) -> None:
    trivy = importlib.import_module("app.scanners.trivy")
    request = _request(tmp_path, "trivy_repo", "https://github.com/acme/api")
    report = request.out_dir / "trivy.json"
    report.parent.mkdir(parents=True)
    secret = "real-secret-must-not-leave-job"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "config.py",
                        "Class": "secret",
                        "Type": "secret",
                        "Secrets": [
                            {
                                "RuleID": "generic-api-key",
                                "Severity": "HIGH",
                                "StartLine": 4,
                                "Title": "Exposed API key",
                                "Match": secret,
                                "Code": {"Lines": [secret]},
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    artifacts = trivy.REPO_ADAPTER.collect(request)

    assert len(artifacts) == 1
    archived = artifacts[0].path.read_text(encoding="utf-8")
    assert secret not in archived
    finding = json.loads(archived)["Results"][0]["Secrets"][0]
    assert finding["RuleID"] == "generic-api-key"
    assert finding["StartLine"] == 4


def test_trivy_image_scans_exact_image_with_nonroot_secret_free_sandbox(tmp_path) -> None:
    trivy = importlib.import_module("app.scanners.trivy")
    adapter = trivy.IMAGE_ADAPTER
    request = _request(tmp_path, "trivy_image", "docker.io/acme/api:1.0")
    adapter.validate(request)
    assert adapter.build_argv(request)[0] == "image"
    assert adapter.build_argv(request)[-1] == "docker.io/acme/api:1.0"
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
    assert not any("TOKEN" in key or "PASSWORD" in key for key in sandbox["environment"])


def test_trivy_rejects_cross_type_or_multiple_targets(tmp_path) -> None:
    trivy = importlib.import_module("app.scanners.trivy")
    repo = trivy.REPO_ADAPTER
    image = trivy.IMAGE_ADAPTER
    with pytest.raises(UnsafeScannerInvocationError):
        repo.validate(_request(tmp_path, "trivy_repo", "https://example.org"))
    with pytest.raises(UnsafeScannerInvocationError):
        image.validate(_request(tmp_path, "trivy_image", "https://github.com/acme/api"))
    with pytest.raises(UnsafeScannerInvocationError):
        repo.validate(
            ScannerRequest(
                scanner=ScannerName("trivy_repo"),
                targets=("https://github.com/acme/api", "https://github.com/acme/web"),
                workdir=tmp_path,
                timeout_seconds=1800,
            )
        )


@pytest.mark.asyncio
async def test_trivy_repository_runs_through_sandbox_and_collects_report(
    tmp_path, monkeypatch
) -> None:
    from app.scanners.runner import DockerRunner

    observed = []

    class _Container:
        id = "trivy-1"
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
            (tmp_path / "out" / "trivy.json").write_bytes(b'{"Results":[]}')
            return _Container()

    async def fake_docker(self):
        return type("Docker", (), {"containers": _Containers()})()

    trivy = importlib.import_module("app.scanners.trivy")
    monkeypatch.setattr(trivy, "stage_repository_snapshot", lambda target, workdir: None)
    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    runner = DockerRunner(Settings())
    result = await runner.run(
        importlib.import_module("app.scanners.trivy").REPO_ADAPTER,
        _request(tmp_path, "trivy_repo", "https://github.com/acme/api"),
    )
    assert result.exit_code == 0
    assert len(result.artifacts) == 1
    assert observed[0]["command"][0] == "fs"
    assert observed[0]["privileged"] is False


@pytest.mark.asyncio
async def test_trivy_scanner_does_not_retain_secret_bearing_container_logs(
    tmp_path, monkeypatch
) -> None:
    from app.scanners.runner import DockerRunner

    secret = "real-secret-must-not-leave-job"

    class _Container:
        id = "trivy-secret-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            pass

        def logs(self, **kwargs):
            return secret.encode()

        def remove(self, **kwargs):
            pass

    class _Containers:
        def run(self, **kwargs):
            (tmp_path / "out" / "trivy.json").write_bytes(b'{"Results":[]}')
            return _Container()

    async def fake_docker(self):
        return type("Docker", (), {"containers": _Containers()})()

    trivy = importlib.import_module("app.scanners.trivy")
    monkeypatch.setattr(trivy, "stage_repository_snapshot", lambda target, workdir: None)
    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(
        importlib.import_module("app.scanners.trivy").REPO_ADAPTER,
        _request(tmp_path, "trivy_repo", "https://github.com/acme/api"),
    )
    assert result.stdout_tail == ""
    assert result.stderr_tail == ""
