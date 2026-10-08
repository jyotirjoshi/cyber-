"""Production scanner execution must apply the sandbox, not merely validate argv."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ScannerName
from app.scanners.base import ScannerAdapter, ScannerRequest


def test_successful_report_scanner_without_report_is_not_completed() -> None:
    from app.db.enums import JobStatus
    from app.scanners.base import ScannerResult
    from app.services.job import _apply_result

    job = SimpleNamespace(timeout_seconds=30)
    result = ScannerResult(
        scanner=ScannerName.TRIVY_REPO,
        exit_code=0,
        duration_seconds=1.0,
        argv=("repo",),
        image="trivy",
        container_id="scan-1",
        sandbox={},
        artifacts=(),
        stdout_tail="",
        stderr_tail="",
    )

    _apply_result(job, result, adapter_success_codes=frozenset({0}), requires_output=True)

    assert job.status == JobStatus.FAILED.value
    assert job.failure_code == "scanner_no_report"


class _Adapter(ScannerAdapter):
    name = ScannerName.NMAP
    image_setting = "image_nmap"

    def build_argv(self, request):
        return ("-sV", "example.com")

    def collect(self, request):
        return ()


@pytest.mark.asyncio
async def test_scanner_uses_isolated_container_with_resource_limits(tmp_path, monkeypatch) -> None:
    from app.scanners.runner import DockerRunner

    created = []
    removed = []

    class _Container:
        id = "container-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            return b""

        def remove(self, **kwargs):
            removed.append(kwargs)

    class _Containers:
        def run(self, **kwargs):
            created.append(kwargs)
            return _Container()

    async def fake_docker(self):
        return type("Docker", (), {"containers": _Containers()})()

    async def forbidden_local_process(*args, **kwargs):
        raise AssertionError("scanner must not run as an unisolated host process")

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker, raising=False)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_local_process)
    settings = Settings()
    runner = DockerRunner(settings)
    request = ScannerRequest(
        scanner=ScannerName.NMAP,
        targets=("example.com",),
        workdir=tmp_path,
        timeout_seconds=30,
    )

    result = await runner.run(_Adapter(), request)

    assert result.exit_code == 0
    assert len(created) == 1
    assert created[0]["privileged"] is False
    assert created[0]["cap_drop"] == ["ALL"]
    assert created[0]["mem_limit"]
    assert created[0]["pids_limit"]
    assert created[0]["network"] == settings.scanner.network
    assert created[0]["image"] == settings.scanner.image_nmap
    assert removed == [{"force": True, "v": True}]


@pytest.mark.asyncio
async def test_credentialed_scanner_never_retains_secret_values_or_logs(
    tmp_path, monkeypatch
) -> None:
    from app.scanners.runner import DockerRunner

    secret = "fake-cloud-secret-123"
    created = []

    class CredentialAdapter(_Adapter):
        credential_environment_names = frozenset({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"})
        capture_logs = False

        def verify_credential_scope(self, request, credentials):
            assert request.targets == ("example.com",)
            assert credentials["AWS_ACCESS_KEY_ID"] == "FAKEACCESS"

    class Container:
        id = "credentialed-container"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            raise AssertionError("credentialed scanner logs must not be captured")

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, **kwargs):
            created.append(kwargs)
            return Container()

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(
        CredentialAdapter(),
        ScannerRequest(
            scanner=ScannerName.NMAP,
            targets=("example.com",),
            workdir=tmp_path,
            timeout_seconds=30,
        ),
        credential_environment={
            "AWS_ACCESS_KEY_ID": "FAKEACCESS",
            "AWS_SECRET_ACCESS_KEY": secret,
        },
    )
    assert created[0]["environment"]["AWS_SECRET_ACCESS_KEY"] == secret
    assert result.exit_code == 0
    assert result.stdout_tail == result.stderr_tail == ""
    assert secret not in str(result)
    assert secret not in str(result.sandbox)
    assert "AWS_SECRET_ACCESS_KEY" in result.sandbox["environment_names"]


@pytest.mark.asyncio
async def test_uncredentialed_scanner_rejects_cloud_secrets(tmp_path) -> None:
    from app.core.errors import UnsafeScannerInvocationError
    from app.scanners.runner import DockerRunner

    with pytest.raises(UnsafeScannerInvocationError):
        await DockerRunner(Settings()).run(
            _Adapter(),
            ScannerRequest(
                scanner=ScannerName.NMAP,
                targets=("example.com",),
                workdir=tmp_path,
                timeout_seconds=30,
            ),
            credential_environment={"AWS_SECRET_ACCESS_KEY": "fake-cloud-secret-123"},
        )


@pytest.mark.asyncio
async def test_credentialed_adapter_must_disable_log_capture(tmp_path) -> None:
    from app.scanners.runner import DockerRunner

    class UnsafeAdapter(_Adapter):
        credential_environment_names = frozenset({"AWS_SECRET_ACCESS_KEY"})

    with pytest.raises(UnsafeScannerInvocationError):
        await DockerRunner(Settings()).run(
            UnsafeAdapter(),
            ScannerRequest(
                scanner=ScannerName.NMAP,
                targets=("example.com",),
                workdir=tmp_path,
                timeout_seconds=30,
            ),
            credential_environment={"AWS_SECRET_ACCESS_KEY": "fake-cloud-secret-123"},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [RuntimeError, UnsafeScannerInvocationError])
async def test_credentialed_container_failure_does_not_expose_secret(
    tmp_path,
    monkeypatch,
    error_type,
) -> None:
    from app.scanners.runner import DockerRunner

    secret = "fake-cloud-secret-123"

    class CredentialAdapter(_Adapter):
        credential_environment_names = frozenset({"AWS_SECRET_ACCESS_KEY"})
        capture_logs = False

        def verify_credential_scope(self, request, credentials):
            assert request.targets == ("example.com",)
            assert credentials["AWS_SECRET_ACCESS_KEY"] == secret

    class Containers:
        def run(self, **kwargs):
            raise error_type(f"Docker rejected request: {secret}")

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    with pytest.raises(Exception) as caught:
        await DockerRunner(Settings()).run(
            CredentialAdapter(),
            ScannerRequest(
                scanner=ScannerName.NMAP,
                targets=("example.com",),
                workdir=tmp_path,
                timeout_seconds=30,
            ),
            credential_environment={"AWS_SECRET_ACCESS_KEY": secret},
        )
    assert secret not in repr(caught.value)
    assert secret not in str(caught.value.__cause__)
    assert secret not in str(caught.value.__context__)


@pytest.mark.asyncio
async def test_scanner_log_collection_streams_and_bounds_large_output() -> None:
    from app.scanners.runner import MAX_LOG_BYTES, DockerRunner

    calls = []

    class _Container:
        def logs(self, **kwargs):
            calls.append(kwargs)
            if kwargs["stdout"]:
                return iter((b"a" * MAX_LOG_BYTES, b"final-out"))
            return iter((b"b" * MAX_LOG_BYTES, b"final-error"))

    runner = DockerRunner(Settings())
    stdout, stderr = await runner._read_logs(_Container())
    assert len(stdout.encode()) <= MAX_LOG_BYTES
    assert len(stderr.encode()) <= MAX_LOG_BYTES
    assert stdout.endswith("final-out")
    assert stderr.endswith("final-error")
    assert len(calls) == 2
    assert all(call["stream"] is True for call in calls)
