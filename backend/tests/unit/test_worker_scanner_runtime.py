"""Production scanner execution must apply the sandbox, not merely validate argv."""

from __future__ import annotations

import asyncio

import pytest

from app.core.config import Settings
from app.db.enums import ScannerName
from app.scanners.base import ScannerAdapter, ScannerRequest


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
        scanner=ScannerName.NMAP, targets=("example.com",),
        workdir=tmp_path, timeout_seconds=30,
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
