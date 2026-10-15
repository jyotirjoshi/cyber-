"""Approved repository SAST is bounded, sandboxed, and importable."""

from __future__ import annotations

import io
import tarfile

import pytest

from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ScannerName
from app.scanners.base import ScannerRequest


def _request(tmp_path, target="https://github.com/acme/api"):
    return ScannerRequest(
        scanner=ScannerName.SEMGREP_REPO,
        targets=(target,),
        workdir=tmp_path,
        timeout_seconds=1800,
    )


def _archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in entries:
            item = tarfile.TarInfo(name)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
    return output.getvalue()


def test_semgrep_stages_bounded_github_snapshot_and_imports_sarif(tmp_path, monkeypatch):
    from app.scanners import repo_snapshot, semgrep

    archive = _archive([("api-sha/src/app.py", b"print('safe')\n")])
    monkeypatch.setattr(repo_snapshot, "_download_archive", lambda owner, repo: archive)
    request = _request(tmp_path)
    semgrep.ADAPTER.prepare(request)
    assert (tmp_path / "src" / "src" / "app.py").read_bytes() == b"print('safe')\n"
    argv = semgrep.ADAPTER.build_argv(request)
    assert "--metrics=off" in argv
    assert argv[-1] == "/work/src"
    assert "--sarif" in argv
    report = request.out_dir / "semgrep.sarif"
    report.parent.mkdir(parents=True)
    report.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    assert semgrep.ADAPTER.collect(request)[0].defectdojo_scan_type == "SARIF"


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/acme/api",
        "https://github.com/acme/api?token=x",
        "https://github.com/acme/api/extra",
        "https://example.com/app",
    ],
)
def test_semgrep_refuses_unsupported_or_ambiguous_repo(tmp_path, target):
    from app.scanners.semgrep import ADAPTER

    with pytest.raises(UnsafeScannerInvocationError):
        ADAPTER.validate(_request(tmp_path, target))


@pytest.mark.parametrize(
    "name",
    [
        "api-sha/../../escape",
        "/escape",
        "other-sha/a.py",
    ],
)
def test_snapshot_refuses_unsafe_archive_names(tmp_path, monkeypatch, name):
    from app.scanners import repo_snapshot

    archive = _archive([("api-sha/src/ok.py", b"ok"), (name, b"evil")])
    monkeypatch.setattr(repo_snapshot, "_download_archive", lambda owner, repo: archive)
    with pytest.raises(UnsafeScannerInvocationError):
        repo_snapshot.stage_public_github_repo("https://github.com/acme/api", tmp_path)
    assert not (tmp_path.parent / "escape").exists()


def test_snapshot_refuses_oversized_archive(tmp_path, monkeypatch):
    from app.scanners import repo_snapshot

    archive = _archive([("api-sha/big", b"x" * 1024)])
    monkeypatch.setattr(repo_snapshot, "MAX_FILE_BYTES", 100)
    monkeypatch.setattr(repo_snapshot, "_download_archive", lambda owner, repo: archive)
    with pytest.raises(UnsafeScannerInvocationError):
        repo_snapshot.stage_public_github_repo("https://github.com/acme/api", tmp_path)


def test_semgrep_jobs_only_for_supported_approved_repositories():
    from app.agent.nodes.approval import _compatible_scanners_for_target
    from app.agent.nodes.scan import _jobs_for_scope

    github = "https://github.com/acme/api"
    gitlab = "https://gitlab.com/acme/api"
    chosen = [ScannerName.TRIVY_REPO, ScannerName.SEMGREP_REPO]
    assert _compatible_scanners_for_target(github, chosen) == chosen
    assert _compatible_scanners_for_target(gitlab, chosen) == chosen
    assert _jobs_for_scope([github, gitlab], chosen) == [
        (ScannerName.TRIVY_REPO, [github]),
        (ScannerName.TRIVY_REPO, [gitlab]),
        (ScannerName.SEMGREP_REPO, [github]),
        (ScannerName.SEMGREP_REPO, [gitlab]),
    ]


def test_snapshot_refuses_symlink(tmp_path, monkeypatch):
    from app.scanners import repo_snapshot

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        item = tarfile.TarInfo("api-sha/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "../../outside"
        archive.addfile(item)
    monkeypatch.setattr(repo_snapshot, "_download_archive", lambda owner, repo: output.getvalue())
    with pytest.raises(UnsafeScannerInvocationError):
        repo_snapshot.stage_public_github_repo("https://github.com/acme/api", tmp_path)


def test_snapshot_uses_only_github_authorized_archive_redirect(monkeypatch):
    import httpx

    from app.scanners import repo_snapshot

    real_client = httpx.Client
    archive = _archive([("api-sha/app.py", b"pass")])
    seen = []

    def handle(request):
        seen.append(str(request.url))
        if request.url.host == "api.github.com":
            return httpx.Response(
                302, headers={"Location": "https://codeload.github.com/acme/api/legacy.tar.gz/sha"}
            )
        return httpx.Response(200, content=archive)

    transport = httpx.MockTransport(handle)
    monkeypatch.setattr(
        repo_snapshot.httpx, "Client", lambda **kw: real_client(transport=transport, **kw)
    )
    assert repo_snapshot._download_archive("acme", "api") == archive
    assert seen == [
        "https://api.github.com/repos/acme/api/tarball",
        "https://codeload.github.com/acme/api/legacy.tar.gz/sha",
    ]


def test_snapshot_blocks_archive_redirect_outside_approved_host(monkeypatch):
    import httpx

    from app.scanners import repo_snapshot

    real_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"Location": "http://127.0.0.1/metadata"})
    )
    monkeypatch.setattr(
        repo_snapshot.httpx, "Client", lambda **kw: real_client(transport=transport, **kw)
    )
    with pytest.raises(UnsafeScannerInvocationError):
        repo_snapshot._download_archive("acme", "api")


@pytest.mark.asyncio
async def test_semgrep_runs_after_source_staging_in_existing_sandbox(tmp_path, monkeypatch):
    from app.core.config import Settings
    from app.scanners import repo_snapshot, semgrep
    from app.scanners.runner import DockerRunner

    archive = _archive([("api-sha/app.py", b"print('safe')\n")])
    monkeypatch.setattr(repo_snapshot, "_download_archive", lambda owner, repo: archive)
    observed = []

    class Container:
        id = "semgrep-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            pass

        def logs(self, **kwargs):
            return b""

        def remove(self, **kwargs):
            pass

    class Containers:
        def run(self, **kwargs):
            observed.append(kwargs)
            assert (tmp_path / "src" / "app.py").is_file()
            (tmp_path / "out" / "semgrep.sarif").write_text(
                '{"version":"2.1.0","runs":[]}', encoding="utf-8"
            )
            return Container()

    async def fake_docker(self):
        return type("Docker", (), {"containers": Containers()})()

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(semgrep.ADAPTER, _request(tmp_path))
    assert result.succeeded
    assert len(result.importable_artifacts) == 1
    assert observed[0]["command"][:2] == ["semgrep", "scan"]
    assert observed[0]["privileged"] is False
    assert observed[0]["user"] != "0"
