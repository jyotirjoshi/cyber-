"""Private repository snapshots keep tenant credentials away from scanner containers."""

from __future__ import annotations

import base64
import io
import tarfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.agent.nodes.approval import _compatible_scanners_for_target
from app.agent.nodes.scan import _jobs_for_scope
from app.core.config import Settings
from app.core.crypto import Secret
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import IntegrationKind, ScannerName
from app.scanners import repo_snapshot
from app.scanners.base import ScannerRequest
from app.scanners.gitleaks import GitleaksRepoAdapter
from app.scanners.semgrep import SemgrepRepoAdapter
from app.scanners.trivy import TrivyRepoAdapter
from app.services import job as job_service


def test_private_github_archive_uses_token_only_for_api_and_accepts_scoped_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.github.com":
            return httpx.Response(
                302,
                headers={
                    "Location": "https://codeload.github.com/acme/service/legacy.tar.gz/main?token=signed"
                },
            )
        return httpx.Response(200, content=b"archive")

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        repo_snapshot.httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )

    assert repo_snapshot._download_archive("acme", "service", Secret("tenant-secret")) == b"archive"
    assert len(seen) == 2
    assert seen[0].headers["authorization"] == "Bearer tenant-secret"
    assert "authorization" not in seen[1].headers


def test_private_github_archive_rejects_redirect_to_other_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"Location": "https://codeload.github.com/other/repo/tar.gz/main"},
        )

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        repo_snapshot.httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    with pytest.raises(UnsafeScannerInvocationError):
        repo_snapshot._download_archive("acme", "service", Secret("tenant-secret"))


@pytest.mark.parametrize(
    ("kind", "target"),
    [
        (IntegrationKind.GITHUB, "https://github.com/acme/service"),
        (IntegrationKind.GITLAB, "https://gitlab.com/acme/service"),
    ],
)
@pytest.mark.parametrize(
    "scanner",
    [ScannerName.SEMGREP_REPO, ScannerName.GITLEAKS_REPO, ScannerName.TRIVY_REPO],
)
@pytest.mark.asyncio
async def test_repository_token_is_resolved_only_from_same_tenant_integration(
    monkeypatch: pytest.MonkeyPatch,
    kind: IntegrationKind,
    target: str,
    scanner: ScannerName,
) -> None:
    tenant = uuid.uuid4()
    other_tenant = uuid.uuid4()
    rows = [
        SimpleNamespace(
            organization_id=other_tenant,
            kind=kind.value,
            is_usable=True,
            config={"organization": "acme"},
        ),
        SimpleNamespace(
            organization_id=tenant,
            kind=kind.value,
            is_usable=True,
            config={"organization": "acme"},
        ),
    ]

    class FakeSession:
        async def execute(self, statement: object) -> SimpleNamespace:
            params = statement.compile().params
            assert tenant in params.values()
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    monkeypatch.setattr(
        job_service,
        "credentials_for",
        lambda integration, **kwargs: {
            "api_token": Secret(
                "other-secret" if integration.organization_id == other_tenant else "tenant-secret"
            )
        },
    )
    job = SimpleNamespace(
        scanner=scanner.value,
        targets=[target],
        organization_id=tenant,
    )
    token = await job_service.repository_token_for_job(FakeSession(), job, Settings())
    assert token is not None
    assert token.reveal() == "tenant-secret"


@pytest.mark.parametrize(
    ("scanner", "adapter"),
    [
        (ScannerName.SEMGREP_REPO, SemgrepRepoAdapter()),
        (ScannerName.GITLEAKS_REPO, GitleaksRepoAdapter()),
    ],
)
def test_source_scanners_use_private_snapshot_without_receiving_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scanner: ScannerName,
    adapter: object,
) -> None:
    archive_data = io.BytesIO()
    with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
        body = b"print('hello')\n"
        item = tarfile.TarInfo("service-main/app.py")
        item.size = len(body)
        archive.addfile(item, io.BytesIO(body))

    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.github.com":
            return httpx.Response(
                302,
                headers={"Location": "https://codeload.github.com/acme/service/tar.gz/main?sig=1"},
            )
        return httpx.Response(200, content=archive_data.getvalue())

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        repo_snapshot.httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    request = ScannerRequest(
        scanner=scanner,
        targets=("https://github.com/acme/service",),
        workdir=tmp_path,
        timeout_seconds=300,
        options={"repo_token": Secret("tenant-secret")},
    )
    adapter.prepare(request)
    assert (tmp_path / "src" / "app.py").read_bytes() == b"print('hello')\n"
    assert "tenant-secret" not in " ".join(adapter.build_argv(request))
    assert seen[0].headers["authorization"] == "Bearer tenant-secret"
    assert "authorization" not in seen[1].headers


@pytest.mark.parametrize(
    ("scanner", "adapter"),
    [
        (ScannerName.SEMGREP_REPO, SemgrepRepoAdapter()),
        (ScannerName.GITLEAKS_REPO, GitleaksRepoAdapter()),
    ],
)
def test_gitlab_source_snapshot_scans_approved_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scanner: ScannerName,
    adapter: object,
) -> None:
    archive_data = io.BytesIO()
    with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
        body = b"SELECT 1;\n"
        item = tarfile.TarInfo("service-main/query.sql")
        item.size = len(body)
        archive.addfile(item, io.BytesIO(body))
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=archive_data.getvalue())

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        repo_snapshot.httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    request = ScannerRequest(
        scanner=scanner,
        targets=("https://gitlab.com/acme/service",),
        workdir=tmp_path,
        timeout_seconds=300,
        options={"repo_token": Secret("tenant-gitlab-token")},
    )
    adapter.prepare(request)
    assert (tmp_path / "src" / "query.sql").read_bytes() == b"SELECT 1;\n"
    assert len(seen) == 1
    assert seen[0].url.host == "gitlab.com"
    assert seen[0].url.raw_path == b"/api/v4/projects/acme%2Fservice/repository/archive.tar.gz"
    assert seen[0].headers["private-token"] == "tenant-gitlab-token"


def test_trivy_scans_tenant_authenticated_source_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive_data = io.BytesIO()
    with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
        body = b"requests==2.0.0\n"
        item = tarfile.TarInfo("service-main/requirements.txt")
        item.size = len(body)
        archive.addfile(item, io.BytesIO(body))
    real_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            302,
            headers={"Location": "https://codeload.github.com/acme/service/tar.gz/main"},
        )
        if request.url.host == "api.github.com"
        else httpx.Response(200, content=archive_data.getvalue())
    )
    monkeypatch.setattr(
        repo_snapshot.httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    request = ScannerRequest(
        scanner=ScannerName.TRIVY_REPO,
        targets=("https://github.com/acme/service",),
        workdir=tmp_path,
        timeout_seconds=300,
        options={"repo_token": Secret("tenant-secret")},
    )
    adapter = TrivyRepoAdapter()
    adapter.prepare(request)
    assert (tmp_path / "src" / "requirements.txt").read_bytes() == b"requests==2.0.0\n"
    argv = adapter.build_argv(request)
    assert argv[0] == "fs"
    assert argv[-1] == "/work/src"
    assert "tenant-secret" not in " ".join(argv)


@pytest.mark.parametrize(
    ("scanner", "adapter"),
    [
        (ScannerName.SEMGREP_REPO, SemgrepRepoAdapter()),
        (ScannerName.GITLEAKS_REPO, GitleaksRepoAdapter()),
        (ScannerName.TRIVY_REPO, TrivyRepoAdapter()),
    ],
)
def test_bitbucket_snapshot_uses_approved_repository_default_branch_and_tenant_auth(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scanner: ScannerName,
    adapter: object,
) -> None:
    archive_data = io.BytesIO()
    with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
        body = b"print('bitbucket')\n"
        item = tarfile.TarInfo("service-main/app.py")
        item.size = len(body)
        archive.addfile(item, io.BytesIO(body))
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.bitbucket.org":
            return httpx.Response(
                200,
                json={
                    "full_name": "acme/service",
                    "scm": "git",
                    "mainbranch": {"name": "main"},
                },
            )
        return httpx.Response(200, content=archive_data.getvalue())

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        repo_snapshot.httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    request = ScannerRequest(
        scanner=scanner,
        targets=("https://bitbucket.org/acme/service",),
        workdir=tmp_path,
        timeout_seconds=300,
        options={
            "repo_token": Secret("tenant-bitbucket-token"),
            "repo_account_email": "operator@example.com",
        },
    )
    adapter.prepare(request)
    assert (tmp_path / "src" / "app.py").read_bytes() == b"print('bitbucket')\n"
    assert [request.url.host for request in seen] == ["api.bitbucket.org", "bitbucket.org"]
    assert seen[1].url.path == "/acme/service/get/main.gz"
    encoded = base64.b64encode(b"operator@example.com:tenant-bitbucket-token").decode()
    assert all(request.headers["authorization"] == f"Basic {encoded}" for request in seen)
    assert "tenant-bitbucket-token" not in " ".join(adapter.build_argv(request))


@pytest.mark.asyncio
async def test_bitbucket_worker_uses_only_exact_tenant_repository_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = uuid.uuid4()
    other_tenant = uuid.uuid4()
    rows = [
        SimpleNamespace(
            organization_id=other_tenant,
            kind="bitbucket",
            is_usable=True,
            config={"workspace": "acme", "repository": "service", "account_email": "other@example.com"},
        ),
        SimpleNamespace(
            organization_id=tenant,
            kind="bitbucket",
            is_usable=True,
            config={"workspace": "acme", "repository": "other", "account_email": "wrong@example.com"},
        ),
        SimpleNamespace(
            organization_id=tenant,
            kind="bitbucket",
            is_usable=True,
            config={"workspace": "acme", "repository": "service", "account_email": "operator@example.com"},
        ),
    ]

    class FakeSession:
        async def execute(self, statement: object) -> SimpleNamespace:
            assert tenant in statement.compile().params.values()
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    monkeypatch.setattr(
        job_service,
        "credentials_for",
        lambda integration, **kwargs: {
            "api_token": Secret(
                "other-secret" if integration.organization_id == other_tenant else "tenant-secret"
            )
        },
    )
    job = SimpleNamespace(
        scanner=ScannerName.TRIVY_REPO.value,
        targets=["https://bitbucket.org/acme/service"],
        organization_id=tenant,
    )
    token, email = await job_service.bitbucket_credentials_for_job(FakeSession(), job, Settings())
    assert token.reveal() == "tenant-secret"
    assert email == "operator@example.com"


def test_bitbucket_source_scanners_are_offered_and_scheduled() -> None:
    target = "https://bitbucket.org/acme/service"
    scanners = [
        ScannerName.SEMGREP_REPO,
        ScannerName.GITLEAKS_REPO,
        ScannerName.TRIVY_REPO,
    ]
    assert _compatible_scanners_for_target(target, scanners) == scanners
    assert _jobs_for_scope([target], scanners) == [
        (scanner, [target]) for scanner in scanners
    ]
