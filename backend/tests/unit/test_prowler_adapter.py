"""Prowler reports must be importable without archiving cloud resource secrets."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.services.file_intake import parse_scan_export


def _finding(secret: str) -> dict:
    return {
        "message": f"DB_PASSWORD={secret}",
        "status_detail": secret,
        "status_code": "FAIL",
        "severity": "Critical",
        "metadata": {"event_code": "ecs_task_definitions_no_environment_secrets"},
        "finding_info": {
            "uid": "prowler-aws-ecs-secret-check-123456789012-eu-west-1-task-1",
            "title": "ECS task definition contains environment secrets",
        },
        "cloud": {
            "provider": "aws",
            "account": {"uid": "123456789012"},
            "region": "eu-west-1",
        },
        "resources": [
            {
                "uid": "arn:aws:ecs:eu-west-1:123456789012:task-definition/api:1",
                "data": {"metadata": {"environment": [{"name": "DB_PASSWORD", "value": secret}]}},
            }
        ],
    }


def test_sanitized_prowler_report_removes_secrets_and_remains_importable(tmp_path) -> None:
    from app.scanners.prowler import sanitize_ocsf_report

    secret = "private-demo-secret-123"
    raw = tmp_path / "prowler.ocsf.json"
    raw.write_text(json.dumps([_finding(secret)]), encoding="utf-8")

    safe_path = sanitize_ocsf_report(raw)

    assert not raw.exists()
    safe = safe_path.read_bytes()
    assert secret.encode() not in safe
    assert b"DB_PASSWORD" not in safe
    assert b'"data"' not in safe
    assert b"status_detail" not in safe
    alerts = parse_scan_export(
        safe,
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
    )
    assert len(alerts) == 1
    assert alerts[0].status == "open"
    assert alerts[0].resource == "arn:aws:ecs:eu-west-1:123456789012:task-definition/api:1"


def test_malformed_prowler_report_is_not_retained(tmp_path) -> None:
    from app.core.errors import UnsafeScannerInvocationError
    from app.scanners.prowler import sanitize_ocsf_report

    raw = tmp_path / "prowler.ocsf.json"
    raw.write_text('{"broken": "document"}', encoding="utf-8")

    with pytest.raises(UnsafeScannerInvocationError):
        sanitize_ocsf_report(raw)
    assert not raw.exists()
    assert not (tmp_path / "prowler.safe.json").exists()


def test_prowler_report_from_another_account_is_rejected(tmp_path) -> None:
    from app.core.errors import UnsafeScannerInvocationError
    from app.scanners.prowler import sanitize_ocsf_report

    raw = tmp_path / "prowler.ocsf.json"
    raw.write_text(json.dumps([_finding("not-relevant")]), encoding="utf-8")
    with pytest.raises(UnsafeScannerInvocationError):
        sanitize_ocsf_report(raw, expected_provider="aws", expected_account="999999999999")
    assert not raw.exists()


@pytest.mark.parametrize(
    "cloud_provider,account,resource",
    [
        ("aws", "123456789012", "arn:aws:iam::999999999999:role/foreign"),
        (
            "gcp",
            "example-project-1",
            "//compute.googleapis.com/projects/other-project-2/zones/us-central1-a/instances/api",
        ),
    ],
)
def test_prowler_sanitizer_rejects_foreign_resource_before_archiving(
    tmp_path,
    cloud_provider: str,
    account: str,
    resource: str,
) -> None:
    from app.core.errors import UnsafeScannerInvocationError
    from app.scanners.prowler import sanitize_ocsf_report

    finding = _finding("not-relevant")
    finding["cloud"]["provider"] = cloud_provider
    finding["cloud"]["account"]["uid"] = account
    finding["resources"][0]["uid"] = resource
    raw = tmp_path / "prowler.ocsf.json"
    raw.write_text(json.dumps([finding]), encoding="utf-8")

    with pytest.raises(UnsafeScannerInvocationError):
        sanitize_ocsf_report(raw, expected_provider=cloud_provider, expected_account=account)
    assert not raw.exists()
    assert not (tmp_path / "prowler.safe.json").exists()


def test_prowler_aws_adapter_collects_only_sanitized_ocsf(tmp_path) -> None:
    from app.core.config import ScannerSettings
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAwsAdapter
    from app.scanners.registry import get_adapter

    request = ScannerRequest(
        scanner=ScannerName.PROWLER_AWS,
        targets=("aws:123456789012",),
        workdir=tmp_path,
        timeout_seconds=120,
    )
    adapter = ProwlerAwsAdapter()
    assert isinstance(get_adapter(ScannerName.PROWLER_AWS), ProwlerAwsAdapter)
    assert adapter.image(ScannerSettings()) in ScannerSettings().allowed_images
    assert adapter.build_argv(request) == (
        "aws",
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        "/work/out",
        "--output-filename",
        "prowler",
        "--no-banner",
        "--ignore-exit-code-3",
    )
    request.out_dir.mkdir()
    raw = request.out_dir / "prowler.ocsf.json"
    secret = "private-demo-secret-123"
    raw.write_text(json.dumps([_finding(secret)]), encoding="utf-8")

    artifacts = adapter.collect(request)

    assert len(artifacts) == 1
    assert artifacts[0].filename == "prowler.safe.json"
    assert secret.encode() not in artifacts[0].path.read_bytes()
    assert not raw.exists()


def test_prowler_azure_adapter_scans_only_approved_subscription(tmp_path) -> None:
    from app.core.config import ScannerSettings
    from app.core.errors import UnsafeScannerInvocationError
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAzureAdapter
    from app.scanners.registry import get_adapter

    subscription = "11111111-1111-1111-1111-111111111111"
    request = ScannerRequest(
        scanner=ScannerName.PROWLER_AZURE,
        targets=(f"azure:{subscription}",),
        workdir=tmp_path,
        timeout_seconds=120,
    )
    adapter = get_adapter(ScannerName.PROWLER_AZURE)
    assert isinstance(adapter, ProwlerAzureAdapter)
    assert adapter.image(ScannerSettings()) in ScannerSettings().allowed_images
    assert adapter.build_argv(request) == (
        "azure",
        "--sp-env-auth",
        "--subscription-ids",
        subscription,
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        "/work/out",
        "--output-filename",
        "prowler",
        "--no-banner",
        "--ignore-exit-code-3",
    )
    with pytest.raises(UnsafeScannerInvocationError):
        adapter.validate(
            ScannerRequest(
                scanner=ScannerName.PROWLER_AZURE,
                targets=("aws:123456789012",),
                workdir=tmp_path,
                timeout_seconds=120,
            )
        )
    request.out_dir.mkdir()
    finding = _finding("private-demo-secret-123")
    finding["cloud"] = {"provider": "azure", "account": {"uid": subscription}}
    finding["resources"] = [{"uid": f"/subscriptions/{subscription}/resourceGroups/demo"}]
    raw = request.out_dir / "prowler.ocsf.json"
    raw.write_text(json.dumps([finding]), encoding="utf-8")
    artifacts = adapter.collect(request)
    assert len(artifacts) == 1
    assert b"private-demo-secret-123" not in artifacts[0].path.read_bytes()


def test_prowler_azure_credentials_must_reach_approved_subscription(tmp_path, monkeypatch) -> None:
    import httpx

    from app.core.errors import UnsafeScannerInvocationError
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAzureAdapter

    request = ScannerRequest(
        scanner=ScannerName.PROWLER_AZURE,
        targets=("azure:11111111-1111-1111-1111-111111111111",),
        workdir=tmp_path,
        timeout_seconds=120,
    )
    secret = "private-demo-secret-123"
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url, *, data):
            calls.append(("post", url, dict(data)))
            return httpx.Response(200, json={"access_token": "short-lived-test-token"})

        def get(self, url, *, headers):
            calls.append(("get", url, dict(headers)))
            return httpx.Response(403, json={"error": {"code": "Forbidden"}})

    monkeypatch.setattr(httpx, "Client", Client)
    with pytest.raises(UnsafeScannerInvocationError) as caught:
        ProwlerAzureAdapter().verify_credential_scope(
            request,
            {
                "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
                "AZURE_TENANT_ID": "33333333-3333-3333-3333-333333333333",
                "AZURE_CLIENT_SECRET": secret,
            },
        )
    assert len(calls) == 2
    assert "11111111-1111-1111-1111-111111111111" in calls[1][1]
    assert secret not in str(caught.value)


def test_prowler_gcp_adapter_scopes_project_and_sanitizes_output(tmp_path) -> None:
    from app.core.errors import UnsafeScannerInvocationError
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerGcpAdapter
    from app.scanners.registry import get_adapter

    project = "example-project-1"
    request = ScannerRequest(
        scanner=ScannerName.PROWLER_GCP,
        targets=(f"gcp:{project}",),
        workdir=tmp_path,
        timeout_seconds=120,
    )
    adapter = get_adapter(ScannerName.PROWLER_GCP)
    assert isinstance(adapter, ProwlerGcpAdapter)
    assert adapter.build_argv(request) == (
        "gcp",
        "--project-ids",
        project,
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        "/work/out",
        "--output-filename",
        "prowler",
        "--no-banner",
        "--ignore-exit-code-3",
    )
    with pytest.raises(UnsafeScannerInvocationError):
        adapter.validate(
            ScannerRequest(
                scanner=ScannerName.PROWLER_GCP,
                targets=("gcp:other-project-2", f"gcp:{project}"),
                workdir=tmp_path,
                timeout_seconds=120,
            )
        )
    with pytest.raises(UnsafeScannerInvocationError):
        adapter.validate(
            ScannerRequest(
                scanner=ScannerName.PROWLER_GCP,
                targets=(f"gcp:{project}",),
                workdir=tmp_path,
                timeout_seconds=2401,
            )
        )
    request.out_dir.mkdir()
    secret = "private-demo-secret-123"
    finding = _finding(secret)
    finding["cloud"] = {"provider": "gcp", "account": {"uid": project}}
    finding["resources"] = [
        {
            "uid": f"//compute.googleapis.com/projects/{project}/zones/us-central1-a/instances/api",
        }
    ]
    (request.out_dir / "prowler.ocsf.json").write_text(json.dumps([finding]), encoding="utf-8")
    artifacts = adapter.collect(request)
    assert len(artifacts) == 1
    assert secret.encode() not in artifacts[0].path.read_bytes()
    alerts = parse_scan_export(
        artifacts[0].path.read_bytes(),
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value=f"gcp:{project}",
    )
    assert len(alerts) == 1
    assert alerts[0].resource.endswith(f"/projects/{project}/zones/us-central1-a/instances/api")


def test_prowler_gcp_token_must_reach_approved_project(tmp_path, monkeypatch) -> None:
    import httpx

    from app.core.errors import UnsafeScannerInvocationError
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerGcpAdapter

    request = ScannerRequest(
        scanner=ScannerName.PROWLER_GCP,
        targets=("gcp:example-project-1",),
        workdir=tmp_path,
        timeout_seconds=120,
    )
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url, *, headers):
            calls.append((url, headers))
            return httpx.Response(200, json={"projectId": "another-project-2"})

    monkeypatch.setattr(httpx, "Client", Client)
    with pytest.raises(UnsafeScannerInvocationError):
        ProwlerGcpAdapter().verify_credential_scope(
            request,
            {
                "CLOUDSDK_AUTH_ACCESS_TOKEN": "temporary-test-token",
                "GOOGLE_CLOUD_PROJECT": "example-project-1",
            },
        )
    assert calls[0][0].endswith("/projects/example-project-1")
    assert calls[0][1]["Authorization"] == "Bearer temporary-test-token"


def test_prowler_aws_credentials_must_match_approved_account(tmp_path, monkeypatch) -> None:
    import boto3

    from app.core.errors import UnsafeScannerInvocationError
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAwsAdapter

    request = ScannerRequest(
        scanner=ScannerName.PROWLER_AWS,
        targets=("aws:123456789012",),
        workdir=tmp_path,
        timeout_seconds=120,
    )
    credentials = {
        "AWS_ACCESS_KEY_ID": "FAKEACCESS",
        "AWS_SECRET_ACCESS_KEY": "private-demo-secret-123",
    }
    calls = []

    class STS:
        def get_caller_identity(self):
            return {"Account": "999999999999"}

    def fake_client(service, **kwargs):
        calls.append((service, kwargs))
        return STS()

    monkeypatch.setattr(boto3, "client", fake_client)
    with pytest.raises(UnsafeScannerInvocationError) as caught:
        ProwlerAwsAdapter().verify_credential_scope(request, credentials)
    assert calls[0][0] == "sts"
    assert calls[0][1]["aws_access_key_id"] == "FAKEACCESS"
    assert "private-demo-secret-123" not in str(caught.value)


@pytest.mark.asyncio
async def test_prowler_wrong_account_never_starts_container(tmp_path, monkeypatch) -> None:
    import boto3

    from app.core.config import Settings
    from app.core.errors import UnsafeScannerInvocationError
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAwsAdapter
    from app.scanners.runner import DockerRunner

    monkeypatch.setattr(
        boto3,
        "client",
        lambda service, **kwargs: SimpleNamespace(
            get_caller_identity=lambda: {"Account": "999999999999"},
        ),
    )

    async def forbidden_docker(self):
        raise AssertionError("Docker must not be contacted for a mismatched account")

    monkeypatch.setattr(DockerRunner, "_docker", forbidden_docker)
    with pytest.raises(UnsafeScannerInvocationError):
        await DockerRunner(Settings()).run(
            ProwlerAwsAdapter(),
            ScannerRequest(
                scanner=ScannerName.PROWLER_AWS,
                targets=("aws:123456789012",),
                workdir=tmp_path,
                timeout_seconds=120,
            ),
            credential_environment={
                "AWS_ACCESS_KEY_ID": "FAKEACCESS",
                "AWS_SECRET_ACCESS_KEY": "private-demo-secret-123",
            },
        )


@pytest.mark.asyncio
async def test_prowler_aws_scan_runs_with_scoped_credentials_and_safe_artifact(
    tmp_path,
    monkeypatch,
) -> None:
    import boto3

    from app.core.config import Settings
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAwsAdapter
    from app.scanners.runner import DockerRunner

    secret = "private-demo-secret-123"
    request = ScannerRequest(
        scanner=ScannerName.PROWLER_AWS,
        targets=("aws:123456789012",),
        workdir=tmp_path,
        timeout_seconds=120,
    )

    class Container:
        id = "prowler-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            raise AssertionError("cloud scan logs must not be captured")

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, **kwargs):
            assert kwargs["environment"]["AWS_SECRET_ACCESS_KEY"] == secret
            assert kwargs["network"] == Settings().scanner.network
            raw = request.out_dir / "prowler.ocsf.json"
            raw.write_text(json.dumps([_finding(secret)]), encoding="utf-8")
            return Container()

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(
        boto3,
        "client",
        lambda service, **kwargs: SimpleNamespace(
            get_caller_identity=lambda: {"Account": "123456789012"},
        ),
    )

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(
        ProwlerAwsAdapter(),
        request,
        credential_environment={
            "AWS_ACCESS_KEY_ID": "FAKEACCESS",
            "AWS_SECRET_ACCESS_KEY": secret,
        },
    )
    assert result.exit_code == 0
    assert len(result.artifacts) == 1
    assert secret not in result.artifacts[0].path.read_text(encoding="utf-8")
    assert secret not in str(result)


@pytest.mark.asyncio
async def test_prowler_azure_scan_runs_with_scoped_credentials_and_safe_artifact(
    tmp_path,
    monkeypatch,
) -> None:
    import httpx

    from app.core.config import Settings
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerAzureAdapter
    from app.scanners.runner import DockerRunner

    subscription = "11111111-1111-1111-1111-111111111111"
    secret = "private-demo-secret-123"
    request = ScannerRequest(
        scanner=ScannerName.PROWLER_AZURE,
        targets=(f"azure:{subscription}",),
        workdir=tmp_path,
        timeout_seconds=120,
    )

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url, *, data):
            assert data["client_secret"] == secret
            return httpx.Response(200, json={"access_token": "short-lived-test-token"})

        def get(self, url, *, headers):
            assert f"/subscriptions/{subscription}" in url
            assert headers["Authorization"] == "Bearer short-lived-test-token"
            return httpx.Response(200, json={"subscriptionId": subscription})

    class Container:
        id = "prowler-azure-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            raise AssertionError("cloud scan logs must not be captured")

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, **kwargs):
            assert kwargs["environment"]["AZURE_CLIENT_SECRET"] == secret
            assert "--subscription-ids" in kwargs["command"]
            assert subscription in kwargs["command"]
            finding = _finding(secret)
            finding["cloud"] = {"provider": "azure", "account": {"uid": subscription}}
            finding["resources"] = [{"uid": f"/subscriptions/{subscription}/resourceGroups/demo"}]
            (request.out_dir / "prowler.ocsf.json").write_text(
                json.dumps([finding]),
                encoding="utf-8",
            )
            return Container()

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(httpx, "Client", Client)
    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(
        ProwlerAzureAdapter(),
        request,
        credential_environment={
            "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
            "AZURE_TENANT_ID": "33333333-3333-3333-3333-333333333333",
            "AZURE_CLIENT_SECRET": secret,
        },
    )
    assert result.exit_code == 0
    assert len(result.artifacts) == 1
    assert secret not in result.artifacts[0].path.read_text(encoding="utf-8")
    assert secret not in str(result)


@pytest.mark.asyncio
async def test_prowler_gcp_scan_runs_with_temporary_token_and_safe_artifact(
    tmp_path,
    monkeypatch,
) -> None:
    import httpx

    from app.core.config import Settings
    from app.db.enums import ScannerName
    from app.scanners.base import ScannerRequest
    from app.scanners.prowler import ProwlerGcpAdapter
    from app.scanners.runner import DockerRunner

    project = "example-project-1"
    token = "temporary-test-token"
    secret = "private-demo-secret-123"
    request = ScannerRequest(
        scanner=ScannerName.PROWLER_GCP,
        targets=(f"gcp:{project}",),
        workdir=tmp_path,
        timeout_seconds=120,
    )

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url, *, headers):
            assert url.endswith(f"/projects/{project}")
            assert headers["Authorization"] == f"Bearer {token}"
            return httpx.Response(200, json={"projectId": project})

    class Container:
        id = "prowler-gcp-1"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            raise AssertionError("cloud scan logs must not be captured")

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, **kwargs):
            assert kwargs["environment"]["CLOUDSDK_AUTH_ACCESS_TOKEN"] == token
            assert "GOOGLE_APPLICATION_CREDENTIALS" not in kwargs["environment"]
            assert "--project-ids" in kwargs["command"]
            assert project in kwargs["command"]
            finding = _finding(secret)
            finding["cloud"] = {"provider": "gcp", "account": {"uid": project}}
            finding["resources"] = [
                {
                    "uid": f"//compute.googleapis.com/projects/{project}/zones/us-central1-a/instances/api",
                }
            ]
            (request.out_dir / "prowler.ocsf.json").write_text(
                json.dumps([finding]),
                encoding="utf-8",
            )
            return Container()

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(httpx, "Client", Client)
    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    result = await DockerRunner(Settings()).run(
        ProwlerGcpAdapter(),
        request,
        credential_environment={
            "CLOUDSDK_AUTH_ACCESS_TOKEN": token,
            "GOOGLE_CLOUD_PROJECT": project,
        },
    )
    assert result.exit_code == 0
    assert len(result.artifacts) == 1
    assert secret not in result.artifacts[0].path.read_text(encoding="utf-8")
    assert token not in str(result)
