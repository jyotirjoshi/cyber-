"""A cloud scanner may only receive its own tenant's account credentials."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ScannerName
from app.services.integration import Secret


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _Session:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return _Result(self.rows)


def _job(org_id, account="123456789012"):
    return SimpleNamespace(
        organization_id=org_id,
        scanner=ScannerName.PROWLER_AWS.value,
        targets=[f"aws:{account}"],
    )


@pytest.mark.asyncio
async def test_prowler_credentials_are_bound_to_tenant_and_account(monkeypatch) -> None:
    from app.services import job as job_service

    tenant = uuid.uuid4()
    other = uuid.uuid4()
    secret = "never-log-me"
    matching = SimpleNamespace(
        organization_id=tenant,
        kind="prowler_aws",
        is_usable=True,
        config={"account_id": "123456789012"},
        credentials=[],
    )
    # Even a malformed/mock query result from another tenant must never be used.
    cross_tenant = SimpleNamespace(
        organization_id=other,
        kind="prowler_aws",
        is_usable=True,
        config={"account_id": "123456789012"},
        credentials=[],
    )
    wrong_account = SimpleNamespace(
        organization_id=tenant,
        kind="prowler_aws",
        is_usable=True,
        config={"account_id": "999999999999"},
        credentials=[],
    )
    session = _Session([cross_tenant, wrong_account, matching])

    def decrypt(integration, *, settings, mark_used=True):
        assert integration is matching
        return {
            "access_key_id": Secret("FAKEACCESS"),
            "secret_access_key": Secret(secret),
        }

    monkeypatch.setattr(job_service, "credentials_for", decrypt, raising=False)
    creds = await job_service.cloud_credentials_for_job(session, _job(tenant), Settings())

    assert creds == {"AWS_ACCESS_KEY_ID": "FAKEACCESS", "AWS_SECRET_ACCESS_KEY": secret}
    compiled = session.statements[0].compile()
    assert tenant in compiled.params.values()
    assert "prowler_aws" in compiled.params.values()
    assert "123456789012" in compiled.params.values()


@pytest.mark.asyncio
async def test_prowler_credentials_require_both_keys_and_never_fall_back(monkeypatch) -> None:
    from app.services import job as job_service

    tenant = uuid.uuid4()
    integration = SimpleNamespace(
        organization_id=tenant,
        kind="prowler_aws",
        is_usable=True,
        config={"account_id": "123456789012"},
        credentials=[],
    )
    monkeypatch.setattr(
        job_service,
        "credentials_for",
        lambda integration, *, settings, mark_used=True: {"access_key_id": Secret("FAKEACCESS")},
        raising=False,
    )
    with pytest.raises(UnsafeScannerInvocationError, match="AWS credentials"):
        await job_service.cloud_credentials_for_job(
            _Session([integration]),
            _job(tenant),
            Settings(),
        )
    with pytest.raises(UnsafeScannerInvocationError, match="AWS credentials"):
        await job_service.cloud_credentials_for_job(_Session([]), _job(tenant), Settings())


@pytest.mark.asyncio
async def test_non_cloud_jobs_never_load_cloud_credentials() -> None:
    from app.services import job as job_service

    session = _Session([])
    job = _job(uuid.uuid4())
    job.scanner = ScannerName.NMAP.value
    assert await job_service.cloud_credentials_for_job(session, job, Settings()) == {}
    assert session.statements == []


def test_prowler_integration_accepts_only_account_scoped_credential_slots() -> None:
    from app.db.enums import IntegrationKind
    from app.services.integration import _spec_for

    spec = _spec_for(IntegrationKind.PROWLER_AWS)
    assert spec.required == ("access_key_id", "secret_access_key")
    assert set(spec.credentials) == {"access_key_id", "secret_access_key", "session_token"}
    assert spec.config == {"account_id": "aws_account_id"}


def test_prowler_azure_credentials_are_tenant_and_subscription_bound(monkeypatch) -> None:
    from app.db.enums import IntegrationKind
    from app.services import job as job_service
    from app.services.integration import _spec_for

    spec = _spec_for(IntegrationKind.PROWLER_AZURE)
    assert spec.required == ("client_id", "tenant_id", "client_secret")
    assert spec.config == {"account_id": "azure_subscription_id"}

    tenant, other = uuid.uuid4(), uuid.uuid4()
    account = "11111111-1111-1111-1111-111111111111"
    matching = SimpleNamespace(
        organization_id=tenant,
        kind="prowler_azure",
        is_usable=True,
        config={"account_id": account},
        credentials=[],
    )
    session = _Session(
        [
            SimpleNamespace(
                organization_id=other,
                kind="prowler_azure",
                is_usable=True,
                config={"account_id": account},
                credentials=[],
            ),
            SimpleNamespace(
                organization_id=tenant,
                kind="prowler_azure",
                is_usable=True,
                config={"account_id": "22222222-2222-2222-2222-222222222222"},
                credentials=[],
            ),
            matching,
        ]
    )

    def decrypt(integration, *, settings, mark_used=True):
        assert integration is matching
        return {
            "client_id": Secret("33333333-3333-3333-3333-333333333333"),
            "tenant_id": Secret("44444444-4444-4444-4444-444444444444"),
            "client_secret": Secret("private-demo-secret-123"),
        }

    monkeypatch.setattr(job_service, "credentials_for", decrypt)
    job = SimpleNamespace(
        organization_id=tenant,
        scanner=ScannerName.PROWLER_AZURE.value,
        targets=[f"azure:{account}"],
    )
    coroutine = job_service.cloud_credentials_for_job(session, job, Settings())
    with pytest.raises(StopIteration) as completed:
        coroutine.send(None)
    assert completed.value.value == {
        "AZURE_CLIENT_ID": "33333333-3333-3333-3333-333333333333",
        "AZURE_TENANT_ID": "44444444-4444-4444-4444-444444444444",
        "AZURE_CLIENT_SECRET": "private-demo-secret-123",
    }
    compiled = session.statements[0].compile()
    assert tenant in compiled.params.values()
    assert account in compiled.params.values()


@pytest.mark.asyncio
async def test_prowler_gcp_job_uses_only_matching_tenant_project_and_passes_short_lived_token(
    monkeypatch,
) -> None:
    from app.db.enums import IntegrationKind
    from app.services import job as job_service
    from app.services.integration import _spec_for

    spec = _spec_for(IntegrationKind.PROWLER_GCP)
    assert spec.required == ("service_account_json",)
    assert spec.config == {"account_id": "gcp_project_id"}
    tenant, other = uuid.uuid4(), uuid.uuid4()
    project = "example-project-1"
    matching = SimpleNamespace(
        organization_id=tenant,
        kind="prowler_gcp",
        is_usable=True,
        config={"account_id": project},
        credentials=[],
    )
    session = _Session(
        [
            SimpleNamespace(
                organization_id=other,
                kind="prowler_gcp",
                is_usable=True,
                config={"account_id": project},
                credentials=[],
            ),
            matching,
        ]
    )
    key = '{"type":"service_account","project_id":"example-project-1"}'

    def decrypt(integration, *, settings, mark_used=True):
        assert integration is matching
        return {"service_account_json": Secret(key)}

    def mint(raw, expected_project):
        assert raw == key
        assert expected_project == project
        return "temporary-test-token"

    monkeypatch.setattr(job_service, "credentials_for", decrypt)
    monkeypatch.setattr(job_service, "mint_gcp_access_token", mint)
    job = SimpleNamespace(
        organization_id=tenant,
        scanner=ScannerName.PROWLER_GCP.value,
        targets=[f"gcp:{project}"],
    )
    credentials = await job_service.cloud_credentials_for_job(session, job, Settings())
    assert credentials == {
        "CLOUDSDK_AUTH_ACCESS_TOKEN": "temporary-test-token",
        "GOOGLE_CLOUD_PROJECT": project,
    }
    assert key not in repr(credentials)
    compiled = session.statements[0].compile()
    assert tenant in compiled.params.values()
    assert project in compiled.params.values()


def test_gcp_token_mint_rejects_key_for_another_project_without_network() -> None:
    from app.services.gcp_credentials import mint_gcp_access_token

    with pytest.raises(UnsafeScannerInvocationError):
        mint_gcp_access_token(
            '{"type":"service_account","project_id":"other-project-2",'
            '"token_uri":"https://oauth2.googleapis.com/token"}',
            "example-project-1",
        )


def test_gcp_token_mint_returns_only_fresh_token_without_exporting_json(monkeypatch) -> None:
    import datetime as dt

    from google.oauth2 import service_account

    from app.services.gcp_credentials import mint_gcp_access_token

    raw_key = "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----\n"
    key = __import__("json").dumps(
        {
            "type": "service_account",
            "project_id": "example-project-1",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_email": "scanner@example-project-1.iam.gserviceaccount.com",
            "private_key": raw_key,
        }
    )

    class Credentials:
        token = None
        expiry = None

        def refresh(self, request):
            self.token = "temporary-test-token"
            self.expiry = dt.datetime.now(dt.UTC).replace(tzinfo=None) + dt.timedelta(minutes=55)

    monkeypatch.setattr(
        service_account.Credentials,
        "from_service_account_info",
        lambda info, scopes: Credentials(),
    )
    token = mint_gcp_access_token(key, "example-project-1")
    assert token == "temporary-test-token"
    assert raw_key not in token


def test_prowler_integration_rejects_invalid_account_identifiers() -> None:
    from app.core.errors import InvalidConfigurationError
    from app.services.integration import validate_aws_account_config

    for value in ("123", "aws:123456789012", "123456789012x", ""):
        with pytest.raises(InvalidConfigurationError):
            validate_aws_account_config({"account_id": value})
    assert validate_aws_account_config({"account_id": "123456789012"}) == "123456789012"


def test_prowler_azure_integration_requires_subscription_uuid() -> None:
    from app.core.errors import InvalidConfigurationError
    from app.services.integration import validate_azure_subscription_config

    for value in ("123", "azure:11111111-1111-1111-1111-111111111111", "", None):
        with pytest.raises(InvalidConfigurationError):
            validate_azure_subscription_config({"account_id": value})
    assert (
        validate_azure_subscription_config(
            {
                "account_id": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
            }
        )
        == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )


def test_prowler_gcp_integration_requires_canonical_project_id() -> None:
    from app.core.errors import InvalidConfigurationError
    from app.services.integration import validate_gcp_project_config

    for value in ("bad", "GCP:example-project-1", "UPPER-PROJECT", "example_project"):
        with pytest.raises(InvalidConfigurationError):
            validate_gcp_project_config({"account_id": value})
    assert (
        validate_gcp_project_config(
            {
                "account_id": "example-project-1",
            }
        )
        == "example-project-1"
    )


@pytest.mark.asyncio
async def test_prowler_integration_probe_verifies_exact_aws_account(monkeypatch) -> None:
    import boto3
    from pydantic import SecretStr

    from app.db.enums import IntegrationKind
    from app.services.integration import _ping

    settings = Settings()
    settings.scanner.aws_account_id = "123456789012"
    settings.scanner.aws_access_key_id = SecretStr("FAKEACCESS")
    settings.scanner.aws_secret_access_key = SecretStr("fake-secret")

    class STS:
        def get_caller_identity(self):
            return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/read-only"}

    def client(service, **kwargs):
        assert service == "sts"
        assert kwargs["aws_access_key_id"] == "FAKEACCESS"
        return STS()

    monkeypatch.setattr(boto3, "client", client)
    assert await _ping(IntegrationKind.PROWLER_AWS, settings, None) is True


@pytest.mark.asyncio
async def test_prowler_gcp_probe_mints_and_verifies_project_token(monkeypatch) -> None:
    from pydantic import SecretStr

    from app.db.enums import IntegrationKind
    from app.services import integration as integration_service

    settings = Settings()
    settings.scanner.gcp_project_id = "example-project-1"
    settings.scanner.gcp_service_account_json = SecretStr("tenant-owned-json")
    seen = []

    def mint(key, project):
        seen.append((key, project))
        return "temporary-test-token"

    def verify(request, credentials):
        seen.append((request.targets, dict(credentials)))

    monkeypatch.setattr(integration_service, "mint_gcp_access_token", mint)
    monkeypatch.setattr(integration_service.GCP_ADAPTER, "verify_credential_scope", verify)
    assert await integration_service._ping(IntegrationKind.PROWLER_GCP, settings, None)
    assert seen == [
        ("tenant-owned-json", "example-project-1"),
        (
            ("gcp:example-project-1",),
            {
                "CLOUDSDK_AUTH_ACCESS_TOKEN": "temporary-test-token",
                "GOOGLE_CLOUD_PROJECT": "example-project-1",
            },
        ),
    ]
