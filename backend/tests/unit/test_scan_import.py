"""Scanner exports must become stable, tenant-safe canonical observations."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest

from app.db.enums import Role
from app.services.canonical_identity import identity_for_observation
from app.services.canonical_ingest import alert_asset_identity
from app.services.context import Principal
from app.services.file_intake import parse_scan_export


def test_sarif_semgrep_result_has_stable_repo_identity_and_safe_evidence() -> None:
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [
                            {
                                "id": "CVE-2024-12345",
                                "properties": {"security-severity": "9.8"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2024-12345",
                        "level": "error",
                        "message": {"text": "Vulnerable dependency"},
                        "partialFingerprints": {"primaryLocationLineHash": "stable-7"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 17},
                                }
                            }
                        ],
                        "properties": {"secret": "must-not-be-retained"},
                    }
                ],
            }
        ],
    }
    payload = json.dumps(document).encode()
    first = parse_scan_export(
        payload,
        format_name="sarif",
        provider="semgrep",
        asset_type="repo",
        asset_value="Acme/API",
    )
    second = parse_scan_export(
        payload,
        format_name="sarif",
        provider="semgrep",
        asset_type="repo",
        asset_value="Acme/API",
    )

    assert len(first) == 1
    alert = first[0]
    assert alert.external_id == second[0].external_id
    assert alert.severity == "critical"
    assert alert.cve_ids == ["CVE-2024-12345"]
    assert alert.evidence["asset_type"] == "repo"
    assert alert.evidence["asset_value"] == "acme/api"
    assert alert.evidence["file"] == "src/app.py"
    assert "must-not-be-retained" not in str(alert.raw_payload)

    persisted = SimpleNamespace(
        provider="semgrep", resource=alert.resource, evidence=alert.evidence
    )
    assert alert_asset_identity(persisted) == ("repo", "acme/api")
    assert identity_for_observation(
        "repo",
        "acme/api",
        alert.cve_ids,
        "semgrep",
        alert.external_id,
    ) == identity_for_observation(
        "repo",
        "acme/api",
        ["CVE-2024-12345"],
        "trivy",
        "other-source",
    )


def test_trivy_export_keeps_package_and_fix_context() -> None:
    document = {
        "ArtifactName": "registry.example/acme/api:1.0",
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-12345",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.0",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "Prototype pollution",
                    }
                ],
            }
        ],
    }
    alerts = parse_scan_export(
        json.dumps(document).encode(),
        format_name="trivy",
        provider="trivy",
        asset_type="container",
        asset_value="registry.example/acme/api:1.0",
    )
    assert len(alerts) == 1
    assert alerts[0].category == "sca"
    assert alerts[0].severity == "high"
    assert alerts[0].evidence["package"] == "lodash"
    assert alerts[0].evidence["fixed_version"] == "4.17.21"


def test_prowler_ocsf_import_scopes_cloud_account_and_drops_resource_secrets() -> None:
    def row(account: str, resource: str, uid: str, status: str) -> dict:
        return {
            "metadata": {"event_code": "s3_bucket_public_access", "product": {"name": "Prowler"}},
            "finding_info": {"uid": uid, "title": "Public bucket"},
            "cloud": {"provider": "aws", "account": {"uid": account}, "region": "us-east-1"},
            "resources": [
                {
                    "uid": resource,
                    "type": "AwsS3Bucket",
                    "data": {
                        "metadata": {"access_key": "secret-never-store"},
                    },
                }
            ],
            "status_code": status,
            "severity": "High",
            "message": "secret-never-store",
        }

    report = [
        row("123456789012", "arn:aws:s3:::customer-a", "finding-a", "FAIL"),
        row("123456789012", "arn:aws:s3:::customer-b", "finding-b", "PASS"),
        row("999999999999", "arn:aws:s3:::other", "finding-c", "FAIL"),
    ]
    first = parse_scan_export(
        json.dumps(report).encode(),
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
    )
    second = parse_scan_export(
        json.dumps(report).encode(),
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
    )
    assert len(first) == 2
    assert [item.external_id for item in first] == [item.external_id for item in second]
    assert [item.status for item in first] == ["open", "fixed"]
    assert first[0].severity == "high"
    assert first[0].resource == "arn:aws:s3:::customer-a"
    assert first[0].evidence["asset_type"] == "cloud"
    assert first[0].evidence["asset_value"] == first[0].resource
    assert first[0].evidence["account_uid"] == "123456789012"
    assert "secret-never-store" not in str(first)
    assert "other" not in str(first)


def test_completed_azure_prowler_job_imports_to_its_canonical_assessment(monkeypatch) -> None:
    from app.db.enums import ArtifactKind, JobStatus, ScannerName
    from app.services import file_intake

    tenant = uuid.uuid4()
    actor = Principal(user_id=uuid.uuid4(), organization_id=tenant, role=Role.SECURITY_ENGINEER)
    subscription = "11111111-1111-1111-1111-111111111111"
    job = SimpleNamespace(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        organization_id=tenant,
        scanner=ScannerName.PROWLER_AZURE.value,
        status=JobStatus.COMPLETED.value,
        targets=[f"azure:{subscription}"],
        artifacts=[
            SimpleNamespace(
                kind=ArtifactKind.RAW_OUTPUT.value,
                filename="prowler.safe.json",
                size_bytes=25,
                storage_key="tenant-safe-key",
            )
        ],
        imported_at=None,
    )
    calls = []

    class Storage:
        async def get_bytes(self, key, *, organization_id):
            calls.append(("storage", key, organization_id))
            return b'[{"safe":true}]'

    async def stage(session, principal, data, **kwargs):
        calls.append(("stage", principal.organization_id, data, kwargs))
        return 1

    monkeypatch.setattr(file_intake, "stage_scan_export", stage)
    coroutine = file_intake.import_prowler_artifact(object(), actor, job, Storage())
    with pytest.raises(StopIteration) as completed:
        coroutine.send(None)

    assert completed.value.value == 1
    assert calls[0] == ("storage", "tenant-safe-key", tenant)
    assert calls[1][3] == {
        "format_name": "prowler_ocsf",
        "provider": "prowler",
        "asset_type": "cloud_account",
        "asset_value": f"azure:{subscription}",
        "assessment_id": job.assessment_id,
        "job_id": job.id,
    }
    assert job.imported_at is not None


@pytest.mark.asyncio
async def test_completed_prowler_job_imports_into_its_own_tenant(monkeypatch) -> None:
    from app.db.enums import ArtifactKind, JobStatus, ScannerName
    from app.services import file_intake

    tenant = uuid.uuid4()
    actor = Principal(user_id=uuid.uuid4(), organization_id=tenant, role=Role.SECURITY_ENGINEER)
    job = SimpleNamespace(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        organization_id=tenant,
        scanner=ScannerName.PROWLER_AWS.value,
        status=JobStatus.COMPLETED.value,
        targets=["aws:123456789012"],
        artifacts=[
            SimpleNamespace(
                kind=ArtifactKind.RAW_OUTPUT.value,
                filename="prowler.safe.json",
                size_bytes=25,
                storage_key="tenant-safe-key",
            )
        ],
        imported_at=None,
    )
    calls = []

    class Storage:
        async def get_bytes(self, key, *, organization_id):
            calls.append(("storage", key, organization_id))
            return b'[{"safe":true}]'

    async def stage(session, principal, data, **kwargs):
        calls.append(("stage", principal.organization_id, data, kwargs))
        return 1

    monkeypatch.setattr(file_intake, "stage_scan_export", stage)
    count = await file_intake.import_prowler_artifact(
        object(),
        actor,
        job,
        Storage(),
    )
    assert count == 1
    assert calls[0] == ("storage", "tenant-safe-key", tenant)
    assert calls[1][0:3] == ("stage", tenant, b'[{"safe":true}]')
    assert calls[1][3] == {
        "format_name": "prowler_ocsf",
        "provider": "prowler",
        "asset_type": "cloud_account",
        "asset_value": "aws:123456789012",
        "assessment_id": job.assessment_id,
        "job_id": job.id,
    }
    assert job.imported_at is not None


@pytest.mark.asyncio
async def test_prowler_import_refuses_cross_tenant_and_raw_output(monkeypatch) -> None:
    from app.core.errors import InvalidConfigurationError, PermissionDeniedError
    from app.db.enums import ArtifactKind, JobStatus, ScannerName
    from app.services import file_intake

    tenant = uuid.uuid4()
    actor = Principal(user_id=uuid.uuid4(), organization_id=tenant, role=Role.SECURITY_ENGINEER)
    job = SimpleNamespace(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scanner=ScannerName.PROWLER_AWS.value,
        status=JobStatus.COMPLETED.value,
        targets=["aws:123456789012"],
        artifacts=[
            SimpleNamespace(
                kind=ArtifactKind.RAW_OUTPUT.value,
                filename="prowler.safe.json",
                size_bytes=25,
                storage_key="unsafe",
            )
        ],
        imported_at=None,
    )

    class NoStorage:
        async def get_bytes(self, *args, **kwargs):
            raise AssertionError("denied job must not read storage")

    with pytest.raises(PermissionDeniedError):
        await file_intake.import_prowler_artifact(object(), actor, job, NoStorage())
    job.organization_id = tenant
    job.artifacts[0].filename = "prowler.ocsf.json"
    with pytest.raises(InvalidConfigurationError):
        await file_intake.import_prowler_artifact(object(), actor, job, NoStorage())


@pytest.mark.asyncio
async def test_prowler_stage_links_observations_to_exact_assessment(monkeypatch) -> None:
    from app.services import external_alert, file_intake

    tenant, assessment, job = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    actor = Principal(user_id=uuid.uuid4(), organization_id=tenant, role=Role.SECURITY_ENGINEER)
    payload = json.dumps(
        [
            {
                "metadata": {"event_code": "s3_public_access"},
                "finding_info": {"uid": "finding-a", "title": "Public bucket"},
                "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
                "resources": [{"uid": "arn:aws:s3:::customer-a"}],
                "status_code": "FAIL",
                "severity": "High",
            }
        ]
    ).encode()
    expected_id = parse_scan_export(
        payload,
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
    )[0].external_id
    links = []

    async def stage(session, *, organization_id, integration_id, provider, alerts):
        assert organization_id == tenant
        return len(alerts)

    async def link(session, **kwargs):
        links.append(kwargs)
        return 1

    async def audit(session, **kwargs):
        return None

    monkeypatch.setattr(external_alert, "_stage_normalized_alerts", stage)
    monkeypatch.setattr(file_intake, "link_scan_observations", link, raising=False)
    monkeypatch.setattr(file_intake.audit_service, "record", audit)
    count = await file_intake.stage_scan_export(
        object(),
        actor,
        payload,
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
        assessment_id=assessment,
        job_id=job,
    )
    assert count == 1
    assert links == [
        {
            "organization_id": tenant,
            "assessment_id": assessment,
            "job_id": job,
            "provider": "prowler",
            "external_ids": [expected_id],
        }
    ]


def test_prowler_ocsf_import_rejects_unscoped_or_malformed_reports() -> None:
    row = {
        "metadata": {"event_code": "s3_bucket_public_access"},
        "finding_info": {"uid": "finding-a", "title": "Public bucket"},
        "cloud": {"provider": "aws", "account": {"uid": "999999999999"}},
        "resources": [{"uid": "arn:aws:s3:::other"}],
        "status_code": "FAIL",
        "severity": "High",
    }
    with pytest.raises(ValueError, match="account-scoped"):
        parse_scan_export(
            json.dumps([row]).encode(),
            format_name="prowler_ocsf",
            provider="prowler",
            asset_type="cloud",
            asset_value="arn:aws:s3:::other",
        )
    with pytest.raises(ValueError, match="selected account"):
        parse_scan_export(
            json.dumps([row]).encode(),
            format_name="prowler_ocsf",
            provider="prowler",
            asset_type="cloud_account",
            asset_value="aws:123456789012",
        )
    with pytest.raises(ValueError, match="invalid status"):
        parse_scan_export(
            json.dumps(
                [
                    {
                        **row,
                        "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
                        "status_code": "UNKNOWN",
                    }
                ]
            ).encode(),
            format_name="prowler_ocsf",
            provider="prowler",
            asset_type="cloud_account",
            asset_value="aws:123456789012",
        )


def test_prowler_ocsf_import_requires_real_azure_subscription_scope() -> None:
    report = [
        {
            "metadata": {"event_code": "storage_public_access"},
            "finding_info": {"uid": "finding-a", "title": "Public storage"},
            "cloud": {"provider": "azure", "account": {"uid": "not-a-subscription"}},
            "resources": [{"uid": "/subscriptions/not-a-subscription/resourceGroups/test"}],
            "status_code": "FAIL",
            "severity": "High",
        }
    ]
    with pytest.raises(ValueError, match="account-scoped"):
        parse_scan_export(
            json.dumps(report).encode(),
            format_name="prowler_ocsf",
            provider="prowler",
            asset_type="cloud_account",
            asset_value="azure:not-a-subscription",
        )


def test_prowler_ocsf_import_rejects_cross_subscription_resource() -> None:
    selected = "11111111-1111-1111-1111-111111111111"
    other = "22222222-2222-2222-2222-222222222222"
    report = [
        {
            "metadata": {"event_code": "storage_public_access"},
            "finding_info": {"uid": "finding-a", "title": "Public storage"},
            "cloud": {"provider": "azure", "account": {"uid": selected}},
            "resources": [{"uid": f"/subscriptions/{other}/resourceGroups/test"}],
            "status_code": "FAIL",
            "severity": "High",
        }
    ]
    with pytest.raises(ValueError, match="outside selected account"):
        parse_scan_export(
            json.dumps(report).encode(),
            format_name="prowler_ocsf",
            provider="prowler",
            asset_type="cloud_account",
            asset_value=f"azure:{selected}",
        )


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
def test_prowler_ocsf_import_rejects_explicit_foreign_cloud_resource(
    cloud_provider: str,
    account: str,
    resource: str,
) -> None:
    report = [
        {
            "metadata": {"event_code": "cloud_resource_check"},
            "finding_info": {"uid": "finding-a", "title": "Cloud issue"},
            "cloud": {"provider": cloud_provider, "account": {"uid": account}},
            "resources": [{"uid": resource}],
            "status_code": "FAIL",
            "severity": "High",
        }
    ]
    with pytest.raises(ValueError, match="outside selected account"):
        parse_scan_export(
            json.dumps(report).encode(),
            format_name="prowler_ocsf",
            provider="prowler",
            asset_type="cloud_account",
            asset_value=f"{cloud_provider}:{account}",
        )


@pytest.mark.parametrize(
    "cloud_provider,account,resource",
    [
        (
            "azure",
            "11111111-1111-1111-1111-111111111111",
            "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test",
        ),
        ("gcp", "example-project-1", "//storage.googleapis.com/projects/_/buckets/example"),
    ],
)
def test_prowler_ocsf_import_maps_azure_and_gcp_resource_assets(
    cloud_provider: str,
    account: str,
    resource: str,
) -> None:
    report = [
        {
            "metadata": {"event_code": "storage_public_access"},
            "finding_info": {"uid": "finding-a", "title": "Public storage"},
            "cloud": {"provider": cloud_provider, "account": {"uid": account}},
            "resources": [{"uid": resource}],
            "status_code": "FAIL",
            "severity": "Medium",
        }
    ]
    alerts = parse_scan_export(
        json.dumps(report).encode(),
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value=f"{cloud_provider}:{account}",
    )
    assert len(alerts) == 1
    assert alerts[0].resource == resource
    assert alerts[0].evidence["asset_value"] == resource
    assert alerts[0].evidence["cloud_provider"] == cloud_provider
    assert alerts[0].status == "open"


def test_rapid7_csv_import_scopes_asset_and_distinguishes_positive_from_negative_checks() -> None:
    headers = (
        "Asset IP Address,Vulnerability ID,Vulnerability Title,Vulnerability Test Result Code,"
        "Vulnerability Severity Level,Vulnerability CVSSv3 Score,Vulnerability CVE IDs,"
        "Service Port,Service Protocol,Vulnerability Proof\n"
    )
    rows = (
        "192.0.2.10,openssl-1,OpenSSL flaw,ve,9,9.8,CVE-2024-12345,443,tcp,secret-never-store\n"
        "192.0.2.10,openssl-2,Old issue,nv,8,8.0,CVE-2024-54321,443,tcp,\n"
        "192.0.2.10,openssl-3,Excluded,ee,9,9.0,CVE-2024-99999,443,tcp,\n"
        "192.0.2.11,other-1,Other host,vv,10,10.0,CVE-2024-88888,443,tcp,\n"
    )
    payload = (headers + rows).encode()

    first = parse_scan_export(
        payload,
        format_name="rapid7_csv",
        provider="rapid7",
        asset_type="ip",
        asset_value="192.0.2.10",
    )
    second = parse_scan_export(
        payload,
        format_name="rapid7_csv",
        provider="rapid7",
        asset_type="ip",
        asset_value="192.0.2.10",
    )

    assert len(first) == 2
    assert first[0].external_id == second[0].external_id
    assert first[0].status == "open"
    assert first[0].severity == "critical"
    assert first[0].cve_ids == ["CVE-2024-12345"]
    assert first[0].evidence == {
        "asset_type": "ip",
        "asset_value": "192.0.2.10",
        "vulnerability_id": "openssl-1",
        "port": 443,
        "protocol": "tcp",
        "result_code": "ve",
    }
    assert first[1].status == "fixed"
    assert "secret-never-store" not in str(first)
    assert "other-1" not in str(first)


def test_rapid7_csv_rejects_unmatched_asset_and_malformed_rows() -> None:
    headers = (
        "Asset IP Address,Vulnerability ID,Vulnerability Title,Vulnerability Test Result Code\n"
    )
    row = "192.0.2.11,openssl-1,OpenSSL flaw,vv\n"
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            (headers + row).encode(),
            format_name="rapid7_csv",
            provider="rapid7",
            asset_type="ip",
            asset_value="192.0.2.10",
        )
    with pytest.raises(ValueError, match="valid CSV"):
        parse_scan_export(
            (headers + '192.0.2.10,openssl-1,"unfinished,vv\n').encode(),
            format_name="rapid7_csv",
            provider="rapid7",
            asset_type="ip",
            asset_value="192.0.2.10",
        )


def test_aws_inspector_csv_scopes_account_and_resource_without_retaining_description() -> None:
    header = (
        "AWS Account Id,Resource ID,Finding ARN,Title,Severity,Status,"
        "Vulnerability Id,Inspector Score,Exploit Available,Description\n"
    )
    rows = (
        "123456789012,i-0abc,arn:aws:inspector2:us-east-1:123456789012:finding/a1,"
        "OpenSSL flaw,HIGH,ACTIVE,CVE-2024-12345,8.7,YES,secret-never-store\n"
        "123456789012,i-0abc,arn:aws:inspector2:us-east-1:123456789012:finding/a2,"
        "Old flaw,MEDIUM,CLOSED,CVE-2024-54321,5.0,NO,\n"
        "999999999999,i-0abc,arn:aws:inspector2:us-east-1:999999999999:finding/b1,"
        "Other account,CRITICAL,ACTIVE,CVE-2024-99999,9.9,YES,\n"
    )
    payload = (header + rows).encode()
    first = parse_scan_export(
        payload,
        format_name="aws_inspector_csv",
        provider="aws_inspector",
        asset_type="cloud",
        asset_value="123456789012:i-0abc",
    )
    second = parse_scan_export(
        payload,
        format_name="aws_inspector_csv",
        provider="aws_inspector",
        asset_type="cloud",
        asset_value="123456789012:i-0abc",
    )
    assert len(first) == 2
    assert first[0].external_id == second[0].external_id
    assert first[0].status == "open"
    assert first[0].severity == "high"
    assert first[0].cve_ids == ["CVE-2024-12345"]
    assert first[0].evidence["exploit_available"] is True
    assert first[1].status == "fixed"
    assert "secret-never-store" not in str(first)
    assert "Other account" not in str(first)


def test_aws_inspector_csv_requires_account_scoped_asset_and_matching_rows() -> None:
    payload = (
        b"AWS Account Id,Resource ID,Finding ARN,Title,Severity,Status\n"
        b"999999999999,i-0abc,arn:aws:inspector2:us-east-1:999999999999:finding/a1,"
        b"Other account,HIGH,ACTIVE\n"
    )
    with pytest.raises(ValueError, match="account-qualified"):
        parse_scan_export(
            payload,
            format_name="aws_inspector_csv",
            provider="aws_inspector",
            asset_type="cloud",
            asset_value="i-0abc",
        )
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            payload,
            format_name="aws_inspector_csv",
            provider="aws_inspector",
            asset_type="cloud",
            asset_value="123456789012:i-0abc",
        )


def test_gcp_scc_response_imports_only_selected_cloud_resource_and_safe_fields() -> None:
    resource = "//compute.googleapis.com/projects/acme/zones/us-central1-a/instances/123"
    payload = json.dumps(
        {
            "listFindingsResults": [
                {
                    "finding": {
                        "name": "organizations/42/sources/7/findings/f-1",
                        "resourceName": resource,
                        "category": "OPEN_FIREWALL",
                        "severity": "HIGH",
                        "state": "ACTIVE",
                        "sourceProperties": {"secret": "must-not-store"},
                        "vulnerability": {
                            "cve": {"id": "CVE-2024-12345", "observedInTheWild": True}
                        },
                    }
                },
                {
                    "finding": {
                        "name": "organizations/42/sources/7/findings/f-2",
                        "resourceName": resource,
                        "category": "OLD_RULE",
                        "severity": "LOW",
                        "state": "INACTIVE",
                    }
                },
                {
                    "finding": {
                        "name": "organizations/42/sources/7/findings/f-3",
                        "resourceName": "//compute.googleapis.com/projects/other/zones/us-central1-a/instances/999",
                        "category": "OTHER",
                        "severity": "CRITICAL",
                        "state": "ACTIVE",
                    }
                },
            ]
        }
    ).encode()
    first = parse_scan_export(
        payload,
        format_name="gcp_scc_json",
        provider="gcp_scc",
        asset_type="cloud",
        asset_value=resource,
    )
    second = parse_scan_export(
        payload,
        format_name="gcp_scc_json",
        provider="gcp_scc",
        asset_type="cloud",
        asset_value=resource,
    )
    assert len(first) == 2
    assert first[0].external_id == second[0].external_id
    assert first[0].status == "open"
    assert first[0].severity == "high"
    assert first[0].cve_ids == ["CVE-2024-12345"]
    assert first[0].evidence["observed_in_the_wild"] is True
    assert first[1].status == "fixed"
    assert "must-not-store" not in str(first)
    assert "OTHER" not in str(first)


def test_gcp_scc_rejects_incomplete_page_and_unmatched_resource() -> None:
    resource = "//compute.googleapis.com/projects/acme/zones/us-central1-a/instances/123"
    finding = {
        "finding": {
            "name": "organizations/42/sources/7/findings/f-1",
            "resourceName": "//compute.googleapis.com/projects/other/instances/999",
            "category": "OPEN_FIREWALL",
            "severity": "HIGH",
            "state": "ACTIVE",
        }
    }
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            json.dumps({"listFindingsResults": [finding]}).encode(),
            format_name="gcp_scc_json",
            provider="gcp_scc",
            asset_type="cloud",
            asset_value=resource,
        )
    with pytest.raises(ValueError, match="incomplete"):
        parse_scan_export(
            json.dumps({"listFindingsResults": [finding], "nextPageToken": "more"}).encode(),
            format_name="gcp_scc_json",
            provider="gcp_scc",
            asset_type="cloud",
            asset_value=resource,
        )


def test_azure_defender_assessments_scope_resource_and_strip_untrusted_details() -> None:
    resource = (
        "/subscriptions/20ff7fc3-e762-44dd-bd96-b71116dcdc23/"
        "resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/api-1"
    )
    assessment_root = f"{resource}/providers/Microsoft.Security/assessments"
    payload = json.dumps(
        {
            "value": [
                {
                    "id": f"{assessment_root}/endpoint-protection",
                    "name": "endpoint-protection",
                    "properties": {
                        "resourceDetails": {"source": "Azure", "id": resource.upper()},
                        "displayName": "Install endpoint protection",
                        "status": {"code": "Unhealthy"},
                        "metadata": {
                            "severity": "High",
                            "partnerData": {"secret": "must-not-store"},
                        },
                        "additionalData": {"credential": "must-not-store"},
                    },
                },
                {
                    "id": f"{assessment_root}/resolved",
                    "name": "resolved",
                    "properties": {
                        "resourceDetails": {"source": "Azure", "id": resource},
                        "displayName": "Turn off public access",
                        "status": {"code": "Healthy"},
                        "metadata": {"severity": "Medium"},
                    },
                },
                {
                    "id": f"{assessment_root}/disabled",
                    "name": "disabled",
                    "properties": {
                        "resourceDetails": {"source": "Azure", "id": resource},
                        "displayName": "Disabled policy",
                        "status": {"code": "NotApplicable"},
                    },
                },
                {
                    "id": "/subscriptions/other/providers/Microsoft.Security/assessments/foreign",
                    "name": "foreign",
                    "properties": {
                        "resourceDetails": {"source": "Azure", "id": "/subscriptions/other"},
                        "displayName": "Foreign issue",
                        "status": {"code": "Unhealthy"},
                        "metadata": {"severity": "High"},
                    },
                },
            ]
        }
    ).encode()
    first = parse_scan_export(
        payload,
        format_name="azure_defender_json",
        provider="azure_defender",
        asset_type="cloud",
        asset_value=resource,
    )
    second = parse_scan_export(
        payload,
        format_name="azure_defender_json",
        provider="azure_defender",
        asset_type="cloud",
        asset_value=resource,
    )
    assert len(first) == 2
    assert first[0].external_id == second[0].external_id
    assert first[0].status == "open"
    assert first[0].severity == "high"
    assert first[0].resource == resource
    assert first[1].status == "fixed"
    assert "must-not-store" not in str(first)
    assert "Foreign issue" not in str(first)


def test_azure_defender_rejects_incomplete_or_unmatched_export() -> None:
    resource = (
        "/subscriptions/20ff7fc3-e762-44dd-bd96-b71116dcdc23/"
        "resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/api-1"
    )
    finding = {
        "id": "/subscriptions/other/providers/Microsoft.Security/assessments/other",
        "name": "other",
        "properties": {
            "resourceDetails": {"source": "Azure", "id": "/subscriptions/other"},
            "displayName": "Other",
            "status": {"code": "Unhealthy"},
        },
    }
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            json.dumps({"value": [finding]}).encode(),
            format_name="azure_defender_json",
            provider="azure_defender",
            asset_type="cloud",
            asset_value=resource,
        )
    with pytest.raises(ValueError, match="incomplete"):
        parse_scan_export(
            json.dumps({"value": [finding], "nextLink": "https://next-page"}).encode(),
            format_name="azure_defender_json",
            provider="azure_defender",
            asset_type="cloud",
            asset_value=resource,
        )


def test_hackerone_reports_import_only_selected_scope_and_safe_metadata() -> None:
    def report(report_id: str, scope: str, state: str) -> dict[str, object]:
        return {
            "id": report_id,
            "type": "report",
            "attributes": {
                "title": f"XSS in search {report_id}",
                "state": state,
                "cve_ids": ["CVE-2025-12345"],
                "vulnerability_information": "Bearer must-not-store",
            },
            "relationships": {
                "structured_scope": {
                    "data": {
                        "type": "structured-scope",
                        "attributes": {
                            "asset_type": "URL",
                            "asset_identifier": scope,
                            "instruction": "secret must-not-store",
                        },
                    }
                },
                "severity": {"data": {"type": "severity", "attributes": {"rating": "high"}}},
                "attachments": {"data": [{"attributes": {"file_name": "must-not-store"}}]},
            },
        }

    payload = json.dumps(
        {
            "data": [
                report("42", "api.example.org", "triaged"),
                report("43", "api.example.org", "resolved"),
                report("44", "other.example.org", "triaged"),
            ],
            "links": {"next": None},
        }
    ).encode()
    first = parse_scan_export(
        payload,
        format_name="hackerone_json",
        provider="hackerone",
        asset_type="domain",
        asset_value="api.example.org",
    )
    second = parse_scan_export(
        payload,
        format_name="hackerone_json",
        provider="hackerone",
        asset_type="domain",
        asset_value="api.example.org",
    )
    assert len(first) == 2
    assert first[0].external_id == second[0].external_id
    assert first[0].status == "open"
    assert first[0].severity == "high"
    assert first[0].cve_ids == ["CVE-2025-12345"]
    assert first[1].status == "fixed"
    assert "must-not-store" not in str(first)
    assert "other.example.org" not in str(first)


def test_hackerone_rejects_incomplete_page_and_unknown_selected_scope() -> None:
    report = {
        "id": "42",
        "type": "report",
        "attributes": {
            "title": "Other report",
            "state": "triaged",
        },
        "relationships": {
            "structured_scope": {
                "data": {
                    "attributes": {
                        "asset_identifier": "other.example.org",
                        "asset_type": "URL",
                    }
                }
            }
        },
    }
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            json.dumps({"data": [report]}).encode(),
            format_name="hackerone_json",
            provider="hackerone",
            asset_type="domain",
            asset_value="api.example.org",
        )
    with pytest.raises(ValueError, match="incomplete"):
        parse_scan_export(
            json.dumps({"data": [report], "links": {"next": "https://next-page"}}).encode(),
            format_name="hackerone_json",
            provider="hackerone",
            asset_type="domain",
            asset_value="api.example.org",
        )


def test_bugcrowd_submissions_resolve_included_target_without_retaining_poc() -> None:
    target_id = "12345678-1234-1234-1234-123456789012"
    other_id = "99999999-9999-9999-9999-999999999999"

    def submission(
        submission_id: str, linked_target: str, state: str, severity: int
    ) -> dict[str, object]:
        return {
            "type": "submission",
            "id": submission_id,
            "attributes": {
                "title": f"Cross-site scripting {submission_id}",
                "state": state,
                "severity": severity,
                "description": "Bearer must-not-store",
            },
            "relationships": {"target": {"data": {"type": "target", "id": linked_target}}},
        }

    payload = json.dumps(
        {
            "data": [
                submission("a", target_id, "triaged", 1),
                submission("b", target_id, "resolved", 3),
                submission("c", other_id, "triaged", 1),
            ],
            "included": [
                {"type": "target", "id": target_id, "attributes": {"name": "api.example.org"}},
                {"type": "target", "id": other_id, "attributes": {"name": "other.example.org"}},
            ],
            "links": {"next": None},
        }
    ).encode()
    first = parse_scan_export(
        payload,
        format_name="bugcrowd_json",
        provider="bugcrowd",
        asset_type="domain",
        asset_value="api.example.org",
    )
    second = parse_scan_export(
        payload,
        format_name="bugcrowd_json",
        provider="bugcrowd",
        asset_type="domain",
        asset_value="api.example.org",
    )
    assert len(first) == 2
    assert first[0].external_id == second[0].external_id
    assert first[0].severity == "critical"
    assert first[0].status == "open"
    assert first[1].severity == "medium"
    assert first[1].status == "fixed"
    assert "must-not-store" not in str(first)
    assert "other.example.org" not in str(first)


def test_bugcrowd_rejects_incomplete_or_unmatched_target_export() -> None:
    payload = {
        "data": [
            {
                "type": "submission",
                "id": "a",
                "attributes": {
                    "title": "Other issue",
                    "state": "triaged",
                    "severity": 1,
                },
                "relationships": {"target": {"data": {"type": "target", "id": "other"}}},
            }
        ],
        "included": [
            {"type": "target", "id": "other", "attributes": {"name": "other.example.org"}}
        ],
    }
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            json.dumps(payload).encode(),
            format_name="bugcrowd_json",
            provider="bugcrowd",
            asset_type="domain",
            asset_value="api.example.org",
        )
    with pytest.raises(ValueError, match="incomplete"):
        parse_scan_export(
            json.dumps({**payload, "links": {"next": "/submissions?page[offset]=25"}}).encode(),
            format_name="bugcrowd_json",
            provider="bugcrowd",
            asset_type="domain",
            asset_value="api.example.org",
        )


def test_nessus_xml_imports_only_the_selected_host_without_plugin_output() -> None:
    export = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report name="network">
  <ReportHost name="192.0.2.10"><HostProperties><tag name="host-fqdn">api.example.org</tag></HostProperties>
    <ReportItem pluginID="12345" pluginName="OpenSSL issue" port="443" protocol="tcp" severity="4">
      <cve>CVE-2024-12345</cve><cvss3_base_score>9.8</cvss3_base_score>
      <plugin_output>Authorization: Bearer secret-never-store</plugin_output>
    </ReportItem>
  </ReportHost>
  <ReportHost name="unrelated.example.org"><ReportItem pluginID="99999" pluginName="Other" port="22" protocol="tcp" severity="3"><cve>CVE-2024-99999</cve></ReportItem></ReportHost>
</Report></NessusClientData_v2>"""
    first = parse_scan_export(
        export,
        format_name="nessus_xml",
        provider="nessus",
        asset_type="domain",
        asset_value="api.example.org",
    )
    second = parse_scan_export(
        export,
        format_name="nessus_xml",
        provider="nessus",
        asset_type="domain",
        asset_value="api.example.org",
    )
    assert len(first) == 1
    assert first[0].external_id == second[0].external_id
    assert first[0].severity == "critical"
    assert first[0].cve_ids == ["CVE-2024-12345"]
    assert first[0].evidence == {
        "asset_type": "domain",
        "asset_value": "api.example.org",
        "plugin_id": "12345",
        "port": 443,
        "protocol": "tcp",
    }
    assert "secret-never-store" not in str(first[0])
    assert "unrelated.example.org" not in str(first[0])


def test_nessus_xml_rejects_unmatched_host_and_entities() -> None:
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            b'<NessusClientData_v2><Report><ReportHost name="other.example.org"/></Report></NessusClientData_v2>',
            format_name="nessus_xml",
            provider="nessus",
            asset_type="domain",
            asset_value="api.example.org",
        )
    with pytest.raises(ValueError, match="XML"):
        parse_scan_export(
            b'<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///etc/passwd">]><NessusClientData_v2/>',
            format_name="nessus_xml",
            provider="nessus",
            asset_type="domain",
            asset_value="api.example.org",
        )


def test_nessus_ip_identity_uses_host_ip_tag_when_report_name_is_fqdn() -> None:
    export = b"""<NessusClientData_v2><Report><ReportHost name="api.example.org">
      <HostProperties><tag name="host-ip">192.0.2.10</tag></HostProperties>
      <ReportItem pluginID="12345" pluginName="TLS issue" port="443" protocol="tcp" severity="3"/>
    </ReportHost></Report></NessusClientData_v2>"""
    findings = parse_scan_export(
        export,
        format_name="nessus_xml",
        provider="nessus",
        asset_type="ip",
        asset_value="192.0.2.10",
    )
    assert len(findings) == 1
    assert findings[0].evidence["asset_value"] == "192.0.2.10"


def test_burp_xml_import_is_scoped_stable_and_drops_http_messages() -> None:
    export = b"""<?xml version="1.0"?>
<!DOCTYPE issues [<!ELEMENT issues (issue*)>]>
<issues burpVersion="2026.9">
  <issue><serialNumber>123456</serialNumber><type>1049088</type>
    <name>SQL injection</name><host ip="192.0.2.10">https://api.example.org</host>
    <path>/app/login</path><location>https://api.example.org/app/login [username]</location>
    <severity>High</severity><confidence>Certain</confidence>
    <issueDetail>Authorization: Bearer secret-never-store</issueDetail>
    <requestresponse><request base64="true">c2VjcmV0</request></requestresponse>
  </issue>
  <issue><serialNumber>123457</serialNumber><type>1049088</type>
    <name>Other host</name><host>https://other.example.org</host><path>/</path>
    <severity>High</severity><confidence>Certain</confidence>
  </issue>
</issues>"""
    first = parse_scan_export(
        export,
        format_name="burp_xml",
        provider="burp",
        asset_type="url",
        asset_value="https://api.example.org/app",
    )
    second = parse_scan_export(
        export,
        format_name="burp_xml",
        provider="burp",
        asset_type="url",
        asset_value="https://api.example.org/app",
    )

    assert len(first) == 1
    assert first[0].external_id == second[0].external_id
    assert first[0].severity == "high"
    assert first[0].category == "dast"
    assert first[0].evidence == {
        "asset_type": "url",
        "asset_value": "https://api.example.org/app",
        "issue_type": "1049088",
        "path": "/app/login",
        "confidence": "certain",
    }
    assert "secret-never-store" not in str(first[0])
    assert "other.example.org" not in str(first[0])


def test_burp_xml_rejects_out_of_scope_and_entity_expansion() -> None:
    export = b"""<issues><issue><serialNumber>10</serialNumber><type>1</type><name>XSS</name>
    <host>https://other.example.org</host><path>/</path><severity>Medium</severity>
    </issue></issues>"""
    with pytest.raises(ValueError, match="selected asset"):
        parse_scan_export(
            export,
            format_name="burp_xml",
            provider="burp",
            asset_type="domain",
            asset_value="api.example.org",
        )
    with pytest.raises(ValueError, match="XML"):
        parse_scan_export(
            b'<!DOCTYPE issues [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'
            b"<issues><issue><name>&leak;</name></issue></issues>",
            format_name="burp_xml",
            provider="burp",
            asset_type="domain",
            asset_value="api.example.org",
        )
    with pytest.raises(ValueError, match="XML"):
        parse_scan_export(
            b'<!DOCTYPE issues SYSTEM "https://external.example/issue.dtd"><issues/>',
            format_name="burp_xml",
            provider="burp",
            asset_type="domain",
            asset_value="api.example.org",
        )


def test_burp_xml_url_scope_rejects_other_scheme_port_and_path_prefix() -> None:
    export = b"""<issues>
      <issue><serialNumber>1</serialNumber><type>1</type><name>Wrong scheme</name>
        <host>https://api.example.org</host><path>http://api.example.org/app/login</path>
        <severity>High</severity></issue>
      <issue><serialNumber>2</serialNumber><type>1</type><name>Wrong port</name>
        <host>https://api.example.org</host><path>https://api.example.org:8443/app/login</path>
        <severity>High</severity></issue>
      <issue><serialNumber>3</serialNumber><type>1</type><name>Wrong prefix</name>
        <host>https://api.example.org</host><path>/application/login</path>
        <severity>High</severity></issue>
      <issue><serialNumber>4</serialNumber><type>1</type><name>Right path</name>
        <host>https://api.example.org</host><path>/app/login</path>
        <severity>High</severity></issue>
    </issues>"""
    findings = parse_scan_export(
        export,
        format_name="burp_xml",
        provider="burp",
        asset_type="url",
        asset_value="https://api.example.org/app",
    )
    assert [finding.title for finding in findings] == ["Right path"]


def test_burp_xml_bad_host_port_does_not_echo_export_content() -> None:
    export = b"""<issues><issue><serialNumber>1</serialNumber><type>1</type>
      <name>XSS</name><host>https://api.example.org:private-token</host>
      <path>/app</path><severity>High</severity></issue></issues>"""
    with pytest.raises(ValueError, match="Burp XML") as error:
        parse_scan_export(
            export,
            format_name="burp_xml",
            provider="burp",
            asset_type="url",
            asset_value="https://api.example.org/app",
        )
    assert "private-token" not in str(error.value)


def test_qualys_host_detection_xml_tracks_selected_host_and_fixed_state() -> None:
    export = b"""<?xml version="1.0"?>
    <!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualys.example/dtd/output.dtd">
    <HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
      <HOST><IP>192.0.2.10</IP><DNS>api.example.org</DNS><DETECTION_LIST>
        <DETECTION><UNIQUE_VULN_ID>61198372</UNIQUE_VULN_ID><QID>13361</QID>
          <TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY><PORT>22</PORT>
          <PROTOCOL>tcp</PROTOCOL><STATUS>Active</STATUS>
          <RESULTS>Authorization: Bearer secret-never-store</RESULTS>
        </DETECTION>
        <DETECTION><UNIQUE_VULN_ID>61198373</UNIQUE_VULN_ID><QID>13362</QID>
          <TYPE>Confirmed</TYPE><SEVERITY>2</SEVERITY><STATUS>Fixed</STATUS>
        </DETECTION>
      </DETECTION_LIST></HOST>
      <HOST><IP>192.0.2.99</IP><DETECTION_LIST>
        <DETECTION><UNIQUE_VULN_ID>999</UNIQUE_VULN_ID><QID>999</QID>
          <SEVERITY>5</SEVERITY><STATUS>Active</STATUS></DETECTION>
      </DETECTION_LIST></HOST>
    </HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""
    first = parse_scan_export(
        export,
        format_name="qualys_host_detection_xml",
        provider="qualys",
        asset_type="domain",
        asset_value="api.example.org",
    )
    second = parse_scan_export(
        export,
        format_name="qualys_host_detection_xml",
        provider="qualys",
        asset_type="domain",
        asset_value="api.example.org",
    )
    assert len(first) == 2
    assert [row.external_id for row in first] == [row.external_id for row in second]
    assert [row.status for row in first] == ["open", "resolved"]
    assert [row.severity for row in first] == ["critical", "medium"]
    assert first[0].evidence == {
        "asset_type": "domain",
        "asset_value": "api.example.org",
        "qid": "13361",
        "unique_vuln_id": "61198372",
        "port": 22,
        "protocol": "tcp",
        "detection_type": "confirmed",
    }
    assert "secret-never-store" not in str(first)
    assert "192.0.2.99" not in str(first)


def test_qualys_host_detection_xml_rejects_truncated_or_unsafe_input() -> None:
    wrapper = b"""<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>
      <HOST_LIST><HOST><IP>192.0.2.10</IP></HOST></HOST_LIST>
      <WARNING><URL>https://qualys.example/next</URL></WARNING>
    </RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""
    with pytest.raises(ValueError, match="truncated"):
        parse_scan_export(
            wrapper,
            format_name="qualys_host_detection_xml",
            provider="qualys",
            asset_type="ip",
            asset_value="192.0.2.10",
        )
    with pytest.raises(ValueError, match="XML"):
        parse_scan_export(
            b'<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'
            b"<HOST_LIST_VM_DETECTION_OUTPUT>&leak;</HOST_LIST_VM_DETECTION_OUTPUT>",
            format_name="qualys_host_detection_xml",
            provider="qualys",
            asset_type="ip",
            asset_value="192.0.2.10",
        )


def test_trivy_misconfiguration_becomes_a_canonical_safe_observation() -> None:
    payload = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Privileged container",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "CauseMetadata": {"StartLine": 8},
                        "Message": "secret-token-must-not-be-retained",
                    }
                ],
            }
        ]
    }
    findings = parse_scan_export(
        json.dumps(payload).encode(),
        format_name="trivy",
        provider="trivy",
        asset_type="repo",
        asset_value="acme/api",
    )
    assert len(findings) == 1
    assert findings[0].category == "misconfiguration"
    assert findings[0].severity == "high"
    assert findings[0].evidence["line"] == 8
    assert "secret-token-must-not-be-retained" not in str(findings[0])


def test_nuclei_jsonl_stages_only_in_scope_matches_without_raw_http_evidence() -> None:
    secret = "sk-private-credential-value"
    finding = {
        "template-id": "CVE-2024-12345",
        "matcher-name": "http-match",
        "info": {"name": "Known endpoint vulnerability", "severity": "high"},
        "host": "https://api.example.org",
        "matched-at": "https://api.example.org/admin?token=secret",
        "request": f"Authorization: Bearer {secret}",
        "response": f"body {secret}",
    }
    out_of_scope = {
        **finding,
        "host": "https://third-party.example",
        "matched-at": "https://third-party.example/admin",
    }
    negative = {**finding, "matcher-status": False}
    data = (
        "\n".join(json.dumps(item) for item in (finding, out_of_scope, negative)) + "\n"
    ).encode()
    alerts = parse_scan_export(
        data,
        format_name="nuclei_jsonl",
        provider="nuclei",
        asset_type="url",
        asset_value="https://api.example.org/",
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.category == "dast"
    assert alert.cve_ids == ["CVE-2024-12345"]
    assert alert.severity == "high"
    assert alert.evidence["path"] == "/admin"
    assert secret not in str(alert)
    assert "token=secret" not in str(alert)
    assert (
        alert.external_id
        == parse_scan_export(
            data,
            format_name="nuclei_jsonl",
            provider="nuclei",
            asset_type="url",
            asset_value="https://api.example.org/",
        )[0].external_id
    )


def test_nuclei_jsonl_rejects_malformed_records_before_staging() -> None:
    with pytest.raises(ValueError, match="Nuclei"):
        parse_scan_export(
            b'{"template-id":"cve-test"}\n',
            format_name="nuclei_jsonl",
            provider="nuclei",
            asset_type="domain",
            asset_value="example.org",
        )


def test_trivy_secret_export_stages_location_without_storing_credential() -> None:
    secret = "AKIAEXAMPLEPRIVATEVALUE"
    document = {
        "Results": [
            {
                "Target": "src/settings.py",
                "Class": "secret",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Title": "AWS access key",
                        "Severity": "HIGH",
                        "StartLine": 12,
                        "EndLine": 12,
                        "Match": secret,
                        "Code": {"Lines": [{"Content": f"AWS_KEY={secret}"}]},
                    }
                ],
            }
        ],
    }
    alerts = parse_scan_export(
        json.dumps(document).encode(),
        format_name="trivy",
        provider="trivy",
        asset_type="repo",
        asset_value="acme/api",
    )
    assert len(alerts) == 1
    assert alerts[0].category == "secret"
    assert alerts[0].severity == "high"
    assert alerts[0].evidence["target"] == "src/settings.py"
    assert alerts[0].evidence["start_line"] == 12
    assert secret not in str(alerts[0])


def test_gitleaks_export_keeps_fingerprint_but_drops_secret_and_match() -> None:
    secret = "sk-example-private-credential"
    document = [
        {
            "RuleID": "generic-api-key",
            "File": "src/config.py",
            "StartLine": 8,
            "Fingerprint": "commit:src/config.py:generic-api-key:8",
            "Secret": secret,
            "Match": f"API_KEY={secret}",
            "Description": f"Matched {secret}",
            "Commit": "abc123",
        }
    ]
    alerts = parse_scan_export(
        json.dumps(document).encode(),
        format_name="gitleaks",
        provider="gitleaks",
        asset_type="repo",
        asset_value="acme/api",
    )
    assert len(alerts) == 1
    assert alerts[0].category == "secret"
    assert alerts[0].evidence["file"] == "src/config.py"
    assert alerts[0].evidence["line"] == 8
    assert secret not in str(alerts[0])
    assert (
        alerts[0].external_id
        == parse_scan_export(
            json.dumps(document).encode(),
            format_name="gitleaks",
            provider="gitleaks",
            asset_type="repo",
            asset_value="acme/api",
        )[0].external_id
    )


def test_cyclonedx_vulnerabilities_map_affected_components_and_ignore_vex_exclusions() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg:npm/lodash@4.17.0",
                "name": "lodash",
                "version": "4.17.0",
                "purl": "pkg:npm/lodash@4.17.0",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-12345",
                "ratings": [{"severity": "high", "score": 8.8}],
                "affects": [{"ref": "pkg:npm/lodash@4.17.0"}],
            },
            {
                "id": "CVE-2024-22222",
                "analysis": {"state": "not_affected"},
                "affects": [{"ref": "pkg:npm/lodash@4.17.0"}],
            },
        ],
    }
    payload = json.dumps(document).encode()
    alerts = parse_scan_export(
        payload,
        format_name="cyclonedx",
        provider="syft",
        asset_type="repo",
        asset_value="acme/api",
    )
    assert len(alerts) == 1
    assert alerts[0].cve_ids == ["CVE-2024-12345"]
    assert alerts[0].severity == "high"
    assert alerts[0].evidence["package"] == "lodash"
    assert alerts[0].evidence["version"] == "4.17.0"
    assert (
        alerts[0].external_id
        == parse_scan_export(
            payload,
            format_name="cyclonedx",
            provider="syft",
            asset_type="repo",
            asset_value="acme/api",
        )[0].external_id
    )


def test_spdx_security_advisory_links_become_package_findings() -> None:
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-1",
                "name": "lodash",
                "versionInfo": "4.17.0",
                "externalRefs": [
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "advisory",
                        "referenceLocator": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                    },
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/lodash@4.17.0",
                    },
                ],
            }
        ],
    }
    alerts = parse_scan_export(
        json.dumps(document).encode(),
        format_name="spdx",
        provider="syft",
        asset_type="repo",
        asset_value="acme/api",
    )
    assert len(alerts) == 1
    assert alerts[0].category == "sca"
    assert alerts[0].cve_ids == ["CVE-2024-12345"]
    assert alerts[0].evidence["package"] == "lodash"
    assert alerts[0].evidence["version"] == "4.17.0"
    assert alerts[0].source_url is None


def test_generic_json_mapping_reads_only_declared_fields() -> None:
    document = {
        "findings": [
            {
                "issue": {"key": "ISSUE-7", "summary": "Outdated lodash"},
                "risk": "high",
                "identifiers": {"cve": "CVE-2024-12345"},
                "state": "open",
                "private_token": "sk-do-not-persist-this-key",
            }
        ]
    }
    mapping = {
        "id": "issue.key",
        "title": "issue.summary",
        "severity": "risk",
        "cve": "identifiers.cve",
        "status": "state",
    }
    alerts = parse_scan_export(
        json.dumps(document).encode(),
        format_name="generic_json",
        provider="vendorx",
        asset_type="repo",
        asset_value="acme/api",
        field_mapping=mapping,
    )
    assert len(alerts) == 1
    assert alerts[0].title == "Outdated lodash"
    assert alerts[0].severity == "high"
    assert alerts[0].cve_ids == ["CVE-2024-12345"]
    assert alerts[0].evidence["asset_value"] == "acme/api"
    assert "sk-do-not-persist-this-key" not in str(alerts[0])


def test_generic_csv_mapping_handles_columns_without_retaining_unmapped_values() -> None:
    payload = (
        b"key,summary,level,cve,private_token\n"
        b"ISSUE-7,Outdated lodash,HIGH,CVE-2024-12345,sk-do-not-persist-this-key\n"
    )
    alerts = parse_scan_export(
        payload,
        format_name="generic_csv",
        provider="vendorx",
        asset_type="repo",
        asset_value="acme/api",
        field_mapping={"id": "key", "title": "summary", "severity": "level", "cve": "cve"},
    )
    assert len(alerts) == 1
    assert alerts[0].title == "Outdated lodash"
    assert alerts[0].cve_ids == ["CVE-2024-12345"]
    assert "sk-do-not-persist-this-key" not in str(alerts[0])


def test_generic_mapping_rejects_missing_identity_and_expression_paths() -> None:
    with pytest.raises(ValueError):
        parse_scan_export(
            b'[{"title":"No stable ID"}]',
            format_name="generic_json",
            provider="vendorx",
            asset_type="repo",
            asset_value="acme/api",
            field_mapping={"id": "id", "title": "title"},
        )
    with pytest.raises(ValueError):
        parse_scan_export(
            b"[]",
            format_name="generic_json",
            provider="vendorx",
            asset_type="repo",
            asset_value="acme/api",
            field_mapping={"id": "row[0]", "title": "title"},
        )


@pytest.mark.parametrize("bad", [b"", b"{}", b"[]", b"not-json"])
def test_invalid_sarif_is_rejected_without_partial_results(bad: bytes) -> None:
    with pytest.raises(ValueError):
        parse_scan_export(
            bad,
            format_name="sarif",
            provider="semgrep",
            asset_type="repo",
            asset_value="acme/api",
        )


@pytest.mark.asyncio
async def test_import_uses_actor_tenant_and_denies_viewer(monkeypatch) -> None:
    from app.core.errors import PermissionDeniedError
    from app.services import external_alert, file_intake

    payload = json.dumps(
        {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-12345",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.0",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
    ).encode()
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    staged = []
    audited = []

    async def stage(session, *, organization_id, integration_id, provider, alerts):
        staged.append((organization_id, provider, list(alerts)))
        return len(staged[-1][2])

    async def record(session, **kwargs):
        audited.append(kwargs)

    monkeypatch.setattr(external_alert, "_stage_normalized_alerts", stage)
    monkeypatch.setattr(file_intake.audit_service, "record", record)
    viewer = Principal(user_id=uuid.uuid4(), organization_id=tenant_a, role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        await file_intake.stage_scan_export(
            object(),
            viewer,
            payload,
            format_name="trivy",
            provider="trivy",
            asset_type="repo",
            asset_value="acme/api",
        )
    assert staged == []

    for tenant in (tenant_a, tenant_b):
        actor = Principal(user_id=uuid.uuid4(), organization_id=tenant, role=Role.SECURITY_ENGINEER)
        count = await file_intake.stage_scan_export(
            object(),
            actor,
            payload,
            format_name="trivy",
            provider="trivy",
            asset_type="repo",
            asset_value="acme/api",
        )
        assert count == 1
    assert [item[0] for item in staged] == [tenant_a, tenant_b]
    assert [item["organization_id"] for item in audited] == [tenant_a, tenant_b]


@pytest.mark.asyncio
async def test_prowler_pass_results_only_update_previously_seen_findings(monkeypatch) -> None:
    from app.services import external_alert, file_intake

    actor = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.SECURITY_ENGINEER
    )

    def row(uid: str, status: str) -> dict:
        return {
            "metadata": {"event_code": "s3_public_access"},
            "finding_info": {"uid": uid, "title": "Public bucket"},
            "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            "resources": [{"uid": f"arn:aws:s3:::{uid}"}],
            "status_code": status,
            "severity": "High",
        }

    payload = json.dumps(
        [row("active", "FAIL"), row("never-failed", "PASS"), row("formerly-failed", "PASS")]
    ).encode()
    parsed = parse_scan_export(
        payload,
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
    )
    existing_id = parsed[2].external_id
    staged = []

    class Result:
        def scalars(self):
            return self

        def all(self):
            return [existing_id]

    class Session:
        async def execute(self, statement):
            compiled = statement.compile()
            assert actor.organization_id in compiled.params.values()
            assert "prowler" in compiled.params.values()
            return Result()

    async def stage(session, *, organization_id, integration_id, provider, alerts):
        staged.extend(alerts)
        return len(alerts)

    async def record(session, **kwargs):
        return None

    monkeypatch.setattr(external_alert, "_stage_normalized_alerts", stage)
    monkeypatch.setattr(file_intake.audit_service, "record", record)
    count = await file_intake.stage_scan_export(
        Session(),
        actor,
        payload,
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value="aws:123456789012",
    )
    assert count == 2
    assert [item.status for item in staged] == ["open", "fixed"]
    assert [item.resource for item in staged] == [
        "arn:aws:s3:::active",
        "arn:aws:s3:::formerly-failed",
    ]


@pytest.mark.asyncio
async def test_import_rejects_invalid_export_as_user_error_without_writes() -> None:
    from app.core.errors import InvalidConfigurationError
    from app.services.file_intake import stage_scan_export

    actor = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.ADMIN)
    with pytest.raises(InvalidConfigurationError):
        await stage_scan_export(
            object(),
            actor,
            b"not-json",
            format_name="sarif",
            provider="semgrep",
            asset_type="repo",
            asset_value="acme/api",
        )


@pytest.mark.asyncio
async def test_import_endpoint_rejects_oversized_upload_before_staging(monkeypatch) -> None:
    from app.api.v1.integrations import import_scan_export
    from app.core.errors import InvalidConfigurationError
    from app.services import file_intake

    class Upload:
        async def read(self, length):
            assert length == file_intake.MAX_IMPORT_BYTES + 1
            return b"x" * length

    async def unexpected_stage(*args, **kwargs):
        raise AssertionError("oversized files must not reach persistence")

    monkeypatch.setattr(file_intake, "stage_scan_export", unexpected_stage)
    actor = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.ADMIN)
    with pytest.raises(InvalidConfigurationError):
        await import_scan_export(
            file=Upload(),
            format_name="sarif",
            provider="semgrep",
            asset_type="repo",
            asset_value="acme/api",
            principal=actor,
            session=object(),
        )


@pytest.mark.asyncio
async def test_import_endpoint_denies_viewer_before_reading_upload() -> None:
    from app.api.v1.integrations import import_scan_export
    from app.core.errors import PermissionDeniedError

    class Upload:
        async def read(self, length):
            raise AssertionError("unauthorized upload must not be read")

    viewer = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        await import_scan_export(
            file=Upload(),
            format_name="sarif",
            provider="semgrep",
            asset_type="repo",
            asset_value="acme/api",
            principal=viewer,
            session=object(),
        )


@pytest.mark.asyncio
async def test_generic_import_endpoint_passes_validated_mapping_to_tenant_stage(
    monkeypatch,
) -> None:
    from app.api.v1.integrations import import_scan_export
    from app.services import file_intake

    actor = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.ADMIN)
    seen = []

    class Upload:
        async def read(self, length):
            return b"key,title\nA-1,Example\n"

    class Session:
        async def commit(self):
            seen.append("committed")

    async def stage(session, principal, data, **kwargs):
        assert principal.organization_id == actor.organization_id
        assert kwargs["field_mapping"] == {"id": "key", "title": "title"}
        seen.append("staged")
        return 1

    monkeypatch.setattr(file_intake, "stage_scan_export", stage)
    result = await import_scan_export(
        file=Upload(),
        format_name="generic_csv",
        provider="vendorx",
        asset_type="repo",
        asset_value="acme/api",
        mapping_json='{"id":"key","title":"title"}',
        principal=actor,
        session=Session(),
    )
    assert result == {"findings_staged": 1}
    assert seen == ["staged", "committed"]
