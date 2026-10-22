"""Integration configuration endpoints (FR-028, FR-032, SEC-002).

WHY the service stages writes and the router commits: :mod:`app.services.integration` follows
the house rule that a service flushes and audits but never commits, so a handler that raises
before its commit persists nothing. Every mutating endpoint here therefore ends its success
path with ``await session.commit()`` -- including ``test``, which never raises for a provider
failure (an unreachable Jira is the *answer*, not an error) but does record the verdict on the
row, so without the commit the probe result would be discarded.

WHY the upsert reloads before projecting: ``created_at``/``updated_at`` are ``server_default``
columns with no client-side default (:class:`app.db.base.TimestampMixin`). A freshly-inserted
integration or credential row therefore has those attributes *expired* after flush, and reading
one on the async session would trigger implicit IO -- a ``MissingGreenlet`` crash inside the
synchronous :func:`app.services.integration.integration_out`. The row is re-read with
:func:`app.services.integration.find_integration` (which carries no permission check, so a
``INTEGRATION_MANAGE`` principal need not also hold ``INTEGRATION_READ``) after the commit,
which repopulates every column from the database.

No endpoint here returns a secret: :func:`integration_out` exposes only a fingerprint and a
four-character hint, and the connectivity probe returns a user-safe summary -- provider response
bodies are logged, never echoed (SEC-002).
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, File, Form, UploadFile

from app.api.deps import DbSession, PrincipalDep, RedisDep, SettingsDep
from app.core.errors import InvalidConfigurationError, ResourceNotFoundError
from app.db.enums import IntegrationKind, Permission
from app.schemas.integration import (
    ConnectorCertificationOut,
    ConnectorContractTestOut,
    IntegrationHealthOut,
    IntegrationOut,
    IntegrationSyncOut,
    IntegrationTestOut,
    IntegrationUpsertIn,
    SourceCoverageOut,
    TenableScanLaunchOut,
    TenableScanStatusOut,
)
from app.services import external_alert as external_alert_service
from app.services import file_intake
from app.services import integration as integration_service

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.post("/imports/scan", response_model=dict[str, int])
async def import_scan_export(
    principal: PrincipalDep,
    session: DbSession,
    file: Annotated[UploadFile, File()],
    format_name: Annotated[str, Form()],
    provider: Annotated[str, Form()],
    asset_type: Annotated[str, Form()],
    asset_value: Annotated[str, Form()],
    mapping_json: Annotated[str | None, Form()] = None,
) -> dict[str, int]:
    """Import bounded scanner and SBOM findings into the tenant's canonical model."""
    principal.require(Permission.ASSESSMENT_CREATE)
    data = await file.read(file_intake.MAX_IMPORT_BYTES + 1)
    if len(data) > file_intake.MAX_IMPORT_BYTES:
        raise InvalidConfigurationError(
            "scanner export too large", user_message="Scanner export exceeds the 10 MB limit."
        )
    field_mapping = None
    if mapping_json is not None:
        if len(mapping_json) > 4096:
            raise InvalidConfigurationError("generic field mapping is too large")
        try:
            field_mapping = json.loads(mapping_json)
        except json.JSONDecodeError as exc:
            raise InvalidConfigurationError("generic field mapping must be valid JSON") from exc
        if not isinstance(field_mapping, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in field_mapping.items()
        ):
            raise InvalidConfigurationError("generic field mapping must be a string map")
    count = await file_intake.stage_scan_export(
        session,
        principal,
        data,
        format_name=format_name,
        provider=provider,
        asset_type=asset_type,
        asset_value=asset_value,
        field_mapping=field_mapping,
    )
    await session.commit()
    return {"findings_staged": count}


@router.get("", response_model=list[IntegrationOut])
async def list_integrations(
    principal: PrincipalDep,
    session: DbSession,
) -> list[IntegrationOut]:
    """Every configured integration for the organization, secrets redacted (FR-028)."""
    rows = await integration_service.list_integrations(session, principal)
    return [integration_service.integration_out(row) for row in rows]


@router.get("/health", response_model=list[IntegrationHealthOut])
async def integration_health(
    principal: PrincipalDep,
    session: DbSession,
    redis: RedisDep,
) -> list[IntegrationHealthOut]:
    """One health row per integration, including live circuit-breaker state (FR-031, FR-020).

    Declared before ``/{kind}`` so ``GET /integrations/health`` is not swallowed as a ``kind``
    path parameter. ``redis`` is passed so the breaker state is real rather than assumed closed.
    """
    return await integration_service.integration_health(session, principal, redis=redis)


@router.get("/coverage", response_model=list[SourceCoverageOut])
async def integration_source_coverage(
    principal: PrincipalDep,
    session: DbSession,
    redis: RedisDep,
) -> list[SourceCoverageOut]:
    """Show source volume, freshness, missing records, and connector confidence."""
    return await integration_service.source_coverage(session, principal, redis=redis)


@router.get("/certifications", response_model=list[ConnectorCertificationOut])
async def connector_certifications(
    principal: PrincipalDep,
    session: DbSession,
    redis: RedisDep,
) -> list[ConnectorCertificationOut]:
    """Explain whether each configured connector is genuinely operational."""

    return await integration_service.connector_certifications(
        session, principal, redis=redis
    )


@router.post("", response_model=IntegrationOut)
async def upsert_integration(
    payload: IntegrationUpsertIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> IntegrationOut:
    """Create or update one integration, encrypting any submitted credentials (FR-028, FR-032).

    Credentials are write-only: they are encrypted on receipt and never returned. Omitting a
    credential slot keeps its stored value; sending an empty string clears it (enforced in the
    service). The row is re-read after the commit before projecting, because a freshly-inserted
    row's ``server_default`` timestamps are expired until reloaded (see the module docstring).
    """
    await integration_service.upsert_integration(session, principal, payload, settings=settings)
    await session.commit()
    reloaded = await integration_service.find_integration(session, principal, payload.kind)
    assert reloaded is not None  # noqa: S101 - just upserted under this tenant and kind
    return integration_service.integration_out(reloaded)


@router.post("/github/sync", response_model=IntegrationSyncOut)
async def sync_github_alerts(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest the organization's GitHub security alerts into Cynux's private ledger.

    The result has only ingestion counts. Raw provider evidence stays restricted to the
    backend correlation path and cannot be exposed through a browser response.
    """
    result = await external_alert_service.sync_github_alerts(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.GITHUB,
        alerts_staged=result.total,
        missing_source_records=result.missing_source_records,
    )


@router.post("/gitlab/sync", response_model=IntegrationSyncOut)
async def sync_gitlab_alerts(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest this organization's GitLab security findings into Cynux's private ledger."""
    result = await external_alert_service.sync_gitlab_alerts(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.GITLAB,
        alerts_staged=result.total,
        missing_source_records=result.missing_source_records,
    )


@router.post("/wazuh/sync", response_model=IntegrationSyncOut)
async def sync_wazuh_alerts(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest this organization's Wazuh Indexer alerts into Cynux's private ledger."""
    result = await external_alert_service.sync_wazuh_alerts(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(kind=IntegrationKind.WAZUH, alerts_staged=result.total)


@router.post("/sonarqube/sync", response_model=IntegrationSyncOut)
async def sync_sonarqube_alerts(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest read-only SonarQube vulnerabilities from the tenant's selected projects."""
    result = await external_alert_service.sync_sonarqube_alerts(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.SONARQUBE,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/snyk/sync", response_model=IntegrationSyncOut)
async def sync_snyk_issues(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest the tenant's Snyk issues into its private exposure ledger."""
    result = await external_alert_service.sync_snyk_issues(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(kind=IntegrationKind.SNYK, alerts_staged=result.total)


@router.post("/tenable/sync", response_model=IntegrationSyncOut)
async def sync_tenable_vulnerabilities(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest selected Tenable VM scan results into the private exposure ledger."""
    result = await external_alert_service.sync_tenable_vulnerabilities(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.TENABLE,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/qualys/sync", response_model=IntegrationSyncOut)
async def sync_qualys_host_detections(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest the configured Qualys VM host-detection report for one tenant IP asset."""
    result = await external_alert_service.sync_qualys_host_detections(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.QUALYS,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/rapid7/sync", response_model=IntegrationSyncOut)
async def sync_rapid7_vulnerabilities(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest vulnerabilities from the selected tenant InsightVM Console assets."""
    result = await external_alert_service.sync_rapid7_vulnerabilities(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.RAPID7,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/wiz/sync", response_model=IntegrationSyncOut)
async def sync_wiz_issues(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest issues from only the configured Wiz projects."""
    result = await external_alert_service.sync_wiz_issues(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.WIZ,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
        missing_source_records=result.missing_source_records,
    )


@router.post("/prisma_cloud/sync", response_model=IntegrationSyncOut)
async def sync_prisma_cloud_alerts(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest open alerts from the tenant's selected Prisma cloud accounts."""
    result = await external_alert_service.sync_prisma_cloud_alerts(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.PRISMA_CLOUD,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/crowdstrike/sync", response_model=IntegrationSyncOut)
async def sync_crowdstrike_vulnerabilities(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest the tenant's open Falcon Spotlight vulnerability snapshot."""
    result = await external_alert_service.sync_crowdstrike_vulnerabilities(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.CROWDSTRIKE,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/aws_security_hub/sync", response_model=IntegrationSyncOut)
async def sync_aws_security_hub_findings(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest active findings from the tenant's selected AWS accounts."""
    result = await external_alert_service.sync_aws_security_hub_findings(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.AWS_SECURITY_HUB,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/aws_inspector/sync", response_model=IntegrationSyncOut)
async def sync_aws_inspector_findings(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest active Amazon Inspector findings for selected AWS accounts."""
    result = await external_alert_service.sync_aws_inspector_findings(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.AWS_INSPECTOR,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/hackerone/sync", response_model=IntegrationSyncOut)
async def sync_hackerone_reports(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest reports from the tenant's selected HackerOne programs."""
    result = await external_alert_service.sync_hackerone_reports(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.HACKERONE,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/bugcrowd/sync", response_model=IntegrationSyncOut)
async def sync_bugcrowd_submissions(principal: PrincipalDep, session: DbSession, settings: SettingsDep, redis: RedisDep) -> IntegrationSyncOut:
    result = await external_alert_service.sync_bugcrowd_submissions(session, principal, settings=settings, redis=redis)
    await session.commit()
    return IntegrationSyncOut(kind=IntegrationKind.BUGCROWD, alerts_staged=result.total, absence_candidates=result.absence_candidates)


@router.post("/checkmarx/sync", response_model=IntegrationSyncOut)
async def sync_checkmarx_results(principal: PrincipalDep, session: DbSession, settings: SettingsDep, redis: RedisDep) -> IntegrationSyncOut:
    result = await external_alert_service.sync_checkmarx_results(session, principal, settings=settings, redis=redis)
    await session.commit()
    return IntegrationSyncOut(kind=IntegrationKind.CHECKMARX, alerts_staged=result.total, absence_candidates=result.absence_candidates)


@router.post("/fortify/sync", response_model=IntegrationSyncOut)
async def sync_fortify_issues(principal: PrincipalDep, session: DbSession, settings: SettingsDep, redis: RedisDep) -> IntegrationSyncOut:
    result = await external_alert_service.sync_fortify_issues(session, principal, settings=settings, redis=redis)
    await session.commit()
    return IntegrationSyncOut(kind=IntegrationKind.FORTIFY, alerts_staged=result.total, absence_candidates=result.absence_candidates)


@router.post("/azure_defender/sync", response_model=IntegrationSyncOut)
async def sync_azure_defender_alerts(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest alerts from the tenant's Microsoft Defender subscription."""
    result = await external_alert_service.sync_azure_defender_alerts(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.AZURE_DEFENDER,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/gcp_scc/sync", response_model=IntegrationSyncOut)
async def sync_gcp_scc_findings(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest findings from the tenant's Google Security Command Center project."""
    result = await external_alert_service.sync_gcp_scc_findings(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.GCP_SCC,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.post("/burp_dast/sync", response_model=IntegrationSyncOut)
async def sync_burp_dast_findings(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationSyncOut:
    """Ingest latest complete scans from the tenant's selected Burp DAST sites."""
    result = await external_alert_service.sync_burp_dast_findings(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return IntegrationSyncOut(
        kind=IntegrationKind.BURP_DAST,
        alerts_staged=result.total,
        absence_candidates=result.absence_candidates,
    )


@router.get("/tenable/scans/{scan_id}/status", response_model=TenableScanStatusOut)
async def tenable_scan_status(
    scan_id: str,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> TenableScanStatusOut:
    status = await integration_service.tenable_scan_status(
        session, principal, scan_id, settings=settings, redis=redis
    )
    return TenableScanStatusOut(scan_id=scan_id, status=status)


@router.post("/tenable/scans/{scan_id}/launch", response_model=TenableScanLaunchOut)
async def launch_tenable_scan(
    scan_id: str,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> TenableScanLaunchOut:
    """Launch a previously saved Tenable scan using its configured targets only."""
    run_uuid = await integration_service.launch_tenable_scan(
        session, principal, scan_id, settings=settings, redis=redis
    )
    await session.commit()
    return TenableScanLaunchOut(scan_id=scan_id, run_uuid=run_uuid)


@router.get("/{kind}", response_model=IntegrationOut)
async def get_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
) -> IntegrationOut:
    """One integration by kind. A kind that is not configured is a 404."""
    integration = await integration_service.get_integration(session, principal, kind)
    return integration_service.integration_out(integration)


@router.delete("/{kind}", response_model=IntegrationOut)
async def disable_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
) -> IntegrationOut:
    """Disable an integration without discarding its credentials (FR-032).

    Deliberately not a hard delete: turning an integration off during an incident and back on
    afterwards must not force an operator to re-enter the API token. The returned row is the
    now-disabled integration, so the UI can update in place. The row was fully loaded by the
    service (via ``get_integration``), so it is projected directly after the commit -- no
    freshly-inserted columns are in play.
    """
    integration = await integration_service.disable_integration(session, principal, kind)
    await session.commit()
    return integration_service.integration_out(integration)


@router.post("/{kind}/test", response_model=IntegrationTestOut)
async def test_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationTestOut:
    """Probe a provider live and persist the verdict on the row (FR-028, FR-032).

    Never fails for a provider-side problem -- an unreachable or rejecting provider is the
    result of the test, not an error in running it. The commit is required: the service stages
    the ``configured``/``error`` status, ``last_verified_at`` and the failure counter without
    committing, so omitting it here would return a verdict that was never saved.
    """
    result = await integration_service.test_integration(
        session, principal, kind, settings=settings, redis=redis
    )
    await session.commit()
    return result


@router.post("/{kind}/contract-test", response_model=ConnectorContractTestOut)
async def contract_test_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> ConnectorContractTestOut:
    integration = await integration_service.find_integration(session, principal, kind)
    if integration is None:
        raise ResourceNotFoundError("integration not configured")
    live = await integration_service.test_integration(
        session, principal, kind, settings=settings, redis=redis
    )
    certifications = await integration_service.connector_certifications(
        session, principal, redis=redis
    )
    certification = next(item for item in certifications if item.kind == kind)
    result = integration_service.connector_contract_result(live, certification)
    await session.commit()
    return result


__all__ = ["router"]
