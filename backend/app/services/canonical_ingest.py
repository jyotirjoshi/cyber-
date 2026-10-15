"""Map provider observations to the tenant-owned canonical inventory."""

from __future__ import annotations

import ipaddress
import uuid
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import Severity
from app.db.models.asset import Asset
from app.db.models.canonical import (
    AssessmentCanonicalFinding,
    CanonicalFinding,
    FindingHistory,
    FindingObservation,
)
from app.db.models.finding import Finding
from app.db.models.identity import Organization
from app.db.queries import pg_any
from app.services.automation import queue_finding_event
from app.services.canonical_identity import (
    asset_storage_name,
    identity_for_observation,
    normalized_asset_identity,
    valid_cves,
)
from app.services.canonical_intel_refresh import (
    verified_intel_evidence,
    with_stale_intel_provenance,
)
from app.services.canonical_lifecycle import next_status
from app.services.canonical_risk import score_canonical
from app.services.entitlements import assert_asset_capacity, load_entitlements
from app.services.organization import load_policy
from app.services.sla import calculate_due_at

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


async def assessment_finding_counts(
    session: AsyncSession,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
) -> dict[str, int]:
    """Merge non-duplicate native severity counts with assessment-linked exposures."""
    counts = {severity.value: 0 for severity in Severity}
    native_rows = await session.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(
            Finding.organization_id == organization_id,
            Finding.assessment_id == assessment_id,
            Finding.is_duplicate.is_(False),
            Finding.is_false_positive.is_(False),
        )
        .group_by(Finding.severity)
    )
    for severity, total in native_rows.all():
        counts[str(severity)] += int(total)
    represented_by_native = exists(
        select(FindingObservation.id)
        .join(Finding, Finding.id == FindingObservation.source_record_id)
        .where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.canonical_finding_id
            == AssessmentCanonicalFinding.canonical_finding_id,
            FindingObservation.provider == "defectdojo",
            Finding.organization_id == organization_id,
            Finding.assessment_id == assessment_id,
            Finding.is_duplicate.is_(False),
            Finding.is_false_positive.is_(False),
        )
        .correlate(AssessmentCanonicalFinding)
    )
    linked_rows = await session.execute(
        select(CanonicalFinding.severity, func.count(AssessmentCanonicalFinding.id))
        .join(
            CanonicalFinding, CanonicalFinding.id == AssessmentCanonicalFinding.canonical_finding_id
        )
        .where(
            AssessmentCanonicalFinding.organization_id == organization_id,
            AssessmentCanonicalFinding.assessment_id == assessment_id,
            CanonicalFinding.organization_id == organization_id,
            CanonicalFinding.status != "false_positive",
            ~represented_by_native,
        )
        .group_by(CanonicalFinding.severity)
    )
    for severity, total in linked_rows.all():
        counts[str(severity)] += int(total)
    return counts


async def link_scan_observations(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
    job_id: uuid.UUID,
    provider: str,
    external_ids: list[str],
) -> int:
    """Pin a scan's canonical identities to its assessment without cross-tenant reads."""
    if not external_ids:
        return 0
    result = await session.execute(
        select(FindingObservation.canonical_finding_id).where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.provider == provider,
            pg_any(FindingObservation.external_id, set(external_ids)),
        )
    )
    finding_ids = set(result.scalars().all())
    if not finding_ids:
        return 0
    ordered_ids = sorted(finding_ids)
    now = utcnow()
    count = 0
    for offset in range(0, len(ordered_ids), 500):
        statement = (
            pg_insert(AssessmentCanonicalFinding)
            .values(
                [
                    {
                        "id": uuid.uuid4(),
                        "organization_id": organization_id,
                        "assessment_id": assessment_id,
                        "canonical_finding_id": finding_id,
                        "scanner_job_id": job_id,
                        "created_at": now,
                    }
                    for finding_id in ordered_ids[offset : offset + 500]
                ]
            )
            .on_conflict_do_nothing(constraint="unique_assessment_canonical_finding")
            .returning(AssessmentCanonicalFinding.id)
        )
        inserted = await session.execute(statement)
        count += len(inserted.scalars().all())
    return count


def _asset_candidate_names(kind: str, value: str) -> frozenset[str]:
    names = {asset_storage_name(kind, value)}
    if kind == "repo":
        first_segment = value.split("/", 1)[0]
        if "." in first_segment or ":" in first_segment:
            names.add(f"https://{value}")
        else:
            names.update(
                f"https://{host}/{value}" for host in ("github.com", "gitlab.com", "bitbucket.org")
            )
    elif kind in {"container_image", "domain", "ip", "url"}:
        names.add(value)
    return frozenset(names)


def alert_asset_identity(alert: Any) -> tuple[str, str] | None:
    """Return an asset key only when the provider supplies a stable resource."""
    resource = str(alert.resource or "").strip()
    evidence = alert.evidence or {}
    provider = str(alert.provider or "").lower()
    if provider in {"github", "gitlab"}:
        repo = str(evidence.get("project") or resource).strip()
        return normalized_asset_identity("repo", repo) if repo else None
    if provider == "wazuh":
        agent_id = str(evidence.get("agent_id") or "").strip()
        return ("endpoint_agent", agent_id) if agent_id else None
    if provider == "sonarqube":
        project = str(evidence.get("project") or "").strip()
        return ("application", project) if project else None
    if provider == "snyk":
        return ("snyk_project", resource) if resource else None
    if provider == "tenable":
        if not resource:
            return None
        if resource == str(evidence.get("host_uuid") or ""):
            return "tenable_host", resource
        try:
            return normalized_asset_identity("ip", resource)
        except ValueError:
            if any(character.isspace() for character in resource):
                return None
            return normalized_asset_identity("domain", resource)
    if provider == "defectdojo":
        kind = str(evidence.get("asset_type") or "").strip()
        value = str(evidence.get("asset_value") or "").strip()
        return normalized_asset_identity(kind, value) if kind and value else None
    kind = str(evidence.get("asset_type") or "").strip()
    value = str(evidence.get("asset_value") or "").strip()
    if kind and value:
        try:
            return normalized_asset_identity(kind, value)
        except ValueError:
            return None
    return None


async def ingest_external_alerts(
    session: AsyncSession,
    organization_id: uuid.UUID,
    alerts: list[Any],
    *,
    asset_overrides: dict[tuple[str, str], Asset] | None = None,
) -> int:
    """Merge alert evidence into canonical findings in the caller's transaction.

    Source alerts remain intact. Organization locking serializes asset capacity and
    fingerprint creation for concurrent syncs of the same tenant. An alert without
    stable asset identity stays in the original inbox instead of being merged into
    an anonymous, shared finding.
    """
    prepared = [
        (alert, identity)
        for alert in alerts
        if (identity := alert_asset_identity(alert)) is not None
    ]
    if not prepared:
        return 0
    if any(alert.organization_id != organization_id for alert, _ in prepared):
        raise ValueError("cross-tenant alert passed to canonical ingestion")

    overrides = asset_overrides or {}
    if any(asset.organization_id != organization_id for asset in overrides.values()):
        raise ValueError("cross-tenant asset override passed to canonical ingestion")

    organization = (
        await session.execute(
            select(Organization).where(Organization.id == organization_id).with_for_update()
        )
    ).scalar_one()
    keys = {(kind, value) for _, (kind, value) in prepared if (kind, value) not in overrides}
    storage_keys = {asset_storage_name(*key): key for key in keys}
    names = {name for kind, value in keys for name in _asset_candidate_names(kind, value)}
    existing_assets = (
        (
            await session.execute(
                select(Asset).where(
                    Asset.organization_id == organization_id,
                    pg_any(Asset.name, names),
                    Asset.port.is_(None),
                    Asset.protocol.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    synthetic: dict[tuple[str, str], Asset] = {}
    native: dict[tuple[str, str], list[Asset]] = {}
    for asset in existing_assets:
        if (
            asset.organization_id != organization_id
            or asset.port is not None
            or asset.protocol is not None
        ):
            continue
        stored_key = storage_keys.get(asset.name)
        if stored_key is not None:
            synthetic[stored_key] = asset
            continue
        try:
            key = normalized_asset_identity(asset.asset_type, asset.name)
        except ValueError:
            continue
        if key in keys and asset.name in _asset_candidate_names(*key):
            native.setdefault(key, []).append(asset)
    resolved = {key: matches[0] for key, matches in native.items() if len(matches) == 1}
    resolved.update({key: asset for key, asset in synthetic.items() if key not in resolved})
    new_asset_keys = {asset_storage_name(*key): key for key in keys if key not in resolved}
    new_asset_names = set(new_asset_keys)
    if new_asset_names:
        current_count = (
            await session.execute(
                select(func.count())
                .select_from(Asset)
                .where(Asset.organization_id == organization_id)
            )
        ).scalar_one()
        assert_asset_capacity(
            current_assets=int(current_count),
            new_assets=len(new_asset_names),
            entitlements=load_entitlements(organization.entitlements),
        )
    now = utcnow()
    sla_targets = load_policy(organization).sla_targets_days
    for name in sorted(new_asset_names):
        kind, _, _ = name.partition(":")
        asset = Asset(
            id=uuid.uuid4(),
            organization_id=organization_id,
            name=name,
            asset_type=kind,
            status="active",
            first_seen_at=now,
            last_seen_at=now,
            criticality="unknown",
            criticality_source="default",
            risk_score=0.0,
            evidence={"identity_source": "external_security_alert"},
            seen_in_assessments=[],
            technology=[],
        )
        session.add(asset)
        resolved[new_asset_keys[name]] = asset

    asset_for_key = {
        (kind, value): overrides.get((kind, value)) or resolved[(kind, value)]
        for _, (kind, value) in prepared
    }

    fingerprinted = [
        (
            alert,
            asset_for_key[(kind, value)],
            cve,
            identity_for_observation(
                kind, value, [cve] if cve else [], alert.provider, alert.external_id
            ),
        )
        for alert, (kind, value) in prepared
        for cve in (valid_cves(alert.cve_ids or []) or [""])
    ]
    fingerprints = {fingerprint for _, _, _, fingerprint in fingerprinted}
    found = (
        (
            await session.execute(
                select(CanonicalFinding).where(
                    CanonicalFinding.organization_id == organization_id,
                    pg_any(CanonicalFinding.fingerprint, fingerprints),
                )
            )
        )
        .scalars()
        .all()
    )
    findings = {finding.fingerprint: finding for finding in found}
    linked_asset_ids = {finding.asset_id for finding in found}
    linked_assets = (
        (
            await session.execute(
                select(Asset).where(
                    Asset.organization_id == organization_id,
                    pg_any(Asset.id, linked_asset_ids),
                )
            )
        )
        .scalars()
        .all()
        if linked_asset_ids
        else []
    )
    original_assets_by_id = {
        row.id: row for row in linked_assets if row.organization_id == organization_id
    }
    source_keys = {(alert.provider, alert.external_id, cve) for alert, _, cve, _ in fingerprinted}
    ids_by_provider: dict[str, set[str]] = {}
    for provider, external_id, _ in source_keys:
        ids_by_provider.setdefault(provider, set()).add(external_id)
    found_observations = (
        (
            await session.execute(
                select(FindingObservation).where(
                    FindingObservation.organization_id == organization_id,
                    or_(
                        *(
                            and_(
                                FindingObservation.provider == provider,
                                pg_any(FindingObservation.external_id, external_ids),
                            )
                            for provider, external_ids in ids_by_provider.items()
                        )
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    observations = {(row.provider, row.external_id, row.cve_id): row for row in found_observations}
    moved_from_ids: set[uuid.UUID] = set()
    created_finding_ids: set[uuid.UUID] = set()
    status_changed_finding_ids: set[uuid.UUID] = set()
    current_cves: dict[tuple[str, str], set[str]] = {}
    for alert, _ in prepared:
        cves = valid_cves(alert.cve_ids or [])
        current_cves.setdefault((alert.provider, alert.external_id), set()).update(cves or [""])
    for prior_observation in found_observations:
        current_cve_set = current_cves.get(
            (prior_observation.provider, prior_observation.external_id)
        )
        if current_cve_set is not None and prior_observation.cve_id not in current_cve_set:
            prior_observation.source_status = "superseded"
            moved_from_ids.add(prior_observation.canonical_finding_id)

    for alert, asset, cve, fingerprint in fingerprinted:
        finding = findings.get(fingerprint)
        if finding is None:
            finding = CanonicalFinding(
                id=uuid.uuid4(),
                organization_id=organization_id,
                asset_id=asset.id,
                fingerprint=fingerprint,
                title=alert.title[:1000],
                severity=alert.severity,
                status="new",
                cve_ids=[cve] if cve else [],
                first_seen_at=now,
                last_seen_at=now,
                due_at=calculate_due_at(
                    Severity(alert.severity), asset.criticality, opened_at=now, targets=sla_targets
                ),
                absence_count=0,
                status_version=0,
            )
            session.add(finding)
            findings[fingerprint] = finding
            created_finding_ids.add(finding.id)
            session.add(
                FindingHistory(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    canonical_finding_id=finding.id,
                    previous_status=None,
                    new_status="new",
                    reason="First source observation",
                    occurred_at=now,
                )
            )
        elif _SEVERITY_RANK.get(alert.severity, 0) > _SEVERITY_RANK.get(finding.severity, 0):
            finding.severity = alert.severity
            finding.title = alert.title[:1000]
            finding.due_at = calculate_due_at(
                Severity(alert.severity), asset.criticality, opened_at=finding.first_seen_at, targets=sla_targets
            )
        if finding.asset_id != asset.id:
            old_asset = original_assets_by_id.get(finding.asset_id)
            identity = alert_asset_identity(alert)
            if (
                old_asset is not None
                and identity is not None
                and old_asset.name == asset_storage_name(*identity)
                and asset.name != old_asset.name
            ):
                finding.asset_id = asset.id
        finding.last_seen_at = now
        finding.absence_count = 0
        finding.cve_ids = [cve] if cve else []

        key = (alert.provider, alert.external_id, cve)
        source_observation = observations.get(key)
        if source_observation is None:
            source_observation = FindingObservation(
                id=uuid.uuid4(),
                organization_id=organization_id,
                canonical_finding_id=finding.id,
                provider=alert.provider,
                external_id=alert.external_id,
                cve_id=cve,
                first_seen_at=now,
                title=alert.title[:1000],
                severity=alert.severity,
                source_status=alert.status,
                last_seen_at=now,
                missing_sync_count=0,
                evidence=dict(alert.evidence or {}),
                source_url=alert.source_url,
                source_record_id=alert.id,
            )
            session.add(source_observation)
            observations[key] = source_observation
        else:
            if source_observation.canonical_finding_id != finding.id:
                moved_from_ids.add(source_observation.canonical_finding_id)
            source_observation.canonical_finding_id = finding.id
            source_observation.source_status = alert.status
            source_observation.last_seen_at = now
            source_observation.missing_sync_count = 0
            source_observation.title = alert.title[:1000]
            source_observation.severity = alert.severity
            source_observation.evidence = dict(alert.evidence or {})
            source_observation.source_url = alert.source_url
            source_observation.source_record_id = alert.id

    await session.flush()
    affected_ids = {item.id for item in findings.values()} | moved_from_ids
    old_findings = (
        (
            await session.execute(
                select(CanonicalFinding)
                .where(
                    CanonicalFinding.organization_id == organization_id,
                    pg_any(CanonicalFinding.id, moved_from_ids),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
        if moved_from_ids
        else []
    )
    affected_findings = {item.id: item for item in [*findings.values(), *old_findings]}
    all_observations = (
        (
            await session.execute(
                select(FindingObservation).where(
                    FindingObservation.organization_id == organization_id,
                    pg_any(FindingObservation.canonical_finding_id, affected_ids),
                )
            )
        )
        .scalars()
        .all()
    )
    states: dict[uuid.UUID, list[str]] = {}
    evidence_by_finding: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for observation in all_observations:
        states.setdefault(observation.canonical_finding_id, []).append(observation.source_status)
        if observation.source_status not in {"absent", "superseded"}:
            evidence_by_finding.setdefault(observation.canonical_finding_id, []).append(
                observation.evidence or {}
            )
    asset_ids = {item.asset_id for item in affected_findings.values()}
    scored_assets = (
        (
            await session.execute(
                select(Asset).where(
                    Asset.organization_id == organization_id, pg_any(Asset.id, asset_ids)
                )
            )
        )
        .scalars()
        .all()
    )
    asset_by_id = {item.id: item for item in scored_assets}
    weights = load_policy(organization).risk_weights
    for finding in affected_findings.values():
        source_states = states.get(finding.id, [])
        active_source_states = [
            state for state in source_states if state not in {"absent", "superseded"}
        ]
        # A source explicitly reassigned to a different asset/fingerprint is positive
        # evidence that the former canonical record no longer owns that observation.
        # This differs from a missing item in a provider feed, which requires two
        # complete scans before closure.
        orphaned_by_move = finding.id in moved_from_ids and not active_source_states
        proposed = next_status(
            finding.status,
            source_states,
            complete=True,
            consecutive_absences=2 if orphaned_by_move else 0,
        )
        if proposed != finding.status:
            prior = finding.status
            finding.status = proposed
            finding.status_version += 1
            status_changed_finding_ids.add(finding.id)
            finding.closed_at = now if proposed == "closed" else None
            session.add(
                FindingHistory(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    canonical_finding_id=finding.id,
                    previous_status=prior,
                    new_status=proposed,
                    reason="Source identity or CVE mapping changed"
                    if orphaned_by_move
                    else "Source observation changed",
                    occurred_at=now,
                )
            )
        if finding.status != "closed" and finding.asset_id in asset_by_id:
            finding.risk_score, finding.risk_factors = score_canonical(
                finding.severity,
                asset_by_id[finding.asset_id],
                [
                    *evidence_by_finding.get(finding.id, []),
                    *verified_intel_evidence(finding.intel_evidence or {}),
                ],
                weights,
            )
            finding.risk_factors = with_stale_intel_provenance(
                finding.risk_factors, finding.intel_evidence or {}
            )
            finding.risk_policy_version = organization.risk_policy_version or 0
    for finding_id in created_finding_ids:
        finding = affected_findings.get(finding_id)
        asset = asset_by_id.get(finding.asset_id) if finding is not None else None
        if finding is not None and asset is not None:
            await queue_finding_event(
                session, finding=finding, asset=asset, trigger="finding.created"
            )
    for finding_id in status_changed_finding_ids - created_finding_ids:
        finding = affected_findings.get(finding_id)
        asset = asset_by_id.get(finding.asset_id) if finding is not None else None
        if finding is not None and asset is not None:
            await queue_finding_event(
                session,
                finding=finding,
                asset=asset,
                trigger="finding.updated",
                event_key_suffix=f":version:{finding.status_version}",
            )
    count = len(fingerprinted)
    if count > 0:
        from app.services.usage_metering import MeterEvent, increment

        await increment(
            session,
            organization_id=organization_id,
            event=MeterEvent.FINDING_INGESTED,
            quantity=count,
        )
    return count


async def ingest_native_findings(
    session: AsyncSession, organization_id: uuid.UUID, findings: list[Any]
) -> int:
    """Project DefectDojo imports onto the same tenant-owned canonical model."""
    asset_ids = {finding.asset_id for finding in findings if finding.asset_id is not None}
    assets = (
        (
            await session.execute(
                select(Asset).where(
                    Asset.organization_id == organization_id, pg_any(Asset.id, asset_ids)
                )
            )
        )
        .scalars()
        .all()
        if asset_ids
        else []
    )
    by_id = {asset.id: asset for asset in assets}
    projections: list[Any] = []
    overrides: dict[tuple[str, str], Asset] = {}
    for finding in findings:
        if finding.organization_id != organization_id:
            raise ValueError("cross-tenant native finding passed to canonical ingestion")
        asset = by_id.get(finding.asset_id)
        if asset is not None:
            kind, value = normalized_asset_identity(asset.asset_type, asset.name)
            overrides[(kind, value)] = asset
        else:
            identity = _identity_from_endpoint(finding.endpoint)
            if identity is None:
                continue
            kind, value = identity
        state = {
            "active": "open",
            "verified": "open",
            "mitigated": "fixed",
            "false_positive": "false_positive",
            "risk_accepted": "accepted_risk",
            "out_of_scope": "dismissed",
            "duplicate": "dismissed",
        }.get(finding.status, finding.status)
        native_inputs = (getattr(finding, "risk_factors", None) or {}).get("inputs", {})
        if not isinstance(native_inputs, dict):
            native_inputs = {}
        evidence = {
            "asset_type": kind,
            "asset_value": value,
            "cvss_score": getattr(finding, "cvss_score", None),
            "in_kev": native_inputs.get("in_kev"),
            "epss_score": native_inputs.get("epss_score"),
            "ransomware_use": native_inputs.get("ransomware_campaign_use"),
        }
        projections.append(
            SimpleNamespace(
                id=finding.id,
                organization_id=organization_id,
                provider="defectdojo",
                external_id=str(finding.defectdojo_finding_id),
                resource=asset.name if asset is not None else finding.endpoint,
                evidence=evidence,
                cve_ids=finding.cve_ids or [],
                title=finding.title,
                severity=finding.severity,
                status=state,
                source_url=None,
            )
        )
    return await ingest_external_alerts(
        session, organization_id, projections, asset_overrides=overrides
    )


def _identity_from_endpoint(endpoint: str | None) -> tuple[str, str] | None:
    raw = (endpoint or "").strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname
        if host is None:
            return None
        try:
            ipaddress.ip_address(host)
            return normalized_asset_identity("ip", host)
        except ValueError:
            return normalized_asset_identity("domain", host)
    except ValueError:
        return None


async def reconcile_absent_observations(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    provider: str,
    scope_keys: list[str],
    observed_external_ids: list[str],
) -> int:
    """Close only after two complete, scoped misses by a trustworthy source.

    The caller invokes this exclusively after its provider returned a complete
    result for all ``scope_keys``. GitHub/GitLab do not use this path because
    reduced provider permissions can look like a successful empty result.
    """
    # A scope is the proof that a provider returned a complete view of a bounded
    # source.  Do not make absence global: a credential with reduced visibility
    # must never close unrelated findings.
    scope_field = {
        "sonarqube": "project",
        "tenable": "scan_id",
        "qualys": "asset_value",
        "rapid7": "asset_id",
        "crowdstrike": "provider",
        "aws_security_hub": "account_id",
        "aws_inspector": "aws_account_id",
        "hackerone": "program_handle",
        "bugcrowd": "engagement_code",
        "checkmarx": "project_id",
        "fortify": "application_version_id",
        "prisma_cloud": "cloud_account_id",
        "azure_defender": "subscription_id",
        "gcp_scc": "project_id",
        "burp_dast": "site_id",
    }.get(provider)
    if scope_field is None:
        raise ValueError("provider does not support absence-based closure")
    if not scope_keys:
        return 0
    statement = select(FindingObservation).where(
        FindingObservation.organization_id == organization_id,
        FindingObservation.provider == provider,
        pg_any(FindingObservation.evidence[scope_field].astext, scope_keys),
        FindingObservation.source_status.not_in(("absent", "superseded")),
    )
    if observed_external_ids:
        statement = statement.where(~pg_any(FindingObservation.external_id, observed_external_ids))
    missing = (await session.execute(statement.with_for_update())).scalars().all()
    if not missing:
        return 0
    affected = {observation.canonical_finding_id for observation in missing}
    newly_absent: set[uuid.UUID] = set()
    for observation in missing:
        observation.missing_sync_count += 1
        if observation.missing_sync_count >= 2:
            observation.source_status = "absent"
            newly_absent.add(observation.canonical_finding_id)
    await session.flush()
    all_observations = (
        (
            await session.execute(
                select(FindingObservation).where(
                    FindingObservation.organization_id == organization_id,
                    pg_any(FindingObservation.canonical_finding_id, affected),
                )
            )
        )
        .scalars()
        .all()
    )
    by_finding: dict[uuid.UUID, list[FindingObservation]] = {}
    for observation in all_observations:
        by_finding.setdefault(observation.canonical_finding_id, []).append(observation)
    findings = (
        (
            await session.execute(
                select(CanonicalFinding)
                .where(
                    CanonicalFinding.organization_id == organization_id,
                    pg_any(CanonicalFinding.id, affected),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    now = utcnow()
    status_changed_findings: list[CanonicalFinding] = []
    for finding in findings:
        sources = by_finding.get(finding.id, [])
        absence_count = (
            min((item.missing_sync_count for item in sources), default=0)
            if sources and all(item.source_status == "absent" for item in sources)
            else 0
        )
        finding.absence_count = absence_count
        proposed = next_status(
            finding.status,
            [item.source_status for item in sources],
            complete=True,
            consecutive_absences=absence_count,
        )
        if proposed != finding.status:
            previous = finding.status
            finding.status = proposed
            finding.status_version += 1
            status_changed_findings.append(finding)
            finding.closed_at = now if proposed == "closed" else None
            session.add(
                FindingHistory(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    canonical_finding_id=finding.id,
                    previous_status=previous,
                    new_status=proposed,
                    reason="Absent from two complete scoped scans",
                    occurred_at=now,
                )
            )
    to_rescore = [
        finding for finding in findings if finding.id in newly_absent and finding.status != "closed"
    ]
    if to_rescore:
        asset_ids = {finding.asset_id for finding in to_rescore}
        assets = (
            (
                await session.execute(
                    select(Asset).where(
                        Asset.organization_id == organization_id, pg_any(Asset.id, asset_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        asset_by_id = {asset.id: asset for asset in assets}
        organization = (
            await session.execute(select(Organization).where(Organization.id == organization_id))
        ).scalar_one()
        weights = load_policy(organization).risk_weights
        for finding in to_rescore:
            asset = asset_by_id.get(finding.asset_id)
            if asset is None:
                continue
            evidences = [
                observation.evidence or {}
                for observation in by_finding.get(finding.id, [])
                if observation.source_status not in {"absent", "superseded"}
            ]
            finding.risk_score, finding.risk_factors = score_canonical(
                finding.severity,
                asset,
                [*evidences, *verified_intel_evidence(finding.intel_evidence or {})],
                weights,
            )
            finding.risk_factors = with_stale_intel_provenance(
                finding.risk_factors, finding.intel_evidence or {}
            )
            finding.risk_policy_version = organization.risk_policy_version
    if status_changed_findings:
        asset_ids = {finding.asset_id for finding in status_changed_findings}
        assets = (
            (
                await session.execute(
                    select(Asset).where(
                        Asset.organization_id == organization_id, pg_any(Asset.id, asset_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        assets_by_id = {asset.id: asset for asset in assets}
        for finding in status_changed_findings:
            asset = assets_by_id.get(finding.asset_id)
            if asset is not None:
                await queue_finding_event(
                    session,
                    finding=finding,
                    asset=asset,
                    trigger="finding.updated",
                    event_key_suffix=f":version:{finding.status_version}",
                )
    return len(missing)
