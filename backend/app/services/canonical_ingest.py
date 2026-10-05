"""Map provider observations to the tenant-owned canonical inventory."""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingHistory, FindingObservation
from app.db.models.identity import Organization
from app.services.canonical_identity import (
    identity_for_observation,
    normalized_asset_identity,
    valid_cves,
)
from app.services.canonical_lifecycle import next_status
from app.services.canonical_risk import score_canonical
from app.services.entitlements import assert_asset_capacity, load_entitlements
from app.services.organization import load_policy

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def asset_storage_name(kind: str, value: str) -> str:
    """Store long provider identifiers without truncation collisions."""
    name = f"{kind}:{value}"
    if len(name) <= 512:
        return name
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"{kind}:sha256:{digest}"


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
    return None


async def ingest_external_alerts(
    session: AsyncSession, organization_id: uuid.UUID, alerts: list[Any],
    *, asset_overrides: dict[tuple[str, str], Asset] | None = None,
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

    organization = (
        await session.execute(
            select(Organization).where(Organization.id == organization_id).with_for_update()
        )
    ).scalar_one()
    overrides = asset_overrides or {}
    names = {
        asset_storage_name(kind, value)
        for _, (kind, value) in prepared
        if (kind, value) not in overrides
    }
    existing_assets = (
        await session.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.name.in_(names),
                Asset.port.is_(None),
                Asset.protocol.is_(None),
            )
        )
    ).scalars().all()
    assets = {asset.name: asset for asset in existing_assets}
    new_asset_names = names - set(assets)
    if new_asset_names:
        current_count = (
            await session.execute(
                select(func.count()).select_from(Asset).where(Asset.organization_id == organization_id)
            )
        ).scalar_one()
        assert_asset_capacity(
            current_assets=int(current_count),
            new_assets=len(new_asset_names),
            entitlements=load_entitlements(organization.entitlements),
        )
    now = utcnow()
    for name in sorted(new_asset_names):
        kind, _, _ = name.partition(":")
        asset = Asset(
            id=uuid.uuid4(), organization_id=organization_id, name=name,
            asset_type=kind, status="active", first_seen_at=now, last_seen_at=now,
            criticality="unknown", criticality_source="default", risk_score=0.0,
            evidence={"identity_source": "external_security_alert"},
            seen_in_assessments=[], technology=[],
        )
        session.add(asset)
        assets[name] = asset

    asset_for_key = {
        (kind, value): overrides.get((kind, value)) or assets[asset_storage_name(kind, value)]
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
        await session.execute(
            select(CanonicalFinding).where(
                CanonicalFinding.organization_id == organization_id,
                CanonicalFinding.fingerprint.in_(fingerprints),
            )
        )
    ).scalars().all()
    findings = {finding.fingerprint: finding for finding in found}
    source_keys = {(alert.provider, alert.external_id, cve) for alert, _, cve, _ in fingerprinted}
    found_observations = (
        await session.execute(
            select(FindingObservation).where(
                FindingObservation.organization_id == organization_id,
                tuple_(FindingObservation.provider, FindingObservation.external_id).in_(
                    {(provider, external_id) for provider, external_id, _ in source_keys}
                ),
            )
        )
    ).scalars().all()
    observations = {(row.provider, row.external_id, row.cve_id): row for row in found_observations}
    moved_from_ids: set[uuid.UUID] = set()
    current_cves: dict[tuple[str, str], set[str]] = {}
    for alert, _ in prepared:
        cves = valid_cves(alert.cve_ids or [])
        if cves:
            current_cves.setdefault((alert.provider, alert.external_id), set()).update(cves)
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
                id=uuid.uuid4(), organization_id=organization_id, asset_id=asset.id,
                fingerprint=fingerprint, title=alert.title[:1000], severity=alert.severity,
                status="new", cve_ids=[cve] if cve else [],
                first_seen_at=now, last_seen_at=now, absence_count=0, status_version=0,
            )
            session.add(finding)
            findings[fingerprint] = finding
            session.add(FindingHistory(
                id=uuid.uuid4(), organization_id=organization_id,
                canonical_finding_id=finding.id, previous_status=None,
                new_status="new", reason="First source observation", occurred_at=now,
            ))
        elif _SEVERITY_RANK.get(alert.severity, 0) > _SEVERITY_RANK.get(finding.severity, 0):
            finding.severity = alert.severity
            finding.title = alert.title[:1000]
        finding.last_seen_at = now
        finding.absence_count = 0
        finding.cve_ids = [cve] if cve else []

        key = (alert.provider, alert.external_id, cve)
        source_observation = observations.get(key)
        if source_observation is None:
            source_observation = FindingObservation(
                id=uuid.uuid4(), organization_id=organization_id,
                canonical_finding_id=finding.id, provider=alert.provider,
                external_id=alert.external_id, cve_id=cve, first_seen_at=now,
                title=alert.title[:1000], severity=alert.severity,
                source_status=alert.status, last_seen_at=now,
                missing_sync_count=0, evidence=dict(alert.evidence or {}),
                source_url=alert.source_url, source_record_id=alert.id,
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
        (await session.execute(
            select(CanonicalFinding).where(
                CanonicalFinding.organization_id == organization_id,
                CanonicalFinding.id.in_(moved_from_ids),
            ).with_for_update()
        )).scalars().all()
        if moved_from_ids else []
    )
    affected_findings = {item.id: item for item in [*findings.values(), *old_findings]}
    all_observations = (
        await session.execute(
            select(FindingObservation).where(
                FindingObservation.organization_id == organization_id,
                FindingObservation.canonical_finding_id.in_(affected_ids),
            )
        )
    ).scalars().all()
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
        await session.execute(
            select(Asset).where(Asset.organization_id == organization_id, Asset.id.in_(asset_ids))
        )
    ).scalars().all()
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
            finding.status, source_states,
            complete=True, consecutive_absences=2 if orphaned_by_move else 0,
        )
        if proposed != finding.status:
            prior = finding.status
            finding.status = proposed
            finding.status_version += 1
            finding.closed_at = now if proposed == "closed" else None
            session.add(FindingHistory(
                id=uuid.uuid4(), organization_id=organization_id,
                canonical_finding_id=finding.id, previous_status=prior,
                new_status=proposed,
                reason="Source identity or CVE mapping changed" if orphaned_by_move
                else "Source observation changed",
                occurred_at=now,
            ))
        if finding.status != "closed" and finding.asset_id in asset_by_id:
            finding.risk_score, finding.risk_factors = score_canonical(
                finding.severity,
                asset_by_id[finding.asset_id],
                evidence_by_finding.get(finding.id, []),
                weights,
            )
            finding.risk_policy_version = organization.risk_policy_version or 0
    return len(fingerprinted)


async def ingest_native_findings(
    session: AsyncSession, organization_id: uuid.UUID, findings: list[Any]
) -> int:
    """Project DefectDojo imports onto the same tenant-owned canonical model."""
    asset_ids = {finding.asset_id for finding in findings if finding.asset_id is not None}
    assets = (
        (await session.execute(
            select(Asset).where(Asset.organization_id == organization_id, Asset.id.in_(asset_ids))
        )).scalars().all()
        if asset_ids else []
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
            "active": "open", "verified": "open", "mitigated": "fixed",
            "false_positive": "false_positive", "risk_accepted": "accepted_risk",
            "out_of_scope": "dismissed", "duplicate": "dismissed",
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
        projections.append(SimpleNamespace(
            id=finding.id, organization_id=organization_id,
            provider="defectdojo", external_id=str(finding.defectdojo_finding_id),
            resource=asset.name if asset is not None else finding.endpoint,
            evidence=evidence,
            cve_ids=finding.cve_ids or [], title=finding.title,
            severity=finding.severity, status=state, source_url=None,
        ))
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
    scope_field = {"sonarqube": "project", "tenable": "scan_id"}.get(provider)
    if scope_field is None:
        raise ValueError("provider does not support absence-based closure")
    if not scope_keys:
        return 0
    statement = select(FindingObservation).where(
        FindingObservation.organization_id == organization_id,
        FindingObservation.provider == provider,
        FindingObservation.evidence[scope_field].astext.in_(scope_keys),
        FindingObservation.source_status.not_in(("absent", "superseded")),
    )
    if observed_external_ids:
        statement = statement.where(FindingObservation.external_id.not_in(observed_external_ids))
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
    all_observations = (await session.execute(
        select(FindingObservation).where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.canonical_finding_id.in_(affected),
        )
    )).scalars().all()
    by_finding: dict[uuid.UUID, list[FindingObservation]] = {}
    for observation in all_observations:
        by_finding.setdefault(observation.canonical_finding_id, []).append(observation)
    findings = (await session.execute(
        select(CanonicalFinding).where(
            CanonicalFinding.organization_id == organization_id,
            CanonicalFinding.id.in_(affected),
        ).with_for_update()
    )).scalars().all()
    now = utcnow()
    for finding in findings:
        sources = by_finding.get(finding.id, [])
        absence_count = min(
            (item.missing_sync_count for item in sources), default=0
        ) if sources and all(item.source_status == "absent" for item in sources) else 0
        finding.absence_count = absence_count
        proposed = next_status(
            finding.status, [item.source_status for item in sources],
            complete=True, consecutive_absences=absence_count,
        )
        if proposed != finding.status:
            previous = finding.status
            finding.status = proposed
            finding.status_version += 1
            finding.closed_at = now if proposed == "closed" else None
            session.add(FindingHistory(
                id=uuid.uuid4(), organization_id=organization_id,
                canonical_finding_id=finding.id, previous_status=previous,
                new_status=proposed, reason="Absent from two complete scoped scans",
                occurred_at=now,
            ))
    to_rescore = [
        finding for finding in findings
        if finding.id in newly_absent and finding.status != "closed"
    ]
    if to_rescore:
        asset_ids = {finding.asset_id for finding in to_rescore}
        assets = (await session.execute(
            select(Asset).where(Asset.organization_id == organization_id, Asset.id.in_(asset_ids))
        )).scalars().all()
        asset_by_id = {asset.id: asset for asset in assets}
        organization = (await session.execute(
            select(Organization).where(Organization.id == organization_id)
        )).scalar_one()
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
                finding.severity, asset, evidences, weights,
            )
            finding.risk_policy_version = organization.risk_policy_version
    return len(missing)
