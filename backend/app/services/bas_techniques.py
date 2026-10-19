"""Bounded, versioned breach-and-attack simulation technique catalog.

The catalog is deliberately code-defined. A campaign may select one of these
techniques, but it cannot supply an executable, image, URL, or command. This keeps
the BAS executor on the same allow-listed scanner path as normal assessments.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from app.core.errors import ApprovalRequiredError, InvalidTargetError
from app.core.targets import TargetType, classify
from app.db.enums import ScannerName
from app.db.models.assessment import Approval

CATALOG_VERSION = "2026.10.2"


@dataclass(frozen=True, slots=True)
class BasTechnique:
    key: str
    scenario: str
    title: str
    mitre_technique: str
    target_types: frozenset[TargetType]
    adapter: ScannerName
    risk_class: str
    approval_required: bool
    safe_action: str
    estimated_cost_usd: float
    timeout_seconds: int
    expected_evidence: tuple[str, ...]
    cleanup: str
    catalog_version: str = CATALOG_VERSION


_CATALOG: tuple[BasTechnique, ...] = (
    BasTechnique(
        key="external-service-discovery",
        scenario="external_exposure",
        title="External service discovery",
        mitre_technique="T1046",
        target_types=frozenset({TargetType.DOMAIN, TargetType.IP, TargetType.CIDR}),
        adapter=ScannerName.NMAP,
        risk_class="medium",
        approval_required=True,
        safe_action="passive_discovery",
        estimated_cost_usd=0.0,
        timeout_seconds=900,
        expected_evidence=("nmap_xml", "stdout"),
        cleanup="No target-side state is created.",
    ),
    BasTechnique(
        key="external-http-exposure",
        scenario="external_exposure",
        title="External HTTP exposure validation",
        mitre_technique="T1595.002",
        target_types=frozenset({TargetType.URL}),
        adapter=ScannerName.NUCLEI,
        risk_class="medium",
        approval_required=True,
        safe_action="safe_probe",
        estimated_cost_usd=0.0,
        timeout_seconds=1200,
        expected_evidence=("nuclei_jsonl", "stdout"),
        cleanup="Templates are non-destructive and create no persistent state.",
    ),
    BasTechnique(
        key="web-exposure-validation",
        scenario="web_attack_surface",
        title="Web exposure validation",
        mitre_technique="T1190",
        target_types=frozenset({TargetType.URL, TargetType.DOMAIN}),
        adapter=ScannerName.NUCLEI,
        risk_class="medium",
        approval_required=True,
        safe_action="safe_probe",
        estimated_cost_usd=0.0,
        timeout_seconds=1200,
        expected_evidence=("nuclei_jsonl", "stdout"),
        cleanup="Templates are non-destructive and create no persistent state.",
    ),
    BasTechnique(
        key="api-control-validation",
        scenario="api_authorization",
        title="API authorization control validation",
        mitre_technique="T1190",
        target_types=frozenset({TargetType.URL}),
        adapter=ScannerName.ZAP,
        risk_class="medium",
        approval_required=True,
        safe_action="non_destructive_validation",
        estimated_cost_usd=0.0,
        timeout_seconds=1200,
        expected_evidence=("zap_report", "stdout"),
        cleanup="Passive and bounded active checks create no accounts or data.",
    ),
    BasTechnique(
        key="repository-secret-exposure",
        scenario="credential_exposure",
        title="Repository credential exposure validation",
        mitre_technique="T1552.001",
        target_types=frozenset({TargetType.REPOSITORY}),
        adapter=ScannerName.GITLEAKS_REPO,
        risk_class="low",
        approval_required=True,
        safe_action="authenticated_read",
        estimated_cost_usd=0.0,
        timeout_seconds=900,
        expected_evidence=("gitleaks_report", "stdout"),
        cleanup="The transient checkout is deleted by the scanner worker.",
    ),
    *(
        BasTechnique(
            key=f"{provider}-cloud-control-validation",
            scenario="cloud_misconfiguration",
            title=f"{provider.upper()} cloud control validation",
            mitre_technique="T1526",
            target_types=frozenset({TargetType.CLOUD_ACCOUNT}),
            adapter=adapter,
            risk_class="low",
            approval_required=True,
            safe_action="authenticated_read",
            estimated_cost_usd=0.0,
            timeout_seconds=2400,
            expected_evidence=("prowler_report", "stdout"),
            cleanup="Read-only cloud API checks create no provider-side resources.",
        )
        for provider, adapter in (
            ("aws", ScannerName.PROWLER_AWS),
            ("azure", ScannerName.PROWLER_AZURE),
            ("gcp", ScannerName.PROWLER_GCP),
        )
    ),
)


def list_techniques() -> tuple[BasTechnique, ...]:
    return _CATALOG


def get_technique(scenario: str, target: str) -> BasTechnique:
    target_type = classify(target)
    candidates = [
        item
        for item in _CATALOG
        if item.scenario == scenario and target_type in item.target_types
    ]
    if target_type is TargetType.CLOUD_ACCOUNT:
        provider = target.split(":", 1)[0].casefold()
        candidates = [item for item in candidates if item.key.startswith(f"{provider}-")]
    if not candidates:
        raise InvalidTargetError(
            f"scenario {scenario!r} is incompatible with target {target!r}",
            user_message="This validation scenario cannot run against that target type.",
        )
    return candidates[0]


def require_technique_approval(
    technique: BasTechnique,
    approval: Approval | None,
    *,
    now: dt.datetime | None = None,
) -> None:
    if not technique.approval_required:
        return
    current = now or dt.datetime.now(dt.UTC)
    if (
        approval is None
        or not approval.is_granted
        or approval.resolved_by_id is None
        or (approval.expires_at is not None and approval.expires_at <= current)
    ):
        raise ApprovalRequiredError(
            "BAS technique requires a current human approval",
            context={"technique": technique.key, "risk_class": technique.risk_class},
        )


def classify_control_result(
    *,
    exit_code: int | None,
    artifact_ids: Sequence[uuid.UUID | str],
    blocked: bool = False,
) -> str:
    """Return only evidence-supportable outcomes.

    A clean process exit is operational evidence, not control evidence. At least
    one archived artifact is therefore required before claiming detection or
    prevention.
    """
    if exit_code not in (0, None):
        return "error"
    if not artifact_ids:
        return "inconclusive"
    return "prevented" if blocked else "detected"


def compare_run_outcomes(
    *, current: Mapping[str, str], baseline: Mapping[str, str]
) -> dict[str, list[str]]:
    regressions: list[str] = []
    improvements: list[str] = []
    unchanged: list[str] = []
    inconclusive: list[str] = []
    for key in sorted(set(current) | set(baseline)):
        before = baseline.get(key)
        after = current.get(key)
        if after in (None, "prevented") and before == "detected":
            improvements.append(key)
        elif before == "prevented" and after == "detected":
            regressions.append(key)
        elif after in ("inconclusive", "error"):
            inconclusive.append(key)
        elif after == before:
            unchanged.append(key)
    return {
        "regressions": regressions,
        "improvements": improvements,
        "unchanged": unchanged,
        "inconclusive": inconclusive,
    }
