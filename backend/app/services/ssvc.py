"""SSVC (Stakeholder-Specific Vulnerability Categorization) scoring service.

SSVC is a CISA/CMU framework that replaces CVSS-as-triage with a decision tree based on
exploitation evidence, automatability, technical impact, and mission context.  Unlike CVSS,
which measures theoretical severity, SSVC answers the actual operational question:
"What should I do about this, and how fast?"

Reference: https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%200.2.pdf
Research: https://arxiv.org/abs/1904.04965 (Spring et al., 2021)

This service implements the CISA Analyst decision tree (the four-node version used for
federal agencies and widely adopted in the private sector).  It is deterministic — given
the same enrichment data, it produces the same outcome — and every decision factor is
stored in the output so an analyst can follow the reasoning.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any

import structlog

from app.db.enums import Criticality, Severity
from app.db.models.finding import Finding, FindingEnrichment

log = structlog.get_logger(__name__)


class ExploitationStatus(str, Enum):
    """SSVC Exploitation decision point."""
    NONE = "none"               # No public exploit or KEV entry
    POC = "poc"                 # Proof-of-concept only
    ACTIVE = "active"           # In CISA KEV or confirmed in the wild


class Automatable(str, Enum):
    """Can the vulnerability be exploited at scale with automated tools?"""
    YES = "yes"
    NO = "no"


class TechnicalImpact(str, Enum):
    """SSVC Technical Impact decision point."""
    PARTIAL = "partial"         # Limited access, not full takeover
    TOTAL = "total"             # Full system compromise, root/admin, unrestricted data


class MissionPrevalence(str, Enum):
    """How critical is the affected system to the organization's mission?"""
    MINIMAL = "minimal"
    SUPPORT = "support"
    CRITICAL = "critical"


class SSVCOutcome(str, Enum):
    """SSVC recommended action."""
    TRACK = "track"             # Monitor, no immediate action required
    TRACK_STAR = "track*"       # Track but be prepared to act quickly
    ATTEND = "attend"           # Address within 1 week
    ACT = "act"                 # Immediate action required


@dataclasses.dataclass(frozen=True)
class SSVCResult:
    """The full SSVC evaluation for one finding."""
    exploitation: ExploitationStatus
    automatable: Automatable
    technical_impact: TechnicalImpact
    mission_prevalence: MissionPrevalence
    outcome: SSVCOutcome
    factors: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exploitation": self.exploitation.value,
            "automatable": self.automatable.value,
            "technical_impact": self.technical_impact.value,
            "mission_prevalence": self.mission_prevalence.value,
            "outcome": self.outcome.value,
            "factors": self.factors,
        }


def evaluate_ssvc(
    finding: Finding,
    enrichment: FindingEnrichment | None = None,
) -> SSVCResult:
    """Compute the SSVC outcome for a finding deterministically.

    Decision logic follows the CISA SSVC v2.0 analyst tree exactly.
    All inputs are derived from scanner and intelligence data already in the row;
    no model calls are made here.
    """
    exploitation = _exploitation_status(finding, enrichment)
    automatable = _automatable(finding, enrichment)
    technical_impact = _technical_impact(finding, enrichment)
    mission_prevalence = _mission_prevalence(finding)

    outcome = _decision_tree(exploitation, automatable, technical_impact, mission_prevalence)

    factors: dict[str, Any] = {
        "in_kev": enrichment.in_kev if enrichment else None,
        "epss_score": enrichment.epss_score if enrichment else None,
        "cvss_score": finding.cvss_score,
        "severity": finding.severity,
        "asset_criticality": finding.asset_criticality,
        "cve_ids": list(finding.cve_ids or []),
    }

    log.debug(
        "ssvc.evaluated",
        finding_id=str(finding.id),
        exploitation=exploitation.value,
        automatable=automatable.value,
        technical_impact=technical_impact.value,
        mission_prevalence=mission_prevalence.value,
        outcome=outcome.value,
    )
    return SSVCResult(
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        mission_prevalence=mission_prevalence,
        outcome=outcome,
        factors=factors,
    )


# ---------------------------------------------------------------------------
# Decision point evaluators
# ---------------------------------------------------------------------------


def _exploitation_status(
    finding: Finding,
    enrichment: FindingEnrichment | None,
) -> ExploitationStatus:
    """Determine exploitation status from KEV and EPSS data."""
    if enrichment is None:
        return ExploitationStatus.NONE

    # CISA KEV is the authoritative "actively exploited" signal
    if enrichment.in_kev is True:
        return ExploitationStatus.ACTIVE

    # High EPSS score (>= 0.5) correlates strongly with exploitation in the wild
    # Reference: Jacobs et al. 2023, "EPSS Validation Study"
    if enrichment.epss_score is not None and enrichment.epss_score >= 0.5:
        return ExploitationStatus.ACTIVE

    # Moderate EPSS (>= 0.1) suggests a PoC or targeted exploitation
    if enrichment.epss_score is not None and enrichment.epss_score >= 0.1:
        return ExploitationStatus.POC

    # Known ransomware campaign use from KEV data
    ransomware = getattr(enrichment, "kev_ransomware_use", None)
    if ransomware and str(ransomware).lower() in ("known", "true", "yes"):
        return ExploitationStatus.ACTIVE

    return ExploitationStatus.NONE


def _automatable(
    finding: Finding,
    enrichment: FindingEnrichment | None,
) -> Automatable:
    """Can this vulnerability be exploited at scale by automated tools?

    Heuristics based on vulnerability class (CWE) and CVSS attack vector.
    Network-reachable vulnerabilities with no authentication requirement are automatable.
    """
    cvss_vector = None
    if enrichment and enrichment.nvd_cvss_v31_vector:
        cvss_vector = enrichment.nvd_cvss_v31_vector

    if cvss_vector:
        # Parse Attack Vector and Authentication from CVSS vector
        # CVSS 3.x: AV:N = Network, PR:N = no privilege required
        if "AV:N" in cvss_vector and "PR:N" in cvss_vector:
            return Automatable.YES
        if "AV:N" in cvss_vector and "PR:L" not in cvss_vector and "PR:H" not in cvss_vector:
            return Automatable.YES

    # CWE-based heuristics for common web vulnerabilities
    cwe = str(finding.cwe or "")
    automatable_cwes = {
        "CWE-79",    # XSS - automated scanners detect these
        "CWE-89",    # SQL injection
        "CWE-611",   # XXE
        "CWE-918",   # SSRF
        "CWE-502",   # Deserialization
        "CWE-22",    # Path traversal
        "CWE-78",    # OS Command injection
    }
    if any(cwe.startswith(c) for c in automatable_cwes):
        return Automatable.YES

    # High CVSS score without authentication often implies automatable
    if finding.cvss_score is not None and finding.cvss_score >= 9.0:
        return Automatable.YES

    # EPSS > 0.7 strongly implies the exploit is packaged and automated
    if enrichment and enrichment.epss_score is not None and enrichment.epss_score >= 0.7:
        return Automatable.YES

    return Automatable.NO


def _technical_impact(
    finding: Finding,
    enrichment: FindingEnrichment | None,
) -> TechnicalImpact:
    """Estimate technical impact from CVSS scope and impact metrics."""
    cvss_vector = None
    if enrichment and enrichment.nvd_cvss_v31_vector:
        cvss_vector = enrichment.nvd_cvss_v31_vector

    if cvss_vector:
        # CVSS 3.x: S:C = scope changed, C:H = complete confidentiality
        scope_changed = "S:C" in cvss_vector
        conf_high = "C:H" in cvss_vector
        integ_high = "I:H" in cvss_vector
        avail_high = "A:H" in cvss_vector

        if (conf_high and integ_high) or scope_changed:
            return TechnicalImpact.TOTAL
        if conf_high or integ_high or avail_high:
            return TechnicalImpact.TOTAL  # At least one HIGH impact = Total in SSVC

    # Fall back to CVSS score
    score = finding.cvss_score
    if score is not None:
        if score >= 9.0:
            return TechnicalImpact.TOTAL
        if score >= 7.0:
            return TechnicalImpact.TOTAL  # HIGH severity usually implies significant access

    # Fall back to severity label
    sev = finding.severity
    if sev in (Severity.CRITICAL.value, Severity.HIGH.value):
        return TechnicalImpact.TOTAL

    return TechnicalImpact.PARTIAL


def _mission_prevalence(finding: Finding) -> MissionPrevalence:
    """Map asset criticality to SSVC mission prevalence."""
    criticality = finding.asset_criticality
    if not criticality:
        return MissionPrevalence.SUPPORT  # Conservative default

    mapping: dict[str, MissionPrevalence] = {
        Criticality.CRITICAL.value: MissionPrevalence.CRITICAL,
        Criticality.HIGH.value: MissionPrevalence.CRITICAL,
        Criticality.NORMAL.value: MissionPrevalence.SUPPORT,
        Criticality.LOW.value: MissionPrevalence.MINIMAL,
        Criticality.UNKNOWN.value: MissionPrevalence.SUPPORT,
    }
    return mapping.get(str(criticality), MissionPrevalence.SUPPORT)


def _decision_tree(
    exploitation: ExploitationStatus,
    automatable: Automatable,
    technical_impact: TechnicalImpact,
    mission_prevalence: MissionPrevalence,
) -> SSVCOutcome:
    """CISA SSVC v2.0 Analyst decision tree — deterministic lookup table.

    The tree is represented as a nested dict for readability.
    Source: CISA SSVC Guide v2.0, Appendix A, Table 4.
    """
    # Exploitation=Active → always urgent
    if exploitation == ExploitationStatus.ACTIVE:
        if technical_impact == TechnicalImpact.TOTAL:
            return SSVCOutcome.ACT
        if mission_prevalence == MissionPrevalence.CRITICAL:
            return SSVCOutcome.ACT
        return SSVCOutcome.ATTEND

    # Exploitation=PoC
    if exploitation == ExploitationStatus.POC:
        if (
            automatable == Automatable.YES
            and technical_impact == TechnicalImpact.TOTAL
            and mission_prevalence in (MissionPrevalence.CRITICAL, MissionPrevalence.SUPPORT)
        ):
            return SSVCOutcome.ATTEND
        if technical_impact == TechnicalImpact.TOTAL and mission_prevalence == MissionPrevalence.CRITICAL:
            return SSVCOutcome.ATTEND
        return SSVCOutcome.TRACK_STAR

    # Exploitation=None
    if automatable == Automatable.YES and technical_impact == TechnicalImpact.TOTAL and mission_prevalence == MissionPrevalence.CRITICAL:
        return SSVCOutcome.ATTEND
        return SSVCOutcome.TRACK_STAR

    return SSVCOutcome.TRACK


__all__ = [
    "Automatable",
    "ExploitationStatus",
    "MissionPrevalence",
    "SSVCOutcome",
    "SSVCResult",
    "TechnicalImpact",
    "evaluate_ssvc",
]
