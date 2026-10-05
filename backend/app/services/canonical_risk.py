"""Deterministic canonical risk score with explicit missing-signal provenance."""

from __future__ import annotations

import math
from typing import Any

from app.db.enums import Criticality
from app.schemas.organization import RiskWeights

_SEVERITY_FALLBACK = {"critical": 38.0, "high": 29.0, "medium": 17.0, "low": 7.0, "info": 1.0}
_CRITICALITY_WEIGHT = {
    "critical": 1.0, "high": 0.75, "normal": 0.5, "low": 0.25, "unknown": 0.4,
}


def _bounded_number(value: Any, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, float | int):
        return None
    number = float(value)
    return number if math.isfinite(number) and 0 <= number <= maximum else None


def _tri_state(evidences: list[dict[str, Any]], key: str) -> bool | None:
    values = [item[key] for item in evidences if isinstance(item.get(key), bool)]
    if True in values:
        return True
    if values:
        return False
    return None


def score_canonical(
    severity: str,
    asset: Any,
    evidences: list[dict[str, Any]],
    weights: RiskWeights,
) -> tuple[float, dict[str, Any]]:
    """Score one exposure from verified normalized signals, retaining every input.

    Missing KEV/EPSS/ransomware data is explicitly unknown, never a negative
    assertion. Provider-specific raw payloads are not accepted as score signals.
    """
    cvss_values = [
        value for item in evidences
        if (value := _bounded_number(item.get("cvss_score"), 10.0)) is not None
    ]
    epss_values = [
        value for item in evidences
        if (value := _bounded_number(item.get("epss_score"), 1.0)) is not None
    ]
    cvss = max(cvss_values, default=None)
    epss = max(epss_values, default=None)
    in_kev = _tri_state(evidences, "in_kev")
    ransomware = _tri_state(evidences, "ransomware_use")
    criticality = str(getattr(asset, "criticality", "unknown") or "unknown")
    if criticality not in Criticality.values():
        criticality = "unknown"
    exposed = bool(getattr(asset, "internet_exposed", False))
    severity_points = cvss / 10.0 if cvss is not None else _SEVERITY_FALLBACK.get(severity, 1.0) / 45.0
    components = {
        "severity": round(weights.severity * severity_points, 2),
        "exploitation": weights.exploitation if in_kev is True else 0.0,
        "exploit_probability": round(weights.exploit_probability * epss, 2) if epss is not None else 0.0,
        "exposure": weights.exposure if exposed else 0.0,
        "asset_criticality": round(weights.asset_criticality * _CRITICALITY_WEIGHT[criticality], 2),
        "ransomware": weights.ransomware if ransomware is True else 0.0,
    }
    score = round(min(100.0, sum(components.values())), 2)
    factors = {
        "components": components,
        "weights": weights.model_dump(),
        "inputs": {
            "severity_label": severity, "cvss_score": cvss, "in_kev": in_kev,
            "epss_score": epss, "internet_exposed": exposed,
            "asset_criticality": criticality, "ransomware_use": ransomware,
        },
        "unavailable": [
            name for name, value in (
                ("cvss", cvss), ("kev", in_kev), ("epss", epss),
                ("ransomware", ransomware),
            ) if value is None
        ],
    }
    return score, factors
