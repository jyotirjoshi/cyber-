"""The scanner registry.

One place that maps a :class:`~app.db.enums.ScannerName` to its adapter, so nothing else in
Cynux imports a scanner module directly.  The agent selects a *scanner name* from a fixed
vocabulary (FR-035) and this is where that name becomes executable behaviour -- which means a
name the agent invents fails here, loudly, rather than somewhere closer to the Docker API.

The completeness assertion at import time is deliberate: adding a value to ``ScannerName``
without an adapter would otherwise fail at the moment a user's assessment tried to run it.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import AssessmentDepth, ScannerName
from app.scanners.base import ScannerAdapter
from app.scanners.nmap import ADAPTER as NMAP_ADAPTER
from app.scanners.nuclei import ADAPTER as NUCLEI_ADAPTER
from app.scanners.reconftw import ADAPTER as RECONFTW_ADAPTER
from app.scanners.zap import ADAPTER as ZAP_ADAPTER

ALL_ADAPTERS: Mapping[ScannerName, ScannerAdapter] = MappingProxyType(
    {
        ScannerName.RECONFTW: RECONFTW_ADAPTER,
        ScannerName.NMAP: NMAP_ADAPTER,
        ScannerName.NUCLEI: NUCLEI_ADAPTER,
        ScannerName.ZAP: ZAP_ADAPTER,
    }
)

#: Scanners that run *before* the FR-011 approval interrupt. Exactly one, and it is passive:
#: everything active waits for a human. Kept here rather than in the graph so that "what may
#: Cynux run without approval?" is answerable from one line.
PRE_APPROVAL_SCANNERS: frozenset[ScannerName] = frozenset({ScannerName.RECONFTW})

#: Active scanners offered at each depth. ZAP only makes sense where there is a web target, so
#: the job service filters it out when asset analysis found none.
_DEPTH_SCANNERS: dict[AssessmentDepth, tuple[ScannerName, ...]] = {
    #: Passive means recon and nothing else -- there is no active scanner to offer.
    AssessmentDepth.PASSIVE: (),
    AssessmentDepth.STANDARD: (ScannerName.NMAP, ScannerName.NUCLEI, ScannerName.ZAP),
    AssessmentDepth.DEEP: (ScannerName.NMAP, ScannerName.NUCLEI, ScannerName.ZAP),
}

_MISSING = set(ScannerName) - set(ALL_ADAPTERS)
if _MISSING:  # pragma: no cover - import-time guard
    raise RuntimeError(f"ScannerName values without an adapter: {sorted(str(m) for m in _MISSING)}")


def get_adapter(name: ScannerName | str) -> ScannerAdapter:
    """The adapter for a scanner name.

    Raises :class:`~app.core.errors.UnsafeScannerInvocationError` rather than ``KeyError`` for
    an unknown name: the realistic source of one is a model that hallucinated a tool, and that
    is a guardrail trip worth logging as such, not a missing dictionary entry.
    """
    try:
        return ALL_ADAPTERS[ScannerName(str(name))]
    except (ValueError, KeyError) as exc:
        raise UnsafeScannerInvocationError(
            "An unknown scanner was requested.",
            user_message="Cynux was asked to run a scanner it does not have.",
            context={"requested": str(name), "known": sorted(str(k) for k in ALL_ADAPTERS)},
            cause=exc,
        ) from exc


def active_scanners(depth: AssessmentDepth | str) -> tuple[ScannerName, ...]:
    """Scanners that may run after approval at this depth."""
    try:
        return _DEPTH_SCANNERS[AssessmentDepth(str(depth))]
    except (ValueError, KeyError):
        return _DEPTH_SCANNERS[AssessmentDepth.STANDARD]


def scan_type_for(name: ScannerName | str) -> str | None:
    """DefectDojo's parser name for a scanner, or ``None`` when it produces no findings."""
    return get_adapter(name).defectdojo_scan_type


__all__ = [
    "ALL_ADAPTERS",
    "PRE_APPROVAL_SCANNERS",
    "active_scanners",
    "get_adapter",
    "scan_type_for",
]
