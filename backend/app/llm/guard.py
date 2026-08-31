"""Mechanical hallucination protection (FR-024).

FR-024 forbids the model from inventing CVEs, CVSS scores, exploitation evidence, scanner
results, MITRE mappings or threat intelligence, and mandates one exact sentence when a fact
cannot be verified.  Prompting alone cannot enforce that -- a model asked nicely not to
hallucinate still occasionally does -- so this module is the deterministic half: it runs on
every model output that reaches a user, and it can only ever *remove* claims, never add
them.

The design rests on one distinction.  Not every sentence is a verifiable claim; "this
should be remediated first" is a judgement and needs no citation.  What needs a citation is
a sentence asserting a *checkable security fact*: a CVE identifier, a CVSS score, KEV or
active-exploitation status, an EPSS probability, a MITRE technique, or a scanner result.
:data:`CLAIM_INDICATORS` is that list.  A sentence that trips an indicator and carries no
source marker resolving into the supplied evidence is unsupported, and in
:attr:`GuardResult.stripped_text` it is replaced by :data:`UNVERIFIABLE_STATEMENT`.

Being conservative in the right direction matters more than being clever: a missed
judgement sentence costs nothing, while a fabricated CVE in a report costs an engineer a
day chasing a vulnerability that does not exist.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field

from app.core.errors import UnverifiableClaimError

#: FR-024 mandates this exact wording. Do not paraphrase; the frontend and the report
#: templates both key off it.
UNVERIFIABLE_STATEMENT = "Unable to verify from available security intelligence."

#: Source markers the prompts instruct the model to emit, e.g. ``[nvd:CVE-2024-3094]`` or
#: ``[S3]``. Bounded length so a runaway generation cannot produce a pathological match.
SOURCE_MARKER_RE = re.compile(r"\[([A-Za-z0-9_.:\-/]{1,80})\]")

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
CVSS_RE = re.compile(r"\b(?:CVSS[^0-9]{0,20})?(\d{1,2}\.\d)\b(?:\s*/\s*10)?", re.IGNORECASE)
CVSS_CONTEXT_RE = re.compile(r"\bCVSS\b|\bbase score\b|\bseverity score\b", re.IGNORECASE)
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
EPSS_RE = re.compile(r"\bEPSS\b", re.IGNORECASE)

#: Sentences matching any of these assert a checkable fact and therefore require a source.
CLAIM_INDICATORS: tuple[re.Pattern[str], ...] = (
    CVE_RE,
    CWE_RE,
    MITRE_RE,
    EPSS_RE,
    re.compile(r"\bCVSS\b", re.IGNORECASE),
    re.compile(r"\bKEV\b|\bknown exploited\b", re.IGNORECASE),
    re.compile(
        r"\bactively exploited\b|\bexploited in the wild\b"
        r"|\bunder active exploitation\b|\bactively being exploited\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bproof[- ]of[- ]concept\b|\bpublic exploit\b|\bexploit (?:exists|is available)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bransomware\b", re.IGNORECASE),
    re.compile(
        r"\b(?:nmap|nuclei|zap|reconftw)\b (?:found|reported|detected|identified)", re.IGNORECASE
    ),
    re.compile(r"\bMITRE\b|\bATT&CK\b", re.IGNORECASE),
)

#: Split on sentence terminators followed by whitespace. Newlines terminate too, so list
#: items and Markdown bullets are treated as separate claims rather than one long run-on.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass(frozen=True, slots=True)
class Claim:
    text: str
    source_id: str | None = None


@dataclass(frozen=True, slots=True)
class GuardResult:
    #: False when at least one claim was unsupported. Callers decide whether to use
    #: ``stripped_text`` or reject the whole response.
    accepted: bool
    claims: list[Claim] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    #: ``text`` with every unsupported claim replaced by :data:`UNVERIFIABLE_STATEMENT`.
    stripped_text: str = ""


def _is_claim(sentence: str) -> bool:
    return any(pattern.search(sentence) for pattern in CLAIM_INDICATORS)


def _sources_in(sentence: str, evidence: Mapping[str, object]) -> str | None:
    """Return the first source marker in ``sentence`` that resolves into ``evidence``.

    Resolution is case-insensitive and tolerates the model writing ``[NVD:CVE-2024-3094]``
    where the evidence key is ``nvd:CVE-2024-3094``; a citation rejected on letter case
    would be a false alarm that trains reviewers to ignore the guard.
    """
    if not evidence:
        return None
    lowered = {str(key).lower(): str(key) for key in evidence}
    for match in SOURCE_MARKER_RE.finditer(sentence):
        candidate = match.group(1)
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
    return None


def verify_claims(text: str, *, evidence: Mapping[str, object]) -> GuardResult:
    """Check that every factual security claim in ``text`` cites supplied evidence."""
    if not text or not text.strip():
        return GuardResult(accepted=True, claims=[], unsupported=[], stripped_text=text)

    sentences = [s for s in _SENTENCE_SPLIT_RE.split(text) if s.strip()]
    # Resolve every sentence's citation up front so a claim can be supported by a marker the
    # model placed in the sentence immediately before or after it. "CVE-x enables RCE. Tracked
    # at [nvd:CVE-x]." is one thought split across a period, and demanding the marker in the
    # *same* sentence would replace a correctly-sourced fact with the can't-verify line -- a
    # false alarm that trains reviewers to ignore the guard. The window is +/-1 only; a citation
    # two sentences away is too loose to call support. This relaxation cannot pass a fabricated
    # CVE or CVSS: assert_no_invented_cve/assert_no_invented_cvss reject those anywhere in the
    # text regardless of what verify_claims accepts.
    resolved = [_sources_in(sentence, evidence) for sentence in sentences]
    claims: list[Claim] = []
    unsupported: list[str] = []
    rebuilt: list[str] = []

    for index, sentence in enumerate(sentences):
        if not _is_claim(sentence):
            rebuilt.append(sentence)
            continue
        source_id = resolved[index]
        if source_id is None and index > 0:
            source_id = resolved[index - 1]
        if source_id is None and index + 1 < len(sentences):
            source_id = resolved[index + 1]
        claims.append(Claim(text=sentence.strip(), source_id=source_id))
        if source_id is None:
            unsupported.append(sentence.strip())
            rebuilt.append(UNVERIFIABLE_STATEMENT)
        else:
            rebuilt.append(sentence)

    return GuardResult(
        accepted=not unsupported,
        claims=claims,
        unsupported=unsupported,
        stripped_text="\n".join(rebuilt),
    )


def normalize_cve(value: str) -> str:
    return value.strip().upper()


def assert_no_invented_cve(text: str, *, known_cves: Collection[str]) -> None:
    """Raise if ``text`` names a CVE that was not in the evidence.

    This is the hardest line in FR-024 to get wrong and the easiest to check: a CVE
    identifier is either one the scanners and intelligence providers actually returned, or
    the model made it up. There is no third case.
    """
    known = {normalize_cve(c) for c in known_cves}
    invented = sorted({normalize_cve(m.group(0)) for m in CVE_RE.finditer(text)} - known)
    if invented:
        raise UnverifiableClaimError(
            f"Model asserted CVE identifiers absent from the evidence: {', '.join(invented)}",
            context={"invented_cves": invented, "known_count": len(known)},
        )


def assert_no_invented_cvss(text: str, *, known_scores: Collection[float]) -> None:
    """Raise if ``text`` states a CVSS score not present in the evidence.

    Only decimals appearing in CVSS context are considered -- an unqualified "3.1" is far
    more likely to be a version number or a count than a fabricated score, and treating
    every decimal as a claim would make the guard fire constantly and get switched off.
    """
    if not CVSS_CONTEXT_RE.search(text):
        return
    known = {round(float(s), 1) for s in known_scores}
    seen: set[float] = set()
    for match in CVSS_RE.finditer(text):
        try:
            value = round(float(match.group(1)), 1)
        except ValueError:  # pragma: no cover - regex guarantees a float
            continue
        if 0.0 <= value <= 10.0:
            seen.add(value)
    invented = sorted(seen - known)
    if invented:
        raise UnverifiableClaimError(
            f"Model asserted CVSS scores absent from the evidence: "
            f"{', '.join(str(v) for v in invented)}",
            context={"invented_scores": invented, "known": sorted(known)},
        )


def collect_evidence_ids(evidence: Mapping[str, object]) -> list[str]:
    """The source ids the prompt should tell the model it may cite."""
    return sorted(str(key) for key in evidence)


__all__ = [
    "CLAIM_INDICATORS",
    "CVE_RE",
    "SOURCE_MARKER_RE",
    "UNVERIFIABLE_STATEMENT",
    "Claim",
    "GuardResult",
    "assert_no_invented_cve",
    "assert_no_invented_cvss",
    "collect_evidence_ids",
    "normalize_cve",
    "verify_claims",
]
