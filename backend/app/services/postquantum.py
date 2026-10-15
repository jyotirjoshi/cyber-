"""Post-quantum readiness: crypto asset discovery, CBOM export, quantum-vulnerable findings.

Discovers cryptographic assets from scanner artifacts and source-code scans, classifies
them against the NIST post-quantum migration guidance, and surfaces quantum-vulnerable
algorithm usage as canonical findings so they flow through the normal remediation pipeline.

Design:
- Reads Semgrep SARIF and Syft CycloneDX artifacts already stored from scan jobs.
- Emits CBOM (Cryptography Bill of Materials) in CycloneDX JSON format.
- Creates ExternalSecurityAlert rows for quantum-vulnerable algorithms so they appear
  in the existing exposure feed without a parallel data model.
- Tenant-isolated at every query; no crypto material is stored or logged.
- Intentionally conservative: unknown algorithms are flagged as "unclassified" rather
  than assumed safe.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.models.asset import Asset
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.services.canonical_identity import normalized_asset_identity
from app.services.context import Principal
from app.services.external_alert import NormalizedExternalAlert, _stage_normalized_alerts

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Algorithm classification
# ---------------------------------------------------------------------------

#: NIST SP 800-131A and CNSA 2.0 quantum-vulnerable algorithms.
#: Keys are normalised algorithm names (lowercase, no hyphens/spaces).
_QUANTUM_VULNERABLE: dict[str, str] = {
    "rsa": "RSA is quantum-vulnerable (Shor's algorithm). Migrate to ML-KEM / ML-DSA.",
    "rsapkcs1v15": "RSA PKCS#1 v1.5 is quantum-vulnerable.",
    "rsaoaep": "RSA-OAEP is quantum-vulnerable.",
    "rsapss": "RSA-PSS is quantum-vulnerable.",
    "dh": "Diffie-Hellman is quantum-vulnerable. Migrate to ML-KEM.",
    "dhe": "DHE is quantum-vulnerable.",
    "ecdh": "ECDH is quantum-vulnerable (Shor's algorithm). Migrate to ML-KEM.",
    "ecdsa": "ECDSA is quantum-vulnerable. Migrate to ML-DSA.",
    "dsa": "DSA is quantum-vulnerable. Migrate to ML-DSA.",
    "ed25519": "Ed25519 is quantum-vulnerable to Shor's algorithm.",
    "ed448": "Ed448 is quantum-vulnerable.",
    "elgamal": "ElGamal is quantum-vulnerable.",
    "des": "DES is classically and quantum-vulnerable. Replace immediately.",
    "3des": "3DES is being deprecated; quantum-vulnerable.",
    "rc4": "RC4 is broken classically and quantum-vulnerable.",
}

#: Post-quantum safe (NIST-standardized or recommended).
_QUANTUM_SAFE = frozenset({
    "mlkem", "mlkem512", "mlkem768", "mlkem1024",
    "mldsa", "mldsa44", "mldsa65", "mldsa87",
    "slhdsa",
    "aes128gcm", "aes192gcm", "aes256gcm", "aes256",
    "chacha20poly1305", "xchacha20poly1305",
    "sha256", "sha384", "sha512", "sha3256", "sha3384", "sha3512",
    "blake2b", "blake2s", "blake3",
})

_SEMGREP_CRYPTO_RULES = frozenset({
    "insecure-crypto", "weak-crypto", "crypto-weak-key", "use-of-rsa",
    "hardcoded-crypto-key", "deprecated-tls-version", "insufficient-keylength",
    "use-of-des", "use-of-rc4", "use-of-md5", "use-of-sha1",
})


def _normalise_algorithm(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(" ", "")


def classify_algorithm(raw_name: str) -> tuple[str, str | None]:
    """Return (classification, advisory) for a raw algorithm name.

    Classifications: 'vulnerable', 'safe', 'unclassified'.
    Advisory is only set for 'vulnerable'.
    """
    norm = _normalise_algorithm(raw_name)
    if norm in _QUANTUM_SAFE:
        return "safe", None
    advisory = _QUANTUM_VULNERABLE.get(norm)
    if advisory:
        return "vulnerable", advisory
    # Partial match — e.g. "RSA-2048" → contains "rsa"
    for key, adv in _QUANTUM_VULNERABLE.items():
        if key in norm:
            return "vulnerable", adv
    return "unclassified", None


# ---------------------------------------------------------------------------
# CBOM export
# ---------------------------------------------------------------------------

def build_cbom(
    crypto_assets: list[dict[str, Any]],
    *,
    subject: str,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 Cryptography Bill of Materials document.

    ``crypto_assets`` is a list of dicts with keys:
        - algorithm (str): raw algorithm name
        - classification (str): 'vulnerable'|'safe'|'unclassified'
        - source_file (str|None): file path where it was found
        - source_line (int|None): line number
        - evidence (dict): additional context
    """
    components = []
    for asset in crypto_assets:
        alg = asset.get("algorithm", "unknown")
        classification = asset.get("classification", "unclassified")
        norm = _normalise_algorithm(alg)
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "name": alg,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "name": alg,
                    "parameterSetIdentifier": norm,
                },
                "quantum-safe": classification == "safe",
            },
        }
        if asset.get("source_file"):
            component["evidence"] = {
                "occurrences": [{"location": asset["source_file"], "line": asset.get("source_line")}]
            }
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": utcnow().isoformat(),
            "subject": subject,
            "properties": [
                {"name": "cynux:organization_id", "value": str(organization_id)},
                {"name": "cynux:assessment_id", "value": str(assessment_id) if assessment_id else ""},
                {"name": "cynux:cbom_type", "value": "post-quantum-readiness"},
            ],
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Artifact scanning
# ---------------------------------------------------------------------------

def _extract_from_semgrep_sarif(sarif_data: bytes) -> list[dict[str, Any]]:
    """Extract crypto-related findings from a Semgrep SARIF artifact."""
    try:
        doc = json.loads(sarif_data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    findings: list[dict[str, Any]] = []
    for run in doc.get("runs", []):
        if not isinstance(run, dict):
            continue
        rules: dict[str, dict[str, Any]] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            if isinstance(rule, dict) and rule.get("id"):
                rules[rule["id"]] = rule
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            # Only harvest crypto-related rules
            if not any(kw in rule_id.lower() for kw in ("crypto", "rsa", "des", "rc4", "tls", "cipher", "key", "hash")):
                continue
            message = result.get("message", {})
            text = str(message.get("text") or message.get("markdown") or rule_id)
            locations = result.get("locations", [])
            file_path = ""
            line = None
            if locations:
                physical = locations[0].get("physicalLocation", {})
                file_path = physical.get("artifactLocation", {}).get("uri", "")
                line = physical.get("region", {}).get("startLine")
            # Try to extract algorithm name from rule_id or message
            algorithm = _infer_algorithm_from_text(rule_id + " " + text)
            if not algorithm:
                continue
            classification, _ = classify_algorithm(algorithm)
            findings.append({
                "algorithm": algorithm,
                "classification": classification,
                "source_file": file_path[:500] if file_path else None,
                "source_line": line if isinstance(line, int) else None,
                "evidence": {"rule_id": rule_id[:200], "message": text[:500]},
            })
    return findings


def _extract_from_syft_cyclonedx(cdx_data: bytes) -> list[dict[str, Any]]:
    """Extract cryptographic component entries from a Syft CycloneDX SBOM."""
    try:
        doc = json.loads(cdx_data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    findings: list[dict[str, Any]] = []
    for component in doc.get("components", []):
        if not isinstance(component, dict):
            continue
        crypto_props = component.get("cryptoProperties")
        if not crypto_props:
            # Fall back to algorithm-keyword matching in component names
            name = str(component.get("name") or "")
            alg = _infer_algorithm_from_text(name)
            if not alg:
                continue
            classification, _ = classify_algorithm(alg)
            findings.append({
                "algorithm": alg,
                "classification": classification,
                "source_file": None,
                "source_line": None,
                "evidence": {"component_name": name[:200]},
            })
        else:
            alg_props = crypto_props.get("algorithmProperties", {})
            name = str(alg_props.get("name") or component.get("name") or "")
            if not name:
                continue
            classification, _ = classify_algorithm(name)
            findings.append({
                "algorithm": name,
                "classification": classification,
                "source_file": None,
                "source_line": None,
                "evidence": {"cdx_type": crypto_props.get("assetType", "")},
            })
    return findings


_ALGORITHM_KEYWORDS = [
    "rsa", "ecdsa", "ecdh", "dsa", "dh", "des", "3des", "rc4", "rc2",
    "ed25519", "ed448", "elgamal",
    "aes", "chacha20", "mlkem", "mldsa", "slhdsa",
]


def _infer_algorithm_from_text(text: str) -> str | None:
    text_lower = text.lower()
    for keyword in _ALGORITHM_KEYWORDS:
        if keyword in text_lower:
            return keyword.upper()
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_postquantum_scan(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> dict[str, Any]:
    """Scan all artifacts from an assessment's Semgrep/Syft jobs for crypto assets.

    Returns a summary dict and stages quantum-vulnerable algorithm findings as
    ExternalSecurityAlert rows so they appear in the normal finding pipeline.

    Tenant isolation: every query filters on organization_id. The asset_id must
    belong to the same organization before any artifact is read.
    """
    from app.integrations.storage import ObjectStorage
    from app.core.config import get_settings

    settings = get_settings()

    # Verify asset belongs to this tenant
    asset = (
        await session.execute(
            select(Asset).where(
                Asset.id == asset_id,
                Asset.organization_id == principal.organization_id,
            )
        )
    ).scalar_one_or_none()
    if asset is None or asset.organization_id != principal.organization_id:
        raise ValueError("Asset not found in organization")

    # Load Semgrep + Syft artifacts from this assessment
    artifacts = (
        await session.execute(
            select(ScannerArtifact)
            .join(ScannerJob, ScannerJob.id == ScannerArtifact.job_id)
            .where(
                ScannerJob.assessment_id == assessment_id,
                ScannerJob.organization_id == principal.organization_id,
                ScannerArtifact.organization_id == principal.organization_id,
                ScannerJob.scanner.in_(["semgrep_repo", "syft_image"]),
            )
        )
    ).scalars().all()

    storage = ObjectStorage(settings.storage)
    crypto_assets: list[dict[str, Any]] = []
    vulnerable: list[dict[str, Any]] = []

    for artifact in artifacts:
        if artifact.organization_id != principal.organization_id:
            continue  # belt-and-suspenders tenant guard
        try:
            data = await storage.get_bytes(
                artifact.storage_key,
                organization_id=principal.organization_id,
            )
        except Exception as exc:
            log.warning(
                "postquantum.artifact_read_failed",
                artifact_id=str(artifact.id),
                exc_type=type(exc).__name__,
            )
            continue

        if "semgrep" in str(artifact.filename).lower() or artifact.filename.endswith(".sarif"):
            extracted = _extract_from_semgrep_sarif(data)
        else:
            extracted = _extract_from_syft_cyclonedx(data)

        crypto_assets.extend(extracted)
        vulnerable.extend(e for e in extracted if e["classification"] == "vulnerable")

    # Deduplicate by (algorithm, file, line)
    seen: set[str] = set()
    unique_vulnerable: list[dict[str, Any]] = []
    for item in vulnerable:
        key = hashlib.sha256(
            json.dumps(
                [item["algorithm"], item.get("source_file"), item.get("source_line")],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        if key not in seen:
            seen.add(key)
            unique_vulnerable.append(item)

    # Stage quantum-vulnerable findings as external alerts
    if unique_vulnerable:
        try:
            kind, value = normalized_asset_identity(asset.asset_type, asset.name)
        except ValueError:
            kind, value = "application", asset.name

        alerts = [
            NormalizedExternalAlert(
                external_id=hashlib.sha256(
                    f"pq:{principal.organization_id}:{item['algorithm']}:{item.get('source_file')}:{item.get('source_line')}".encode()
                ).hexdigest(),
                category="post_quantum",
                title=f"Quantum-vulnerable algorithm: {item['algorithm']}",
                severity="medium",
                status="open",
                resource=value,
                source_url=None,
                cve_ids=[],
                evidence={
                    "asset_type": kind,
                    "asset_value": value,
                    "algorithm": item["algorithm"],
                    "file": item.get("source_file", ""),
                    "line": item.get("source_line"),
                    "advisory": _QUANTUM_VULNERABLE.get(
                        _normalise_algorithm(item["algorithm"]), ""
                    )[:500],
                },
                raw_payload={},
            )
            for item in unique_vulnerable
        ]
        await _stage_normalized_alerts(
            session,
            organization_id=principal.organization_id,
            integration_id=None,
            provider="postquantum",
            alerts=alerts,
        )

    # Build CBOM
    cbom = build_cbom(
        crypto_assets,
        subject=asset.name,
        organization_id=principal.organization_id,
        assessment_id=assessment_id,
    )

    log.info(
        "postquantum.scan_complete",
        assessment_id=str(assessment_id),
        total=len(crypto_assets),
        vulnerable=len(unique_vulnerable),
    )
    return {
        "total_crypto_assets": len(crypto_assets),
        "vulnerable_count": len(unique_vulnerable),
        "safe_count": sum(1 for a in crypto_assets if a["classification"] == "safe"),
        "unclassified_count": sum(1 for a in crypto_assets if a["classification"] == "unclassified"),
        "cbom": cbom,
    }


__all__ = [
    "build_cbom",
    "classify_algorithm",
    "run_postquantum_scan",
]
