"""Conservative, deterministic identities for cross-provider observations.

Only a validated CVE on the same normalized asset is sufficient for automatic
cross-provider merging. Other findings retain their source identity until an
analyst or a future rule establishes equivalence; titles alone are never proof.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def valid_cves(values: list[str]) -> list[str]:
    """Return sorted, distinct, syntactically valid CVEs only."""
    return sorted({value.strip().upper() for value in values if _CVE.fullmatch(value.strip())})


def normalized_asset_identity(asset_type: str, value: str) -> tuple[str, str]:
    """Normalize a stable asset identifier without conflating asset kinds."""
    kind = asset_type.strip().lower()
    raw = value.strip()
    if not kind or not raw:
        raise ValueError("asset type and identity are required")
    if kind == "host":
        try:
            return "ip", str(ipaddress.ip_address(raw))
        except ValueError:
            return normalized_asset_identity("domain", raw)
    if kind in {"ip", "ip_address"}:
        return "ip", str(ipaddress.ip_address(raw))
    if kind in {"domain", "subdomain", "hostname"}:
        return "domain", raw.rstrip(".").encode("idna").decode("ascii").lower()
    if kind in {"repo", "repository"}:
        repo = raw.split(":", 1)[0].strip("/").lower()
        if "/" not in repo:
            raise ValueError("repository identity must include owner and name")
        return "repo", repo
    if kind in {"url", "website"}:
        url = urlsplit(raw)
        if url.scheme.lower() not in {"http", "https"} or not url.hostname:
            raise ValueError("URL asset identity requires an HTTP(S) host")
        host = url.hostname.rstrip(".").lower()
        port = f":{url.port}" if url.port else ""
        path = url.path.rstrip("/") or "/"
        return "url", f"{url.scheme.lower()}://{host}{port}{path}"
    return kind, raw


def identity_for_observation(
    asset_type: str,
    asset_value: str,
    cve_ids: list[str],
    provider: str,
    external_id: str,
) -> str:
    """Produce a stable finding fingerprint for one source observation."""
    kind, asset = normalized_asset_identity(asset_type, asset_value)
    cves = valid_cves(cve_ids)
    if cves:
        identity = ["cve", kind, asset, cves[0]]
    else:
        source = provider.strip().lower()
        record = external_id.strip()
        if not source or not record:
            raise ValueError("source identity is required without a valid CVE")
        identity = ["source", kind, asset, source, record]
    payload = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
