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

from app.core.errors import InvalidTargetError
from app.core.targets import _build_image

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def asset_storage_name(kind: str, value: str) -> str:
    """Store long provider identifiers without truncation collisions."""
    name = f"{kind}:{value}"
    if len(name) <= 512:
        return name
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"{kind}:sha256:{digest}"


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
        if raw.startswith(("https://", "http://")):
            parsed = urlsplit(raw)
            if (
                not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("repository URL must be an unambiguous host and project")
            host = parsed.hostname.lower()
            path = parsed.path.strip("/").lower()
            repo = (
                path if host in {"github.com", "gitlab.com", "bitbucket.org"} else f"{host}/{path}"
            )
        elif raw.startswith("git@"):
            host_part, separator, path = raw[4:].partition(":")
            if not separator or not host_part or not path:
                raise ValueError("repository identity must include host and project")
            host = host_part.lower()
            path = path.strip("/").lower()
            repo = (
                path if host in {"github.com", "gitlab.com", "bitbucket.org"} else f"{host}/{path}"
            )
        else:
            repo = raw.split(":", 1)[0].strip("/").lower()
        if repo.endswith(".git"):
            repo = repo[:-4]
        if "/" not in repo or repo.startswith("/") or repo.endswith("/"):
            raise ValueError("repository identity must include owner and name")
        return "repo", repo
    if kind in {"container", "container_image", "image"}:
        try:
            return "container_image", _build_image(raw).canonical
        except InvalidTargetError as exc:
            raise ValueError("container image identity is invalid") from exc
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
