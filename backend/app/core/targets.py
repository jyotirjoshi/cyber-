"""Target parsing and validation (FR-006).

This module is the only place a raw, user- or model-supplied target string becomes
something a scanner may act on.  It exists to stop three distinct problems:

1. **Malformed input reaching a scanner.**  ``nmap $(rm -rf /)`` must never be
   attempted; targets are validated against strict grammars and the resulting
   canonical form contains no shell metacharacters.
2. **SSRF and internal pivoting.**  Cloud metadata endpoints, loopback, RFC1918 and
   link-local ranges are blocked unless the deployment explicitly opts in.
3. **Accidental scanning of third parties.**  CIDR expansion is bounded and an
   optional organization allow list can restrict scanning to owned space.

The classifier is deliberately ordered: URL, then CIDR, then IP, then repository,
then container image, then domain.  Ambiguity is resolved toward the *more
specific* type so ``https://x.com`` is a URL and not a domain named "https".
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

from app.core.config import TargetPolicySettings
from app.core.errors import InvalidTargetError, TargetDeniedError


class TargetType(str, enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    CIDR = "cidr"
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"


# --- grammars ---------------------------------------------------------------

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[A-Za-z]{{2,63}}\.?$")
_REPO_RE = re.compile(
    r"^(?:https?://|git@)?"
    r"(?P<host>github\.com|gitlab\.com|bitbucket\.org|[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r"[:/](?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)
_IMAGE_RE = re.compile(
    r"^(?:(?P<registry>[A-Za-z0-9.\-]+(?::\d+)?)/)?"
    r"(?P<path>[a-z0-9]+(?:[._\-/][a-z0-9]+)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._\-]{0,127}))?"
    r"(?:@sha256:(?P<digest>[a-f0-9]{64}))?$"
)

#: Anything containing one of these is rejected outright, before classification.
#: The canonical forms produced here are also passed to Docker as an argv list
#: (never through a shell), so this is defence in depth rather than the only guard.
_FORBIDDEN_CHARS = frozenset(";|&$`\n\r\t<>()!*?[]{}'\"\\ ")

#: Known SSRF magnets. Blocked whenever ``block_metadata_endpoints`` is on.
_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "100.100.100.200",  # Alibaba Cloud
        "169.254.169.253",
        "fd00:ec2::254",
    }
)

#: Registrable suffixes that are never a legitimate assessment target.
_ALWAYS_DENIED_SUFFIXES = frozenset({".localhost", ".local", ".internal", ".arpa", ".onion"})


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """A target that has passed every policy check.

    ``canonical`` is what gets handed to a scanner. ``host`` is what gets recorded
    as the asset identity, so ``https://api.x.com:8443/v1`` and ``api.x.com`` are
    recognisably the same asset.
    """

    raw: str
    type: TargetType
    canonical: str
    host: str
    port: int | None = None
    scheme: str | None = None
    path: str | None = None
    #: Number of addresses a CIDR target expands to; 1 for everything else.
    host_count: int = 1
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def is_web(self) -> bool:
        return self.type == TargetType.URL or (
            self.port in (80, 443, 8080, 8443) and self.type in (TargetType.DOMAIN, TargetType.IP)
        )


# ---------------------------------------------------------------------------


def classify(raw: str) -> TargetType:
    """Determine what kind of target this is without applying policy."""
    value = raw.strip()
    if not value:
        raise InvalidTargetError(user_message="Enter a target to assess.")

    if "://" in value and not value.startswith("git@"):
        scheme = value.split("://", 1)[0].lower()
        if scheme in ("http", "https"):
            return TargetType.URL
        if scheme in ("git", "ssh"):
            return TargetType.REPOSITORY
        raise InvalidTargetError(
            user_message=f"Cynux cannot assess '{scheme}://' targets. Use http, https or a domain."
        )

    if "/" in value:
        # Either a CIDR block or a repository path; the network form wins.
        try:
            ipaddress.ip_network(value, strict=False)
            return TargetType.CIDR
        except ValueError:
            pass
        if _REPO_RE.match(value):
            return TargetType.REPOSITORY
        if _IMAGE_RE.match(value):
            return TargetType.CONTAINER_IMAGE
        raise InvalidTargetError(
            user_message=f"'{_sanitize_for_display(value)}' is not a network range, repository or image."
        )

    if value.startswith("git@"):
        return TargetType.REPOSITORY

    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        pass

    bare = value.rstrip(".")
    if _DOMAIN_RE.match(value):
        return TargetType.DOMAIN
    if ":" in bare and _IMAGE_RE.match(value):
        return TargetType.CONTAINER_IMAGE

    raise InvalidTargetError(
        user_message=(
            f"'{_sanitize_for_display(value)}' is not a target Cynux recognizes. "
            "Use a domain, IP address, URL, CIDR range, repository URL or container image."
        )
    )


def validate_target(raw: str, policy: TargetPolicySettings) -> ValidatedTarget:
    """Parse, canonicalize and policy-check a target.

    Raises :class:`InvalidTargetError` for shape problems and
    :class:`TargetDeniedError` for policy refusals -- the two are distinct because
    the first is a typo and the second is a scope violation worth auditing.
    """
    value = raw.strip()
    if len(value) > 2048:
        raise InvalidTargetError(user_message="That target is too long.")

    illegal = _FORBIDDEN_CHARS & set(value)
    if illegal:
        raise InvalidTargetError(
            user_message=(
                "Targets cannot contain spaces or shell characters. Remove: "
                + " ".join(sorted(illegal))
            )
        )

    ttype = classify(value)
    target = _build[ttype](value)
    _enforce_policy(target, policy)
    return target


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _build_url(value: str) -> ValidatedTarget:
    parsed = urlparse(value)
    if not parsed.hostname:
        raise InvalidTargetError(user_message="That URL has no hostname.")
    host = parsed.hostname.lower()
    scheme = (parsed.scheme or "https").lower()
    port = parsed.port or (443 if scheme == "https" else 80)

    if parsed.username or parsed.password:
        # Credentials in a URL would end up in scanner argv, logs and DefectDojo.
        raise InvalidTargetError(
            user_message="Remove the credentials from that URL before scanning it."
        )
    if not (_DOMAIN_RE.match(host) or _is_ip(host)):
        raise InvalidTargetError(
            user_message=f"'{_sanitize_for_display(host)}' is not a valid hostname."
        )

    path = parsed.path or "/"
    canonical = urlunparse((scheme, parsed.netloc.lower(), path, "", parsed.query, ""))
    return ValidatedTarget(
        raw=value,
        type=TargetType.URL,
        canonical=canonical,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
    )


def _build_cidr(value: str) -> ValidatedTarget:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise InvalidTargetError(
            user_message=f"'{_sanitize_for_display(value)}' is not a valid network range."
        ) from exc
    return ValidatedTarget(
        raw=value,
        type=TargetType.CIDR,
        canonical=str(net),
        host=str(net),
        host_count=net.num_addresses,
        metadata={"version": str(net.version)},
    )


def _build_ip(value: str) -> ValidatedTarget:
    addr = ipaddress.ip_address(value)
    return ValidatedTarget(
        raw=value,
        type=TargetType.IP,
        canonical=str(addr),
        host=str(addr),
        metadata={"version": str(addr.version)},
    )


def _build_domain(value: str) -> ValidatedTarget:
    host = value.strip().rstrip(".").lower()
    try:
        # Reject homograph/punycode tricks by requiring a clean IDNA round-trip.
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTargetError(
            user_message="That domain contains characters Cynux cannot resolve safely."
        ) from exc
    if len(host) > 253:
        raise InvalidTargetError(user_message="That domain name is too long.")
    return ValidatedTarget(raw=value, type=TargetType.DOMAIN, canonical=host, host=host)


def _build_repository(value: str) -> ValidatedTarget:
    match = _REPO_RE.match(value)
    if not match:
        raise InvalidTargetError(
            user_message="That does not look like a repository URL. Use e.g. https://github.com/org/repo."
        )
    host = match.group("host").lower()
    owner, repo = match.group("owner"), match.group("repo")
    return ValidatedTarget(
        raw=value,
        type=TargetType.REPOSITORY,
        canonical=f"https://{host}/{owner}/{repo}",
        host=host,
        scheme="https",
        path=f"/{owner}/{repo}",
        metadata={"owner": owner, "repository": repo},
    )


def _build_image(value: str) -> ValidatedTarget:
    match = _IMAGE_RE.match(value)
    if not match:
        raise InvalidTargetError(
            user_message="That does not look like a container image reference."
        )
    registry = (match.group("registry") or "docker.io").lower()
    path = match.group("path")
    tag = match.group("tag") or ("" if match.group("digest") else "latest")
    digest = match.group("digest")
    canonical = f"{registry}/{path}"
    if digest:
        canonical += f"@sha256:{digest}"
    elif tag:
        canonical += f":{tag}"
    return ValidatedTarget(
        raw=value,
        type=TargetType.CONTAINER_IMAGE,
        canonical=canonical,
        host=registry,
        metadata={k: v for k, v in {"tag": tag, "digest": digest}.items() if v},
    )


_build = {
    TargetType.URL: _build_url,
    TargetType.CIDR: _build_cidr,
    TargetType.IP: _build_ip,
    TargetType.DOMAIN: _build_domain,
    TargetType.REPOSITORY: _build_repository,
    TargetType.CONTAINER_IMAGE: _build_image,
}


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def _enforce_policy(target: ValidatedTarget, policy: TargetPolicySettings) -> None:
    host = target.host.lower()

    if policy.block_metadata_endpoints and host in _METADATA_HOSTS:
        raise TargetDeniedError(user_message="Cloud metadata endpoints cannot be scanned.")

    for suffix in _ALWAYS_DENIED_SUFFIXES:
        if host.endswith(suffix):
            raise TargetDeniedError(
                user_message=f"'{suffix}' names are not routable assessment targets."
            )

    if target.type == TargetType.CIDR and target.host_count > policy.max_cidr_hosts:
        raise TargetDeniedError(
            user_message=(
                f"That range covers {target.host_count:,} addresses; the limit is "
                f"{policy.max_cidr_hosts:,}. Split it into smaller ranges."
            )
        )

    if policy.block_private_ranges:
        for addr in _addresses_of(target):
            if _is_non_public(addr):
                raise TargetDeniedError(
                    user_message=(
                        "That target is a private, loopback or link-local address. "
                        "Enable internal scanning for this deployment if you are "
                        "authorized to test it."
                    )
                )

    if _matches_any(target, policy.deny_list):
        raise TargetDeniedError(user_message="Scanning this target is blocked by policy.")

    if policy.allow_list and not _matches_any(target, policy.allow_list):
        raise TargetDeniedError(
            user_message=("This target is outside the scope this deployment is allowed to scan.")
        )


def _addresses_of(target: ValidatedTarget) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Literal addresses present in the target. Domains are resolved later, during
    reconnaissance, and re-checked there -- this only covers what is knowable now."""
    if target.type == TargetType.CIDR:
        net = ipaddress.ip_network(target.canonical, strict=False)
        # Checking the boundaries is sufficient: a private range's endpoints are private.
        return [net.network_address, net.broadcast_address]
    if _is_ip(target.host):
        return [ipaddress.ip_address(target.host)]
    return []


def _is_non_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or (addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"))  # CGNAT
    )


def _matches_any(target: ValidatedTarget, patterns: list[str]) -> bool:
    host = target.host.lower()
    for pattern in patterns:
        pat = pattern.strip().lower().lstrip("*.")
        if not pat:
            continue
        if host == pat or host.endswith(f".{pat}"):
            return True
        try:
            net = ipaddress.ip_network(pat, strict=False)
        except ValueError:
            continue
        for addr in _addresses_of(target):
            if addr.version == net.version and addr in net:
                return True
    return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _sanitize_for_display(value: str) -> str:
    """Truncate and strip control characters so an invalid target cannot inject
    escape sequences into a terminal or markup into the UI."""
    cleaned = "".join(ch for ch in value[:120] if ch.isprintable())
    return cleaned or "(empty)"


def expand_cidr(target: ValidatedTarget, limit: int) -> list[str]:
    """List usable host addresses in a CIDR target, bounded by ``limit``."""
    if target.type != TargetType.CIDR:
        return [target.host]
    net = ipaddress.ip_network(target.canonical, strict=False)
    hosts: list[str] = []
    for addr in net.hosts():
        hosts.append(str(addr))
        if len(hosts) >= limit:
            break
    return hosts or [str(net.network_address)]


def is_public_hostname(host: str) -> bool:
    """Re-check a *resolved* address discovered during recon.

    Reconnaissance can turn a public domain into a private address (split-horizon
    DNS, DNS rebinding). Scanner adapters call this before acting on discovered IPs.
    """
    try:
        return not _is_non_public(ipaddress.ip_address(host))
    except ValueError:
        return not any(host.lower().endswith(s) for s in _ALWAYS_DENIED_SUFFIXES)


__all__ = [
    "TargetType",
    "ValidatedTarget",
    "classify",
    "expand_cidr",
    "is_public_hostname",
    "validate_target",
]
