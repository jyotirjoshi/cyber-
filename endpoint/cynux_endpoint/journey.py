"""Privacy-preserving HTTPS synthetic journey probe for Cynux experience monitoring."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import logging
import os
import signal
import socket
import ssl
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from .agent import Spool, json_transport

LOG = logging.getLogger("cynux.journey")


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    path: str
    address: str
    digest: str


@dataclass(frozen=True)
class ProbeResult:
    available: bool
    status_code: int | None
    dns_ms: float
    connect_ms: float
    tls_ms: float
    ttfb_ms: float
    total_ms: float
    certificate_days_remaining: int | None
    error_code: str | None


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not any(
        (ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved)
    )


def validate_target(url: str, *, resolver=socket.getaddrinfo) -> Target:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target must be an HTTPS URL without embedded credentials")
    if parsed.port not in {None, 443}:
        raise ValueError("Only HTTPS port 443 is supported")
    host = parsed.hostname.rstrip(".").casefold()
    try:
        if not _is_public(host):
            raise ValueError("Target must resolve to public addresses")
        addresses = [host]
    except ValueError as exc:
        if "public" in str(exc):
            raise
        addresses = []
        for result in resolver(host, 443, 0, socket.SOCK_STREAM):
            address = str(result[4][0])
            if address not in addresses:
                addresses.append(address)
        if not addresses or any(not _is_public(address) for address in addresses):
            raise ValueError("Target must resolve only to public addresses")
    path = parsed.path or "/"
    canonical = f"https://{host}{path}"
    return Target(
        host=host,
        port=443,
        path=path,
        address=addresses[0],
        digest=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def probe(target: Target, *, timeout: float = 10.0, resolver=socket.getaddrinfo) -> ProbeResult:
    start = time.perf_counter()
    dns_ms = 0.0
    try:
        dns_at = time.perf_counter()
        addresses = list(
            dict.fromkeys(
                str(item[4][0])
                for item in resolver(target.host, target.port, 0, socket.SOCK_STREAM)
            )
        )
        dns_ms = (time.perf_counter() - dns_at) * 1000
        if not addresses or any(not _is_public(address) for address in addresses):
            raise OSError("DNS target is no longer public")
        connected_at = time.perf_counter()
        raw = socket.create_connection((addresses[0], target.port), timeout=timeout)
        connect_ms = (time.perf_counter() - connected_at) * 1000
        with raw:
            tls_at = time.perf_counter()
            context = ssl.create_default_context()
            with context.wrap_socket(raw, server_hostname=target.host) as secure:
                tls_ms = (time.perf_counter() - tls_at) * 1000
                certificate = secure.getpeercert()
                expiry = certificate.get("notAfter")
                cert_days = (
                    int((ssl.cert_time_to_seconds(expiry) - time.time()) // 86400)
                    if expiry
                    else None
                )
                request = (
                    f"HEAD {target.path} HTTP/1.1\r\nHost: {target.host}\r\n"
                    "User-Agent: cynux-journey/0.7\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                secure.sendall(request)
                first_byte_at = time.perf_counter()
                data = b""
                while b"\r\n\r\n" not in data and len(data) <= 65536:
                    chunk = secure.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                ttfb_ms = (time.perf_counter() - first_byte_at) * 1000
                status_line = data.split(b"\r\n", 1)[0].split()
                status = int(status_line[1]) if len(status_line) >= 2 else None
                total_ms = (time.perf_counter() - start) * 1000
                available = status is not None and status < 500
                return ProbeResult(
                    available, status, dns_ms, connect_ms, tls_ms, ttfb_ms,
                    total_ms, cert_days, None if available else "upstream_error",
                )
    except (OSError, ssl.SSLError, ValueError) as exc:
        code = type(exc).__name__.casefold().replace("error", "_error")[:80]
        return ProbeResult(
            False, None, dns_ms, 0.0, 0.0, 0.0,
            (time.perf_counter() - start) * 1000, None, code,
        )


def probe_payload(
    *, journey_name: str, journey_key: str, location: str, target_digest: str,
    result: ProbeResult, occurred_at: dt.datetime | None = None,
) -> dict:
    occurred_at = occurred_at or dt.datetime.now(dt.UTC)
    event_identity = f"{journey_key}:{location}:{occurred_at.isoformat()}:{target_digest}"
    return {
        "event_key": hashlib.sha256(event_identity.encode()).hexdigest(),
        "journey_key": journey_key,
        "journey_name": journey_name,
        "location": location,
        "occurred_at": occurred_at.isoformat(),
        "target_digest": target_digest,
        **asdict(result),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--location", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    if not 60 <= args.interval <= 3600:
        parser.error("interval must be between 60 and 3600 seconds")
    target = validate_target(args.url)
    send = json_transport(
        args.server,
        os.environ.get("CYNUX_ENDPOINT_API_KEY", ""),
        "/api/v1/control-plane/experience/probes",
    )
    logging.basicConfig(level=logging.INFO)
    spool = Spool(args.state_dir / "journeys.sqlite3", capacity=20000)
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    failures = 0
    try:
        while not stop.is_set():
            spool.enqueue(probe_payload(
                journey_name=args.name, journey_key=args.key, location=args.location,
                target_digest=target.digest, result=probe(target),
            ))
            try:
                delivered = spool.drain(send)
                failures = 0
                LOG.info("Delivered %s journey observations", delivered)
            except (HTTPError, URLError, OSError):
                failures += 1
                LOG.warning("Delivery deferred; observations retained")
            stop.wait(min(3600, args.interval * (2 ** min(failures, 4))))
    finally:
        spool.db.close()


if __name__ == "__main__":
    main()
