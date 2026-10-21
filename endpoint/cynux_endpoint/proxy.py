"""Opt-in loopback CONNECT gateway. Domain policy, not TLS content inspection.

Only explicitly configured clients are covered. This is not a host firewall:
direct connections bypass it. The service never changes OS proxy settings.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import socket
import sqlite3
import uuid
from pathlib import Path

from cynux_endpoint.agent import Spool


def domain(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("Invalid domain")
    value = value.lower()
    if "." not in value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("Use an ASCII fully qualified domain name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("IP literal destinations are not supported")


def authority(value: str) -> str:
    host, separator, port = value.rpartition(":")
    if not separator or port != "443":
        raise ValueError("Only explicit domain:443 CONNECT destinations are supported")
    return domain(host)


class Policy:
    def __init__(self, data: dict):
        if not isinstance(data, dict) or set(data) - {"allow", "deny"}:
            raise ValueError("Policy supports only allow and deny lists")
        self.rules = {}
        for kind in ("allow", "deny"):
            entries = data.get(kind, [])
            if not isinstance(entries, list) or len(entries) > 1000:
                raise ValueError("Each policy list must contain at most 1000 domains")
            rules = []
            for entry in entries:
                if not isinstance(entry, str):
                    raise ValueError("Policy domains must be strings")
                wildcard = entry.startswith("*.")
                rules.append((domain(entry[2:] if wildcard else entry), wildcard))
            self.rules[kind] = tuple(rules)

    def allows(self, host: str) -> bool:
        host = domain(host)

        def matches(kind):
            return any(
                host.endswith("." + name) if wildcard else host == name
                for name, wildcard in self.rules[kind]
            )

        return matches("allow") and not matches("deny")


class ReloadingPolicy:
    """Read a bounded policy for each new tunnel; invalid updates deny access.

    Already established tunnels finish within their existing five-minute cap.
    """

    def __init__(self, path):
        self.path = path
        self.load()  # Invalid initial policy must fail startup.

    def load(self):
        with self.path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("Policy exceeds 64 KiB")
        return Policy(json.loads(raw))

    def allows(self, host):
        try:
            return self.load().allows(host)
        except (OSError, ValueError):
            return False


class AuditSink:
    def __init__(self, spool, *, emit=None):
        self.spool = spool
        self.emit = (
            emit
            if emit is not None
            else lambda item: print(json.dumps(item), flush=True)
        )

    def __call__(self, record):
        record = dict(record)
        if record.get("outcome") in {"allowed", "policy_denied"}:
            payload = {
                "event_key": f"proxy:{uuid.uuid4()}",
                "endpoint_key": self.spool.endpoint,
                "hostname": socket.gethostname()[:255],
                "operating_system": {
                    "Windows": "windows",
                    "Linux": "linux",
                    "Darwin": "macos",
                }.get(platform.system(), "other"),
                "occurred_at": dt.datetime.now(dt.UTC).isoformat(),
                "event_type": "network_connection",
                "network_action": "blocked"
                if record["outcome"] == "policy_denied"
                else "allowed",
                "destination_sha256": record.get("destination_sha256"),
                "destination_port": 443,
            }
            try:
                record["audit_delivery"] = (
                    "queued" if self.spool.enqueue(payload) else "queue_full"
                )
            except sqlite3.Error:
                record["audit_delivery"] = "storage_error"
        self.emit(record)


def public_address(records) -> tuple[int, str]:
    if not records:
        raise ValueError("No destination addresses")
    for family, _, _, _, address in records:
        ip = ipaddress.ip_address(address[0])
        if (
            family not in {socket.AF_INET, socket.AF_INET6}
            or not ip.is_global
            or ip.is_multicast
        ):
            raise ValueError("Non-public destination denied")
    return records[0][0], records[0][4][0]


async def connect_public(host):
    records = await asyncio.get_running_loop().getaddrinfo(
        host, 443, type=socket.SOCK_STREAM
    )
    family, address = public_address(records)
    # Connect to a validated numeric address, not a second DNS lookup of host.
    return await asyncio.open_connection(address, 443, family=family)


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (OSError, asyncio.TimeoutError):
        pass


class Gateway:
    def __init__(self, policy, token, *, connector=connect_public, emit=None):
        if not isinstance(token, str) or not re.fullmatch(
            r"[\x21-\x7e]{32,256}", token
        ):
            raise ValueError(
                "CYNUX_PROXY_TOKEN must contain 32–256 printable non-space ASCII characters"
            )
        self.policy = policy
        self.authorization = (
            "Basic " + base64.b64encode(f"cynux:{token}".encode()).decode()
        )
        self.connector = connector
        self.emit = (
            emit
            if emit is not None
            else lambda record: print(json.dumps(record), flush=True)
        )
        self.slots = asyncio.Semaphore(32)

    async def reject(self, writer, code):
        challenge = (
            'Proxy-Authenticate: Basic realm="Cynux local proxy"\r\n'
            if code == 407
            else ""
        )
        writer.write(
            f"HTTP/1.1 {code} Rejected\r\n{challenge}Content-Length: 0\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()

    async def handle(self, reader, writer):
        acquired = False
        upstream = None
        connected = False
        host = None
        outcome = "rejected"
        try:
            if self.slots.locked():
                await self.reject(writer, 503)
                return
            await self.slots.acquire()
            acquired = True
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            if len(raw) > 8192:
                raise ValueError("Headers too large")
            lines = raw.decode("ascii").split("\r\n")
            request = lines[0].split(" ")
            if len(request) != 3 or request[0] != "CONNECT" or request[2] != "HTTP/1.1":
                await self.reject(writer, 405)
                return
            headers = {}
            for line in lines[1:-2]:
                key, separator, value = line.partition(":")
                key = key.lower()
                if (
                    not separator
                    or not re.fullmatch(r"[a-z0-9-]+", key)
                    or key in headers
                ):
                    raise ValueError("Invalid or duplicate header")
                headers[key] = value.strip()
            if not hmac.compare_digest(
                headers.get("proxy-authorization", ""), self.authorization
            ):
                await self.reject(writer, 407)
                return
            if "content-length" in headers or "transfer-encoding" in headers:
                raise ValueError("CONNECT bodies are unsupported")
            host = authority(request[1])
            if headers.get("host", "").lower() != request[1].lower():
                raise ValueError("Host must match CONNECT authority")
            if not self.policy.allows(host):
                await self.reject(writer, 403)
                outcome = "policy_denied"
                return
            remote_reader, upstream = await asyncio.wait_for(self.connector(host), 10)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            connected = True
            outcome = "allowed"

            async def pump(source, destination):
                remaining = 64 * 1024 * 1024
                while remaining:
                    data = await asyncio.wait_for(
                        source.read(min(65536, remaining)), 30
                    )
                    if not data:
                        return
                    destination.write(data)
                    await asyncio.wait_for(destination.drain(), 30)
                    remaining -= len(data)

            tasks = [
                asyncio.create_task(pump(reader, upstream)),
                asyncio.create_task(pump(remote_reader, writer)),
            ]
            try:
                done, _ = await asyncio.wait(
                    tasks, timeout=300, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (
            OSError,
            ValueError,
            UnicodeError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            asyncio.TimeoutError,
        ):
            outcome = "connection_error"
            if not connected:
                try:
                    await self.reject(writer, 502)
                except OSError:
                    pass
        finally:
            if upstream is not None:
                await close(upstream)
            await close(writer)
            if acquired:
                self.slots.release()
            self.emit(
                {
                    "outcome": outcome,
                    "destination_sha256": hashlib.sha256(host.encode()).hexdigest()
                    if host
                    else None,
                }
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="Queue audit events for a running cynux-endpoint collector using this same directory",
    )
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    try:
        gateway = Gateway(
            ReloadingPolicy(args.policy), os.environ.get("CYNUX_PROXY_TOKEN", "")
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    async def serve():
        spool = Spool(args.state_dir / "events.sqlite3") if args.state_dir else None
        if spool:
            gateway.emit = AuditSink(spool)
        try:
            server = await asyncio.start_server(
                gateway.handle, "127.0.0.1", args.port, limit=8192
            )
            async with server:
                await server.serve_forever()
        finally:
            if spool:
                spool.db.close()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
