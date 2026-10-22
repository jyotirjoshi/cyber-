"""Polling process sensor with durable, bounded delivery to the Cynux console.

This collector observes processes; it does not provide antivirus prevention.
Short-lived processes between polling intervals may not be observed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import logging
import os
import platform
import signal
import socket
import sqlite3
import threading
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

LOG = logging.getLogger("cynux.endpoint")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Spool:
    def __init__(self, path: Path, capacity: int = 10000):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        if os.name != "nt":
            path.chmod(0o600)
        self.capacity = capacity
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE IF NOT EXISTS events (key TEXT PRIMARY KEY, payload TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS processes (key TEXT PRIMARY KEY);"
        )
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('endpoint', ?)",
                (str(uuid.uuid4()),),
            )
        self.endpoint = self.db.execute(
            "SELECT value FROM metadata WHERE key='endpoint'"
        ).fetchone()[0]

    def enqueue(self, payload: dict) -> bool:
        with self.db:
            if self.db.execute(
                "SELECT 1 FROM events WHERE key=?", (payload["event_key"],)
            ).fetchone():
                return True
            if (
                self.db.execute("SELECT count(*) FROM events").fetchone()[0]
                >= self.capacity
            ):
                return False
            self.db.execute(
                "INSERT INTO events VALUES (?, ?)",
                (payload["event_key"], json.dumps(payload)),
            )
        return True

    def drain(self, send, limit: int = 100) -> int:
        delivered = 0
        for key, payload in self.db.execute(
            "SELECT key, payload FROM events ORDER BY rowid LIMIT ?", (limit,)
        ).fetchall():
            send(payload.encode())
            with self.db:
                self.db.execute("DELETE FROM events WHERE key=?", (key,))
            delivered += 1
        return delivered


def process_event(endpoint: str, info: dict, hostname: str, os_name: str) -> dict:
    identity = f"{endpoint}:{info['pid']}:{info['create_time']}"
    return {
        "event_key": hashlib.sha256(identity.encode()).hexdigest(),
        "endpoint_key": endpoint,
        "hostname": hostname[:255],
        "operating_system": os_name,
        "occurred_at": dt.datetime.fromtimestamp(
            info["create_time"], dt.UTC
        ).isoformat(),
        "event_type": "process_start",
        "process_name": (info.get("name") or "unknown")[:260],
        "parent_process_name": (info.get("parent_name") or "")[:260] or None,
        "signature_status": "unknown",
    }


def json_transport(base_url: str, token: str, path: str):
    url = urlsplit(base_url)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
    ):
        raise ValueError(
            "Server must be an HTTPS origin without credentials, query, or fragment"
        )
    if url.path not in {"", "/"}:
        raise ValueError("Server must be the origin, without an API path")
    if not token.startswith("cynux_"):
        raise ValueError("A scoped Cynux platform API key is required")
    opener = build_opener(NoRedirect())
    if not path.startswith("/api/v1/") or "?" in path or "#" in path:
        raise ValueError("Ingestion path must be a bounded API v1 path")
    endpoint = base_url.rstrip("/") + path

    def send(body: bytes):
        request = Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with opener.open(request, timeout=15) as response:
            if response.status not in {200, 201}:
                raise OSError(f"Unexpected ingestion status {response.status}")

    return send


def transport(base_url: str, token: str):
    return json_transport(base_url, token, "/api/v1/control-plane/endpoint/events")


def collect(spool: Spool, seen: set, psutil) -> set:
    current = set()
    persisted = {row[0] for row in spool.db.execute("SELECT key FROM processes")}
    live_keys = set()
    complete = True
    hostname = socket.gethostname()
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(
        platform.system(), "other"
    )
    for process in psutil.process_iter(["pid", "name", "create_time", "ppid"]):
        try:
            info = dict(process.info)
            if info.get("create_time") is None:
                continue
            identity = (info["pid"], info["create_time"])
            current.add(identity)
            process_key = json.dumps(identity)
            live_keys.add(process_key)
            if identity in seen or process_key in persisted:
                continue
            try:
                info["parent_name"] = psutil.Process(info["ppid"]).name()
            except (psutil.Error, OSError):
                info["parent_name"] = None
            # Queue and inventory checkpoint are atomic so a restart cannot lose
            # an event or resend changed metadata under an already delivered key.
            with spool.db:
                if (
                    spool.db.execute("SELECT count(*) FROM events").fetchone()[0]
                    >= spool.capacity
                ):
                    current.discard(identity)
                    complete = False
                    LOG.warning("Local queue is full; telemetry coverage is degraded")
                    break
                payload = process_event(spool.endpoint, info, hostname, os_name)
                spool.db.execute(
                    "INSERT OR IGNORE INTO events VALUES (?, ?)",
                    (payload["event_key"], json.dumps(payload)),
                )
                spool.db.execute(
                    "INSERT OR IGNORE INTO processes VALUES (?)", (process_key,)
                )
        except (psutil.Error, OSError):
            complete = False
            continue
    if complete:
        with spool.db:
            spool.db.executemany(
                "DELETE FROM processes WHERE key=?",
                ((key,) for key in persisted - live_keys),
            )
    return current


def main():
    import psutil

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.interval <= 300:
        parser.error("interval must be between 1 and 300 seconds")
    logging.basicConfig(level=logging.INFO)
    send = transport(args.server, os.environ.get("CYNUX_ENDPOINT_API_KEY", ""))
    spool = Spool(args.state_dir / "events.sqlite3")
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    seen: set = set()
    failures = 0
    try:
        while not stop.is_set():
            seen = collect(spool, seen, psutil)
            try:
                count = spool.drain(send)
                failures = 0
                if count:
                    LOG.info("Delivered %s process events", count)
            except (HTTPError, URLError, OSError) as exc:
                failures += 1
                LOG.warning(
                    "Delivery deferred (%s); events retained", type(exc).__name__
                )
            stop.wait(min(300, args.interval * (2 ** min(failures, 6))))
    finally:
        spool.db.close()


if __name__ == "__main__":
    main()
