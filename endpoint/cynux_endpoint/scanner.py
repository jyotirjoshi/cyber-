"""On-demand local ClamAV scanning with durable Cynux detection delivery."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import uuid
from pathlib import Path

from cynux_endpoint.agent import Spool, transport

MAX_BYTES = 32 * 1024 * 1024


def scan_file(path: Path, executable: str, *, run=subprocess.run) -> dict:
    # Only bounded regular files are scanned. Read once so the digest describes
    # the exact bytes sent to the engine, even if the original changes later.
    if path.is_symlink() or not path.is_file():
        return {"status": "error", "reason": "not_regular_file"}
    try:
        with path.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
    except OSError:
        return {"status": "error", "reason": "unreadable"}
    if len(data) > MAX_BYTES:
        return {"status": "skipped", "reason": "file_size_limit"}
    digest = hashlib.sha256(data).hexdigest()
    try:
        result = run(
            [
                executable,
                "--no-summary",
                "--stdout",
                "--max-filesize=32M",
                "--max-scansize=64M",
                "--alert-exceeds-max=yes",
                "-",
            ],
            input=data,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "status": "error",
            "reason": "engine_unavailable_or_timeout",
            "sha256": digest,
        }
    output = result.stdout.decode("utf-8", errors="replace")
    matches = [
        line.removeprefix("stdin: ").removesuffix(" FOUND")
        for line in output.splitlines()
        if line.startswith("stdin: ") and line.endswith(" FOUND")
    ]
    if result.returncode == 1 and matches:
        if any("Exceeded" in value for value in matches):
            return {
                "status": "skipped",
                "reason": "engine_scan_limit",
                "sha256": digest,
            }
        return {"status": "detected", "sha256": digest, "signature": matches[0][:256]}
    if result.returncode == 0 and "stdin: OK" in output:
        return {"status": "clean", "sha256": digest}
    return {"status": "error", "reason": "engine_scan_failed", "sha256": digest}


def detection_event(endpoint: str, result: dict) -> dict:
    if result.get("status") != "detected":
        raise ValueError("Only confirmed scanner detections produce malware events")
    return {
        "event_key": f"scan:{uuid.uuid4()}",
        "endpoint_key": endpoint,
        "hostname": socket.gethostname()[:255],
        "operating_system": {
            "Windows": "windows",
            "Linux": "linux",
            "Darwin": "macos",
        }.get(platform.system(), "other"),
        "occurred_at": dt.datetime.now(dt.UTC).isoformat(),
        "event_type": "malware",
        "file_sha256": result["sha256"],
        "malware_signature": result["signature"],
        "scanner_engine": "clamav",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument(
        "--server", help="Deliver queued detections to this Cynux HTTPS origin"
    )
    args = parser.parse_args()
    executable = shutil.which("clamscan")
    if not executable:
        parser.error(
            "Install ClamAV and update its signature database with freshclam first"
        )
    sender = (
        transport(args.server, os.environ.get("CYNUX_ENDPOINT_API_KEY", ""))
        if args.server
        else None
    )
    spool = Spool(args.state_dir / "events.sqlite3")
    detected = failed = False
    try:
        for path in args.files:
            result = scan_file(path, executable)
            if result["status"] == "detected":
                detected = True
                if not spool.enqueue(detection_event(spool.endpoint, result)):
                    result["delivery"] = "queue_full"
                    failed = True
                else:
                    result["delivery"] = "queued"
            failed |= result["status"] in {"error", "skipped"}
            print(json.dumps({"file": str(path), **result}))
        if sender:
            try:
                spool.drain(sender)
            except OSError:
                print(
                    json.dumps(
                        {
                            "delivery": "deferred",
                            "reason": "delivery_failed",
                            "events_retained": True,
                        }
                    )
                )
                failed = True
    finally:
        spool.db.close()
    return 2 if failed else 1 if detected else 0


if __name__ == "__main__":
    raise SystemExit(main())
