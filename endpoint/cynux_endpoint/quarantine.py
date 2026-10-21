"""Explicit local file containment and non-overwriting recovery.

This does not stop running processes, isolate hosts, or protect against an
administrator. Keep the state directory private and on the source filesystem.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import uuid
import zipfile
from pathlib import Path

MAX_BYTES = 32 * 1024 * 1024


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Select a regular file, not a symlink or directory")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("File exceeds the 32 MiB containment limit")
    return data


def contain(source: Path, state: Path, expected_sha256: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("Expected digest must be a lowercase SHA-256 value")
    data = _read(source)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("File digest no longer matches the reviewed detection")
    if state.is_symlink() or (state / "quarantine").is_symlink():
        raise ValueError("State directory must not be a symlink")
    vault = state / "quarantine"
    vault.mkdir(parents=True, exist_ok=True, mode=0o700)
    identifier = uuid.uuid4().hex
    entry = vault / identifier
    entry.mkdir(mode=0o700)
    record = {
        "id": identifier,
        "original_path": str(source.absolute()),
        "sha256": expected_sha256,
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "status": "pending",
    }
    # Persist intent before moving. A failed operation always retains either
    # the original file or the raw recovery file; it never silently deletes it.
    metadata = entry / "record.json"
    with metadata.open("x", encoding="utf-8") as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    recovery = entry / "recovery.bin"
    try:
        # Same-filesystem atomic relocation only. No copy/unlink fallback that
        # could remove a different file at the original path after a race.
        source.rename(recovery)
        moved = _read(recovery)
        if hashlib.sha256(moved).hexdigest() != expected_sha256:
            raise ValueError(
                "File changed during containment; manual recovery required"
            )
        archive = entry / "payload.zip"
        with archive.open("xb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as bundle:
                bundle.writestr("payload", moved)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            archive.chmod(0o600)
        with zipfile.ZipFile(archive) as bundle:
            if hashlib.sha256(bundle.read("payload")).hexdigest() != expected_sha256:
                raise ValueError("Recovery archive verification failed")
        record["status"] = "contained"
        with metadata.open("w", encoding="utf-8") as stream:
            json.dump(record, stream)
            stream.flush()
            os.fsync(stream.fileno())
        recovery.unlink()
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise RuntimeError(
            f"Containment incomplete: {exc}. Inspect original file and recovery directory {entry}"
        ) from exc
    return record


def restore(state: Path, identifier: str, destination: Path) -> None:
    if not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise ValueError("Invalid quarantine identifier")
    entry = state / "quarantine" / identifier
    for path in (
        state,
        state / "quarantine",
        entry,
        entry / "record.json",
        entry / "payload.zip",
    ):
        if path.is_symlink():
            raise ValueError("Recovery paths must not be symlinks")
    record = json.loads((entry / "record.json").read_text(encoding="utf-8"))
    if record.get("status") != "contained" or record.get("id") != identifier:
        raise ValueError("Incomplete quarantine record; manual recovery required")
    with zipfile.ZipFile(entry / "payload.zip") as bundle:
        info = bundle.getinfo("payload")
        if info.file_size > MAX_BYTES:
            raise ValueError("Recovery payload exceeds size limit")
        with bundle.open(info) as stream:
            data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("Recovery payload digest mismatch")
    # Exclusive creation, never overwrite. The archive remains available even
    # if writing the destination fails or the operator restores more than once.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    quarantine = actions.add_parser("contain")
    quarantine.add_argument("file", type=Path)
    quarantine.add_argument("--expected-sha256", required=True)
    recovery = actions.add_parser("restore")
    recovery.add_argument("id")
    recovery.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "contain":
            print(json.dumps(contain(args.file, args.state_dir, args.expected_sha256)))
        else:
            restore(args.state_dir, args.id, args.destination)
            print(json.dumps({"status": "restored", "id": args.id}))
    except (OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
