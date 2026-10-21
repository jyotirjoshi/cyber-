import hashlib
import subprocess
from types import SimpleNamespace

import pytest

from cynux_endpoint.scanner import detection_event, scan_file
from cynux_endpoint import scanner
from cynux_endpoint.agent import Spool


class CycleStop:
    def __init__(self, cycles):
        self.cycles = cycles
        self.waits = []

    def is_set(self):
        return self.cycles == 0

    def wait(self, seconds):
        self.waits.append(seconds)
        self.cycles -= 1
        return self.is_set()


@pytest.mark.parametrize("interval", [-1, 1, 59, 86401])
def test_watch_rejects_unbounded_frequency(interval):
    with pytest.raises(ValueError, match="Repeat interval"):
        scanner.run_scans(["sample"], "clamscan", None, interval=interval)


def test_stopped_watch_does_not_scan(tmp_path):
    assert (
        scanner.run_scans([tmp_path / "sample"], "clamscan", None, stop=CycleStop(0))
        == 0
    )


def test_failed_delivery_retains_detection(tmp_path):
    spool = Spool(tmp_path / "queue.db")
    output = []

    def offline(_):
        raise OSError("offline")

    try:
        result = scanner.run_scans(
            [tmp_path / "sample"],
            "clamscan",
            spool,
            sender=offline,
            emit=output.append,
            scan=lambda *_: {
                "status": "detected",
                "sha256": "a" * 64,
                "signature": "Test",
            },
        )
        assert result == 2
        assert output[-1]["events_retained"] is True
        assert spool.db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    finally:
        spool.db.close()


def test_watch_rescans_but_deduplicates_unchanged_detections(tmp_path):
    spool = Spool(tmp_path / "queue.db")
    stop = CycleStop(3)
    output = []
    try:
        result = scanner.run_scans(
            [tmp_path / "sample"],
            "clamscan",
            spool,
            interval=60,
            stop=stop,
            emit=output.append,
            scan=lambda *_: {
                "status": "detected",
                "sha256": "a" * 64,
                "signature": "Test",
            },
        )
        assert result == 1
        assert len(output) == 3
        assert stop.waits == [60, 60, 60]
        assert spool.db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert output[-1]["delivery"] == "already_queued"
    finally:
        spool.db.close()


def test_watch_retries_full_queue_without_losing_detection(tmp_path):
    spool = Spool(tmp_path / "queue.db", capacity=0)
    stop = CycleStop(2)
    output = []

    def emit(record):
        output.append(record)
        spool.capacity = 10

    try:
        assert (
            scanner.run_scans(
                [tmp_path / "sample"],
                "clamscan",
                spool,
                interval=60,
                stop=stop,
                emit=emit,
                scan=lambda *_: {
                    "status": "detected",
                    "sha256": "a" * 64,
                    "signature": "Test",
                },
            )
            == 2
        )
        assert [item["delivery"] for item in output] == ["queue_full", "queued"]
        assert spool.db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    finally:
        spool.db.close()


def test_clean_rescan_allows_reappearing_detection(tmp_path):
    spool = Spool(tmp_path / "queue.db")
    results = iter(
        [
            {"status": "detected", "sha256": "a" * 64, "signature": "Test"},
            {"status": "clean", "sha256": "b" * 64},
            {"status": "detected", "sha256": "a" * 64, "signature": "Test"},
        ]
    )
    try:
        scanner.run_scans(
            [tmp_path / "sample"],
            "clamscan",
            spool,
            interval=60,
            stop=CycleStop(3),
            emit=lambda _: None,
            scan=lambda *_: next(results),
        )
        assert spool.db.execute("SELECT count(*) FROM events").fetchone()[0] == 2
    finally:
        spool.db.close()


@pytest.mark.parametrize(
    "code, output, expected",
    [
        (0, b"stdin: OK\n", "clean"),
        (1, b"stdin: Win.Test.Signature FOUND\n", "detected"),
        (2, b"database missing", "error"),
        (0, b"", "error"),
        (1, b"stdin: Heuristics.Limits.Exceeded.MaxScanSize FOUND\n", "skipped"),
    ],
)
def test_scan_verdicts_and_exact_bytes(tmp_path, code, output, expected):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"harmless fixture")

    def run(argv, **kwargs):
        assert argv[-1] == "-"
        assert kwargs["input"] == b"harmless fixture"
        assert kwargs["timeout"] == 120
        return SimpleNamespace(returncode=code, stdout=output)

    result = scan_file(path, "clamscan", run=run)
    assert result["status"] == expected
    assert result["sha256"] == hashlib.sha256(b"harmless fixture").hexdigest()
    if expected == "detected":
        event = detection_event("device", result)
        assert event["file_sha256"] == result["sha256"]
        assert event["scanner_engine"] == "clamav"
        assert "executable_path" not in event


def test_engine_timeout_is_not_clean(tmp_path):
    path = tmp_path / "sample"
    path.write_bytes(b"test")

    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired("clamscan", 120)

    assert scan_file(path, "clamscan", run=run)["status"] == "error"


def test_directories_are_not_scanned_recursively(tmp_path):
    assert scan_file(tmp_path, "clamscan")["reason"] == "not_regular_file"


def test_non_detection_cannot_be_reported_as_malware():
    with pytest.raises(ValueError):
        detection_event("device", {"status": "error"})
