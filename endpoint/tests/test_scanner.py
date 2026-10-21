import hashlib
import subprocess
from types import SimpleNamespace

import pytest

from cynux_endpoint.scanner import detection_event, scan_file


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
