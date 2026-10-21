import hashlib
import zipfile
from pathlib import Path

import pytest

from cynux_endpoint import quarantine


def test_quarantine_roundtrip_preserves_bytes_without_overwriting(tmp_path):
    source = tmp_path / "sample.txt"
    data = b"harmless test content"
    source.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    record = quarantine.contain(source, tmp_path / "state", digest)
    assert not source.exists()
    assert record["sha256"] == digest
    destination = tmp_path / "restored.txt"
    quarantine.restore(tmp_path / "state", record["id"], destination)
    assert destination.read_bytes() == data
    with pytest.raises(FileExistsError):
        quarantine.restore(tmp_path / "state", record["id"], destination)
    assert destination.read_bytes() == data


def test_wrong_digest_does_not_move_file(tmp_path):
    source = tmp_path / "sample"
    source.write_bytes(b"test")
    with pytest.raises(ValueError, match="digest"):
        quarantine.contain(source, tmp_path / "state", "0" * 64)
    assert source.read_bytes() == b"test"


def test_restore_rejects_traversal(tmp_path):
    with pytest.raises(ValueError, match="identifier"):
        quarantine.restore(tmp_path, "../elsewhere", tmp_path / "output")


def test_quarantine_rejects_directories(tmp_path):
    with pytest.raises(ValueError, match="regular file"):
        quarantine.contain(tmp_path, tmp_path / "state", "0" * 64)


def test_tampered_archive_is_not_restored(tmp_path):
    source = tmp_path / "sample"
    source.write_bytes(b"test")
    record = quarantine.contain(
        source, tmp_path / "state", hashlib.sha256(b"test").hexdigest()
    )
    archive = tmp_path / "state" / "quarantine" / record["id"] / "payload.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("payload", b"changed")
    with pytest.raises(ValueError, match="digest"):
        quarantine.restore(tmp_path / "state", record["id"], tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_archive_failure_keeps_recoverable_raw_file(tmp_path, monkeypatch):
    source = tmp_path / "sample"
    source.write_bytes(b"test")
    original = Path.open

    def fail_archive(path, *args, **kwargs):
        if path.name == "payload.zip":
            raise OSError("simulated disk error")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_archive)
    with pytest.raises(RuntimeError, match="recovery directory"):
        quarantine.contain(
            source, tmp_path / "state", hashlib.sha256(b"test").hexdigest()
        )
    recovery = list((tmp_path / "state" / "quarantine").glob("*/recovery.bin"))
    assert len(recovery) == 1
    assert recovery[0].read_bytes() == b"test"
