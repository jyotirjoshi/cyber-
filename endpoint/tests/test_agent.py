import json
from types import SimpleNamespace

import pytest

from cynux_endpoint.agent import Spool, collect, process_event, transport


def event():
    return process_event(
        "endpoint",
        {"pid": 12, "create_time": 1700000000, "name": "python"},
        "host",
        "linux",
    )


def test_retry_retains_exact_payload_and_persistent_identity(tmp_path):
    path = tmp_path / "queue.db"
    spool = Spool(path)
    identity = spool.endpoint
    spool.enqueue(event())

    def fail(body):
        raise OSError("offline")

    with pytest.raises(OSError):
        spool.drain(fail)
    spool.db.close()
    reopened = Spool(path)
    sent = []
    assert reopened.endpoint == identity
    assert reopened.drain(sent.append) == 1
    assert json.loads(sent[0]) == event()
    assert reopened.drain(sent.append) == 0
    reopened.db.close()


def test_spool_is_bounded_and_deduplicated(tmp_path):
    spool = Spool(tmp_path / "queue.db", capacity=1)
    assert spool.enqueue(event())
    assert spool.enqueue(event())
    assert not spool.enqueue({**event(), "event_key": "second"})
    spool.db.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://user:pass@example.com",
        "https://example.com/api",
        "https://example.com?token=x",
    ],
)
def test_transport_rejects_unsafe_server(url):
    with pytest.raises(ValueError):
        transport(url, "cynux_test")


def test_process_event_never_contains_command_line_or_username():
    payload = event()
    assert "command_line" not in payload
    assert "identity_ref" not in payload
    assert payload["event_key"] == event()["event_key"]


def test_restart_does_not_reemit_existing_process(tmp_path):
    path = tmp_path / "queue.db"
    process = SimpleNamespace(
        info={"pid": 12, "create_time": 1700000000, "name": "python", "ppid": 1}
    )
    fake = SimpleNamespace(
        process_iter=lambda fields: [process],
        Process=lambda pid: SimpleNamespace(name=lambda: "parent"),
        Error=RuntimeError,
    )
    spool = Spool(path)
    collect(spool, set(), fake)
    assert spool.drain(lambda body: None) == 1
    spool.db.close()
    spool = Spool(path)
    collect(spool, set(), fake)
    assert spool.drain(lambda body: None) == 0
    spool.db.close()
