import json

from cynux_endpoint.agent import Spool
from cynux_endpoint import proxy


def test_policy_reload_changes_decisions_and_invalid_update_fails_closed(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"allow":["example.com"]}')
    policy = proxy.ReloadingPolicy(path)
    assert policy.allows("example.com")
    path.write_text('{"allow":[]}')
    assert not policy.allows("example.com")
    path.write_text("{broken")
    assert not policy.allows("example.com")
    path.write_text('{"allow":["example.com"]}')
    assert policy.allows("example.com")


def test_proxy_audit_spools_without_raw_destination_or_token(tmp_path):
    spool = Spool(tmp_path / "events.db")
    try:
        emit = proxy.AuditSink(spool, emit=lambda _: None)
        emit({"outcome": "policy_denied", "destination_sha256": "a" * 64})
        sent = []
        assert spool.drain(sent.append) == 1
        event = json.loads(sent[0])
        assert event["event_type"] == "network_connection"
        assert event["network_action"] == "blocked"
        assert event["destination_sha256"] == "a" * 64
        assert "destination_host" not in event
        assert event["endpoint_key"] == spool.endpoint
    finally:
        spool.db.close()


def test_audit_queue_full_reports_loss_without_interrupting_enforcement(tmp_path):
    spool = Spool(tmp_path / "events.db", capacity=0)
    output = []
    try:
        proxy.AuditSink(spool, emit=output.append)(
            {"outcome": "allowed", "destination_sha256": "b" * 64}
        )
        assert output[-1]["audit_delivery"] == "queue_full"
    finally:
        spool.db.close()
