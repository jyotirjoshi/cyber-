import json
import hashlib

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


def test_remote_policy_refresh_verifies_digest_and_fails_closed_when_stale():
    now = [1000.0]
    body = {
        "allow": ["example.com"],
        "deny": ["bad.example.com"],
        "policy_versions": ["policy-1:1"],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    responses = [{**body, "digest": hashlib.sha256(canonical.encode()).hexdigest()}]
    policy = proxy.RemotePolicy(lambda: responses.pop(0), clock=lambda: now[0])

    assert policy.refresh()
    assert policy.allows("example.com")
    assert not policy.allows("bad.example.com")
    now[0] += 301
    assert not policy.allows("example.com")


def test_remote_policy_keeps_last_good_bundle_after_invalid_refresh():
    now = [1000.0]
    body = {"allow": ["example.com"], "deny": [], "policy_versions": ["p:1"]}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    responses = [
        {**body, "digest": hashlib.sha256(canonical.encode()).hexdigest()},
        {**body, "allow": ["attacker.example"], "digest": "0" * 64},
    ]
    policy = proxy.RemotePolicy(lambda: responses.pop(0), clock=lambda: now[0])

    assert policy.refresh()
    assert not policy.refresh()
    assert policy.allows("example.com")
    assert not policy.allows("attacker.example")


def test_fetch_policy_bundle_uses_bearer_auth_and_bounded_endpoint():
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, limit):
            assert limit == 65537
            return b'{"allow":[],"deny":[],"policy_versions":[],"digest":"' + b"0" * 64 + b'"}'

    def opener(request, timeout):
        seen.append((request.full_url, request.headers, timeout))
        return Response()

    result = proxy.fetch_policy_bundle(
        "https://cynux.example/", "endpoint-secret", opener=opener
    )

    assert result["allow"] == []
    assert seen == [
        (
            "https://cynux.example/api/v1/control-plane/secure-web/policy-bundle",
            {"Authorization": "Bearer endpoint-secret", "Accept": "application/json"},
            10,
        )
    ]
