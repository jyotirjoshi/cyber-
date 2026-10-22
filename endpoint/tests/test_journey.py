import datetime as dt

import pytest

from cynux_endpoint import journey


def test_target_validation_requires_public_https_and_strips_secrets():
    target = journey.validate_target(
        "https://shop.example/checkout?secret=hidden",
        resolver=lambda *_: [(None, None, None, None, ("93.184.216.34", 443))],
    )
    assert target.host == "shop.example"
    assert target.path == "/checkout"
    assert "secret" not in target.path

    with pytest.raises(ValueError):
        journey.validate_target("http://shop.example")
    with pytest.raises(ValueError):
        journey.validate_target("https://user:pass@shop.example")
    with pytest.raises(ValueError):
        journey.validate_target("https://127.0.0.1/admin")


def test_probe_payload_contains_digest_and_metrics_but_not_url():
    payload = journey.probe_payload(
        journey_name="Customer checkout",
        journey_key="checkout",
        location="branch-mumbai",
        target_digest="a" * 64,
        result=journey.ProbeResult(
            available=True,
            status_code=200,
            dns_ms=10.0,
            connect_ms=20.0,
            tls_ms=30.0,
            ttfb_ms=80.0,
            total_ms=100.0,
            certificate_days_remaining=90,
            error_code=None,
        ),
        occurred_at=dt.datetime(2026, 10, 22, tzinfo=dt.UTC),
    )
    assert payload["target_digest"] == "a" * 64
    assert payload["total_ms"] == 100.0
    assert "url" not in payload
    assert "host" not in payload
