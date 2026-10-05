"""Recon extraction should stop reading once the bounded inventory is full."""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.db.enums import JobStatus


def test_recon_stops_consuming_source_at_asset_cap(tmp_path, monkeypatch) -> None:
    from app.scanners import recon_assets as parser

    source = tmp_path / "subdomains"
    source.mkdir()
    (source / "subdomains.txt").touch()
    consumed: list[str] = []

    def lines(path):
        for index in range(100):
            value = f"host{index}.example.com"
            consumed.append(value)
            yield value

    monkeypatch.setattr(parser, "_iter_lines", lines)
    monkeypatch.setattr(parser, "MAX_ASSETS", 5)
    assets = parser.parse_recon_output(tmp_path)
    assert [asset.name for asset in assets] == [
        "host0.example.com", "host1.example.com", "host2.example.com",
        "host3.example.com", "host4.example.com",
    ]
    assert len(consumed) == 5


def test_recon_streaming_keeps_httpx_enrichment_and_ip_pair(tmp_path) -> None:
    from app.scanners.recon_assets import parse_recon_output

    hosts = tmp_path / "hosts"
    hosts.mkdir()
    (hosts / "ips.txt").write_text("www.example.com 203.0.113.10\n", encoding="utf-8")
    webs = tmp_path / "webs"
    webs.mkdir()
    (webs / "webs.txt").write_text("https://www.example.com/\n", encoding="utf-8")
    (webs / "web_full_info.txt").write_text(
        json.dumps({
            "url": "https://www.example.com/", "host": "203.0.113.10",
            "port": 443, "scheme": "https", "tech": ["nginx"],
            "title": "Home", "status_code": 200,
        }) + "\n",
        encoding="utf-8",
    )
    assets = parse_recon_output(tmp_path)
    assert len(assets) == 2
    by_name = {asset.name: asset for asset in assets}
    assert by_name["www.example.com"].ip_address == "203.0.113.10"
    web = by_name["https://www.example.com/"]
    assert web.port == 443
    assert web.technology == ("nginx",)
    assert web.http_title == "Home"
    assert web.http_status_code == 200


@pytest.mark.asyncio
async def test_recon_replay_does_not_start_completed_container(monkeypatch) -> None:
    import app.agent.nodes.recon as recon

    org_id, assessment_id, job_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    state = {
        "organization_id": str(org_id), "assessment_id": str(assessment_id),
    }
    plan = recon._ReconPlan(
        seeds=[], hosts=["example.com"], primary_domain="example.com",
        job_id=job_id, timeout_seconds=30,
    )

    class Session:
        async def get(self, model, key):
            assert key == job_id
            return SimpleNamespace(
                organization_id=org_id, status=JobStatus.COMPLETED.value,
            )

    @asynccontextmanager
    async def scope(settings):
        yield Session()

    class Runner:
        async def run(self, *args, **kwargs):
            raise AssertionError("replayed recon must not launch a container")

    monkeypatch.setattr(recon, "session_scope", scope)
    outcome = await recon._execute_recon(
        SimpleNamespace(settings=SimpleNamespace(), runner=Runner()),
        state, SimpleNamespace(), plan,
    )
    assert outcome.assets == []
    assert outcome.degradation is not None
