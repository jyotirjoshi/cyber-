"""An imported API contract must never expand an approved scan scope."""

import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from app.agent.nodes.scan import _jobs_for_scope
from app.core.config import Settings
from app.core.crypto import Secret
from app.db.enums import ScannerName
from app.scanners.base import ScannerRequest
from app.scanners.nuclei import NucleiAdapter
from app.scanners.openapi_scope import OpenAPIScopeError, normalize_openapi_spec
from app.scanners.runner import DockerRunner
from app.scanners.zap import ZapAdapter
from app.services.job import _options_for


def _spec(server: str = "https://api.example.com") -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Example", "version": "1"},
        "servers": [{"url": server}],
        "paths": {"/users": {"get": {"responses": {"200": {"description": "OK"}}}}},
    }


def test_normalizes_in_scope_spec_to_exact_approved_origin() -> None:
    result = normalize_openapi_spec(_spec(), "https://api.example.com")
    assert result["servers"] == [{"url": "https://api.example.com"}]
    assert result["paths"]["/users"]["get"]


def test_does_not_expand_an_approved_path_prefix() -> None:
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(_spec(), "https://api.example.com/v1")
    result = normalize_openapi_spec(_spec("https://api.example.com/v1"), "https://api.example.com/v1")
    assert result["servers"] == [{"url": "https://api.example.com/v1"}]


@pytest.mark.parametrize(
    "server",
    [
        "https://other.example.com",
        "http://api.example.com",
        "https://api.example.com:8443",
        "https://user:pass@api.example.com",
        "https://api.example.com/{tenant}",
        "//api.example.com",
    ],
)
def test_rejects_server_outside_exact_origin(server: str) -> None:
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(_spec(server), "https://api.example.com")


@pytest.mark.parametrize("reference", ["https://evil.example/x", "file:///etc/passwd", "../other.yaml"])
def test_rejects_external_references(reference: str) -> None:
    spec = _spec()
    spec["paths"]["/users"]["get"]["responses"]["200"]["content"] = {
        "application/json": {"schema": {"$ref": reference}}
    }
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(spec, "https://api.example.com")


def test_rejects_operation_server_override_and_callbacks() -> None:
    spec = _spec()
    spec["paths"]["/users"]["get"]["servers"] = [{"url": "https://evil.example"}]
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(spec, "https://api.example.com")
    del spec["paths"]["/users"]["get"]["servers"]
    spec["paths"]["/users"]["get"]["callbacks"] = {"event": {}}
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(spec, "https://api.example.com")


def test_rejects_embedded_secrets_and_webhooks() -> None:
    spec = _spec()
    spec["components"] = {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "value": "secret"}}}
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(spec, "https://api.example.com")
    del spec["components"]
    spec["webhooks"] = {"notify": {}}
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(spec, "https://api.example.com")


def test_rejects_oversized_spec() -> None:
    spec = _spec()
    spec["info"]["description"] = "x" * 1_000_000
    with pytest.raises(OpenAPIScopeError):
        normalize_openapi_spec(spec, "https://api.example.com")


@pytest.mark.parametrize("scanner,adapter", [(ScannerName.NUCLEI, NucleiAdapter()), (ScannerName.ZAP, ZapAdapter())])
def test_api_scanner_uses_local_spec_not_remote_url(tmp_path, scanner, adapter) -> None:
    request = ScannerRequest(
        scanner=scanner,
        targets=("https://api.example.com",),
        workdir=tmp_path,
        timeout_seconds=300,
        options={"api_spec": _spec()},
    )
    adapter.prepare(request)
    argv = adapter.build_argv(request)
    assert (tmp_path / "api-openapi.json").is_file()
    assert "https://api.example.com" not in argv
    assert "openapi" in argv
    assert "api-openapi.json" in " ".join(argv)


def test_zap_jobs_are_per_target_so_no_approved_api_is_silently_skipped() -> None:
    jobs = _jobs_for_scope(
        ["https://first.example.com", "https://api.example.com"], [ScannerName.ZAP]
    )
    assert jobs == [
        (ScannerName.ZAP, ["https://first.example.com"]),
        (ScannerName.ZAP, ["https://api.example.com"]),
    ]


def test_job_options_attach_contract_only_to_its_scoped_api_target() -> None:
    settings = SimpleNamespace(scanner=SimpleNamespace(max_concurrent_jobs_per_org=2))
    assessment = SimpleNamespace(extra_data={"api_scan": {"target": "https://api.example.com", "spec": _spec()}})
    api_job = SimpleNamespace(scanner=ScannerName.NUCLEI.value, targets=["https://api.example.com"])
    unrelated = SimpleNamespace(scanner=ScannerName.NUCLEI.value, targets=["https://other.example.com"])
    assert _options_for(api_job, settings, assessment)["api_spec"] == _spec()
    assert "api_spec" not in _options_for(unrelated, settings, assessment)


def test_job_options_decrypt_token_only_for_matching_nuclei_api_job(monkeypatch) -> None:
    settings = SimpleNamespace(scanner=SimpleNamespace(max_concurrent_jobs_per_org=2))
    assessment = SimpleNamespace(
        extra_data={"api_scan": {"target": "https://api.example.com", "spec": _spec()}},
        api_auth_ciphertext="encrypted-placeholder",
    )
    decrypted = []

    class Cipher:
        def decrypt(self, value):
            decrypted.append(value)
            return Secret("scoped-token")

    monkeypatch.setattr("app.services.job.get_cipher", lambda settings: Cipher())
    other = SimpleNamespace(scanner=ScannerName.NUCLEI.value, targets=["https://other.example.com"])
    zap = SimpleNamespace(scanner=ScannerName.ZAP.value, targets=["https://api.example.com"])
    nuclei = SimpleNamespace(scanner=ScannerName.NUCLEI.value, targets=["https://api.example.com"])
    assert "api_auth_token" not in _options_for(other, settings, assessment)
    assert _options_for(zap, settings, assessment)["api_auth_token"].reveal() == "scoped-token"
    assert _options_for(nuclei, settings, assessment)["api_auth_token"].reveal() == "scoped-token"
    assert decrypted == ["encrypted-placeholder", "encrypted-placeholder"]


def test_zap_authenticated_api_scan_stages_hook_without_plaintext_token(tmp_path) -> None:
    token = "test-zap-token-do-not-write"
    request = ScannerRequest(
        scanner=ScannerName.ZAP,
        targets=("https://api.example.com/v1/",),
        workdir=tmp_path,
        timeout_seconds=60,
        options={
            "api_spec": _spec("https://api.example.com/v1"),
            "api_auth_token": Secret(token),
        },
    )
    adapter = ZapAdapter()
    adapter.prepare(request)
    argv = adapter.build_argv(request)
    assert "--hook=/zap/wrk/zap-auth-hook.py" in argv
    assert token not in repr(argv)
    assert token not in (tmp_path / "zap-auth-hook.py").read_text(encoding="utf-8")
    assert token not in (tmp_path / "zap-auth-sender.js").read_text(encoding="utf-8")
    assert "api.example.com" in (tmp_path / "zap-auth-sender.js").read_text(encoding="utf-8")


def test_generated_zap_sender_only_attaches_token_to_exact_approved_url(tmp_path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed to execute the generated JavaScript sender")
    request = ScannerRequest(
        scanner=ScannerName.ZAP,
        targets=("https://api.example.com/v1/",),
        workdir=tmp_path,
        timeout_seconds=60,
        options={"api_spec": _spec("https://api.example.com/v1"), "api_auth_token": Secret("safe-token")},
    )
    ZapAdapter().prepare(request)
    candidates = [
        "https://api.example.com/v1/users",
        "https://api.example.com.evil.test/v1/users",
        "https://api.example.com/v11/users",
        "http://api.example.com/v1/users",
        "https://api.example.com:8443/v1/users",
    ]
    harness = """
const fs = require('fs');
const vm = require('vm');
globalThis.Java = {type: () => ({getenv: () => 'safe-token'})};
vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'));
const values = JSON.parse(process.argv[2]).map(candidate => {
  const url = new URL(candidate);
  const headers = {};
  const uri = {
    getScheme: () => url.protocol.slice(0, -1),
    getHost: () => url.hostname,
    getPort: () => url.port ? Number(url.port) : -1,
    getPath: () => url.pathname,
  };
  const header = {getURI: () => uri, setHeader: (name, value) => {headers[name] = value}};
  sendingRequest({getRequestHeader: () => header}, 0, {});
  return headers.Authorization || null;
});
process.stdout.write(JSON.stringify(values));
"""
    output = subprocess.run(
        [node, "-e", harness, str(tmp_path / "zap-auth-sender.js"), json.dumps(candidates)],  # noqa: S603 - test-controlled Node command and arguments
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(output.stdout) == ["Bearer safe-token", None, None, None, None]


def test_nuclei_auth_is_scoped_to_exact_domain_and_never_in_argv(tmp_path) -> None:
    token = "test-token-never-in-argv"
    request = ScannerRequest(
        scanner=ScannerName.NUCLEI,
        targets=("https://api.example.com",),
        workdir=tmp_path,
        timeout_seconds=300,
        options={"api_spec": _spec(), "api_auth_token": Secret(token)},
    )
    adapter = NucleiAdapter()
    adapter.prepare(request)
    argv = adapter.build_argv(request)
    assert "-sf" in argv
    assert "-or" in argv
    assert token not in repr(argv)
    secret_file = tmp_path / "api-auth.yaml"
    assert secret_file.exists()
    assert '"domains":["api.example.com"]' in secret_file.read_text(encoding="utf-8")
    assert token in secret_file.read_text(encoding="utf-8")


def test_zap_authenticated_report_does_not_archive_bearer_token(tmp_path) -> None:
    token = "test-token-in-zap-alert"
    request = ScannerRequest(
        scanner=ScannerName.ZAP,
        targets=("https://api.example.com",),
        workdir=tmp_path,
        timeout_seconds=60,
        options={"api_spec": _spec(), "api_auth_token": Secret(token)},
    )
    report = tmp_path / "zap.json"
    report.write_text('{"evidence":"Authorization: Bearer ' + token + '"}', encoding="utf-8")
    artifacts = ZapAdapter().collect(request)
    assert len(artifacts) == 1
    assert token not in report.read_text(encoding="utf-8")
    assert "[REDACTED]" in report.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_authenticated_api_scan_runs_in_sandbox_without_retaining_token(tmp_path, monkeypatch) -> None:
    token = "test-api-token-not-logged"
    created = []

    class Container:
        id = "api-scan-container"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            raise AssertionError("authenticated scanner logs must not be retained")

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, **kwargs):
            created.append(kwargs)
            return Container()

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    request = ScannerRequest(
        scanner=ScannerName.NUCLEI,
        targets=("https://api.example.com",),
        workdir=tmp_path,
        timeout_seconds=60,
        options={"api_spec": _spec(), "api_auth_token": Secret(token)},
    )
    result = await DockerRunner(Settings()).run(NucleiAdapter(), request)
    assert result.exit_code == 0
    assert result.stdout_tail == result.stderr_tail == ""
    assert created[0]["privileged"] is False
    assert "-sf" in created[0]["command"]
    assert token not in repr(created)
    assert token not in repr(result)


@pytest.mark.asyncio
async def test_zap_api_scan_produces_importable_report_in_mock_container(tmp_path, monkeypatch) -> None:
    commands = []
    environments = []
    token = "test-zap-scoped-token"

    class Container:
        id = "zap-api-container"
        attrs = {"State": {"Running": False, "ExitCode": 0}}

        def reload(self):
            return None

        def logs(self, **kwargs):
            raise AssertionError("authenticated ZAP logs must not be retained")

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, **kwargs):
            commands.append(kwargs["command"])
            environments.append(kwargs["environment"])
            (tmp_path / "zap.json").write_text('{"site":[]}', encoding="utf-8")
            return Container()

    async def fake_docker(self):
        return SimpleNamespace(containers=Containers())

    monkeypatch.setattr(DockerRunner, "_docker", fake_docker)
    request = ScannerRequest(
        scanner=ScannerName.ZAP,
        targets=("https://api.example.com",),
        workdir=tmp_path,
        timeout_seconds=60,
        options={"api_spec": _spec(), "api_auth_token": Secret(token)},
    )
    result = await DockerRunner(Settings()).run(
        ZapAdapter(), request,
        credential_environment={"CYNUX_ZAP_API_TOKEN": token},
    )
    assert result.exit_code == 0
    assert len(result.importable_artifacts) == 1
    assert commands[0][:2] == ["zap-api-scan.py", "-t"]
    assert environments[0]["CYNUX_ZAP_API_TOKEN"] == token
    assert token not in repr(commands)
    assert token not in repr(result)
