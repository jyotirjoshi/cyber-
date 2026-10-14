"""Static safety contracts Terraform's test language cannot introspect."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_FILE = ROOT / "infra" / "gcp" / "terraform" / "outputs.tf"


def _output_blocks(source: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for match in re.finditer(r'output\s+"([^"]+)"\s*\{', source):
        name = match.group(1)
        depth = 1
        cursor = match.end()
        while cursor < len(source) and depth:
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
            cursor += 1
        assert depth == 0, f"unterminated Terraform output block: {name}"
        blocks[name] = source[match.end() : cursor - 1]
    return blocks


def test_terraform_outputs_expose_only_the_reviewed_non_secret_contract() -> None:
    blocks = _output_blocks(OUTPUTS_FILE.read_text(encoding="utf-8"))

    assert set(blocks) == {
        "project_id",
        "region",
        "network_id",
        "subnetwork_id",
        "artifact_repository",
        "artifact_bucket_name",
        "sql_instance_name",
        "sql_connection_name",
        "redis_endpoint",
        "runtime_service_accounts",
        "secret_resource_ids",
    }

    forbidden_expressions = (
        "random_password.",
        "random_id.",
        ".auth_string",
        "google_storage_hmac_key.artifacts.secret",
        "google_secret_manager_secret_version.",
        "local.secret_payloads",
    )
    for name, body in blocks.items():
        assert not any(expression in body for expression in forbidden_expressions), (
            f"Terraform output {name!r} exposes a secret-producing expression"
        )
