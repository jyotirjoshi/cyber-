"""Target-scoped resolution of encrypted scanner credentials."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import Secret, get_cipher
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission, ScannerName
from app.db.models.scan_auth import ScanAuthProfile
from app.db.repository import tenant_select
from app.schemas.scan_auth import ScanAuthProfileIn
from app.services.context import Principal


@dataclass(frozen=True, slots=True)
class ResolvedScannerAuth:
    environment: dict[str, str]
    options: dict[str, Secret]

    def __repr__(self) -> str:
        return "ResolvedScannerAuth([REDACTED])"


def profile_target_matches(target: str, patterns: list[str]) -> bool:
    normalized = target.strip().lower()
    parsed = urlsplit(normalized if "://" in normalized else f"//{normalized}")
    host = parsed.hostname or normalized
    for pattern in patterns:
        candidate = pattern.strip().lower()
        if candidate.startswith(("aws:", "azure:", "gcp:")):
            if normalized == candidate:
                return True
        elif candidate.startswith("*."):
            suffix = candidate[1:]
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif host == candidate or normalized == candidate:
            return True
    return False


def resolve_secret_material(*, auth_type: str, scanner: ScannerName, secret: dict[str, str]) -> ResolvedScannerAuth:
    environment: dict[str, str] = {}
    options: dict[str, Secret] = {}
    if auth_type in {"bearer", "openapi_token"} and scanner in {ScannerName.NUCLEI, ScannerName.ZAP}:
        options["api_auth_token"] = Secret(secret["token"])
    elif auth_type == "aws_static" and scanner == ScannerName.PROWLER_AWS:
        environment = {
            "AWS_ACCESS_KEY_ID": secret["access_key_id"],
            "AWS_SECRET_ACCESS_KEY": secret["secret_access_key"],
            **({"AWS_SESSION_TOKEN": secret["session_token"]} if secret.get("session_token") else {}),
        }
    elif auth_type == "azure_service_principal" and scanner == ScannerName.PROWLER_AZURE:
        environment = {"AZURE_TENANT_ID": secret["tenant_id"], "AZURE_CLIENT_ID": secret["client_id"], "AZURE_CLIENT_SECRET": secret["client_secret"]}
    elif auth_type == "gcp_service_account" and scanner == ScannerName.PROWLER_GCP:
        options["gcp_service_account_json"] = Secret(secret["service_account_json"])
    else:
        raise ValueError("authentication profile is not compatible with scanner")
    return ResolvedScannerAuth(environment=environment, options=options)


async def create_profile(session: AsyncSession, principal: Principal, body: ScanAuthProfileIn, settings: Settings) -> ScanAuthProfile:
    principal.require(Permission.INTEGRATION_MANAGE)
    plaintext = json.dumps(body.secrets, sort_keys=True, separators=(",", ":"))
    row = ScanAuthProfile(
        organization_id=principal.organization_id, name=body.name.strip(), auth_type=body.auth_type,
        target_patterns=body.target_patterns, permitted_scanners=[item.value for item in body.permitted_scanners],
        metadata_=body.metadata, secret_ciphertext=get_cipher(settings).encrypt(plaintext).encode(),
        fingerprint=hashlib.sha256(plaintext.encode()).hexdigest()[:16], hint=plaintext[-4:],
        is_active=body.is_active, created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    return row


async def list_profiles(session: AsyncSession, principal: Principal) -> list[ScanAuthProfile]:
    principal.require(Permission.INTEGRATION_READ)
    rows = (await session.execute(tenant_select(ScanAuthProfile, principal.organization_id).order_by(ScanAuthProfile.name, ScanAuthProfile.id))).scalars().all()
    return list(rows)


async def delete_profile(session: AsyncSession, principal: Principal, profile_id: uuid.UUID) -> None:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = (await session.execute(tenant_select(ScanAuthProfile, principal.organization_id).where(ScanAuthProfile.id == profile_id))).scalar_one_or_none()
    if row is None:
        raise ResourceNotFoundError("scan authentication profile not found")
    await session.delete(row)
    await session.flush()


async def resolve_scanner_credentials(session: AsyncSession, principal: Principal, profile_id: uuid.UUID, scanner: ScannerName, target: str, *, settings: Settings) -> ResolvedScannerAuth:
    principal.require(Permission.ASSESSMENT_CREATE)
    row = (await session.execute(tenant_select(ScanAuthProfile, principal.organization_id).where(ScanAuthProfile.id == profile_id, ScanAuthProfile.is_active.is_(True)))).scalar_one_or_none()
    if row is None or scanner.value not in row.permitted_scanners or not profile_target_matches(target, row.target_patterns):
        raise ResourceNotFoundError("scan authentication profile not found")
    secret = json.loads(get_cipher(settings).decrypt(row.secret_ciphertext.decode()).reveal())
    if not isinstance(secret, dict):
        raise ValueError("invalid encrypted scanner credential")
    if row.auth_type == "gcp_service_account" and scanner == ScannerName.PROWLER_GCP:
        from app.services.gcp_credentials import mint_gcp_access_token

        project = target.removeprefix("gcp:")
        return ResolvedScannerAuth(
            environment={
                "CLOUDSDK_AUTH_ACCESS_TOKEN": mint_gcp_access_token(
                    str(secret["service_account_json"]), project
                ),
                "GOOGLE_CLOUD_PROJECT": project,
            },
            options={},
        )
    if row.auth_type == "aws_role" and scanner == ScannerName.PROWLER_AWS:
        def assume_role() -> dict[str, str]:
            import boto3
            from botocore.config import Config

            arguments = {
                "RoleArn": str(secret["role_arn"]),
                "RoleSessionName": f"cynux-{profile_id.hex[:12]}",
                "DurationSeconds": 3600,
            }
            if secret.get("external_id"):
                arguments["ExternalId"] = str(secret["external_id"])
            response = boto3.client(
                "sts",
                config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1}),
            ).assume_role(**arguments)
            credentials = response["Credentials"]
            return {
                "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
                "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
                "AWS_SESSION_TOKEN": credentials["SessionToken"],
            }

        try:
            environment = await asyncio.to_thread(assume_role)
        except Exception:
            from app.core.errors import UnsafeScannerInvocationError

            raise UnsafeScannerInvocationError("AWS role credentials could not be assumed.") from None
        return ResolvedScannerAuth(environment=environment, options={})
    if row.auth_type in {"basic", "header", "cookie"} and scanner == ScannerName.NUCLEI:
        host = urlsplit(target if "://" in target else f"//{target}").hostname
        if not host:
            raise ResourceNotFoundError("scan authentication profile not found")
        if row.auth_type == "basic":
            document = {"static": [{"type": "basicauth", "domains": [host], "username": secret["username"], "password": secret["password"]}]}
        elif row.auth_type == "header":
            document = {"dynamic": [{"type": "header", "domains": [host], "headers": [{"key": secret["header_name"], "value": secret["header_value"]}]}]}
        else:
            document = {"dynamic": [{"type": "cookie", "domains": [host], "cookies": [secret["cookie"]]}]}
        return ResolvedScannerAuth(
            environment={},
            options={"scan_auth_document": Secret(json.dumps(document, separators=(",", ":")))},
        )
    return resolve_secret_material(auth_type=row.auth_type, scanner=scanner, secret=secret)


__all__ = ["ResolvedScannerAuth", "create_profile", "delete_profile", "list_profiles", "profile_target_matches", "resolve_scanner_credentials", "resolve_secret_material"]
