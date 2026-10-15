"""Read-only, tenant-scoped Amazon Inspector v2 finding ingestion."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import Settings
from app.core.errors import (
    IntegrationAuthError,
    IntegrationError,
    IntegrationNotConfiguredError,
    IntegrationTimeoutError,
)

PROVIDER = "Amazon Inspector"
_REGION = re.compile(r"\A[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_ACCOUNT_ID = re.compile(r"\A\d{12}\Z")
_PAGE_SIZE = 100
_MAX_PAGES = 500
_MAX_FINDINGS = 50_000
_MAX_SYNC_SECONDS = 300


class AwsInspectorClient:
    """Read a complete bounded ACTIVE snapshot through Inspector2 ListFindings."""

    def __init__(self, settings: Settings) -> None:
        self._cfg = settings.aws_inspector
        self._client: Any | None = None

    def _scope(self) -> tuple[str, list[str]]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set region, access key ID, secret access key, and selected AWS accounts.",
            )
        region = str(self._cfg.region or "")
        accounts = list(self._cfg.account_ids)
        if (
            _REGION.fullmatch(region) is None
            or not 1 <= len(accounts) <= 20
            or any(_ACCOUNT_ID.fullmatch(value) is None for value in accounts)
            or len(set(accounts)) != len(accounts)
        ):
            raise IntegrationError("Invalid AWS region or account scope.", provider=PROVIDER)
        return region, accounts

    def _require(self) -> Any:
        region, _ = self._scope()
        if self._client is None:
            self._client = boto3.client(
                "inspector2",
                region_name=region,
                aws_access_key_id=self._cfg.access_key_id.get_secret_value(),
                aws_secret_access_key=self._cfg.secret_access_key.get_secret_value(),
                aws_session_token=(
                    self._cfg.session_token.get_secret_value() if self._cfg.session_token else None
                ),
                config=Config(
                    connect_timeout=10,
                    read_timeout=45,
                    retries={"max_attempts": 4, "mode": "adaptive"},
                    user_agent_extra="cynux-inspector/1",
                ),
            )
        return self._client

    def _page(self, next_token: str | None) -> tuple[list[dict[str, Any]], str | None]:
        _, accounts = self._scope()
        request: dict[str, Any] = {
            "filterCriteria": {
                "awsAccountId": [
                    {"comparison": "EQUALS", "value": account} for account in accounts
                ],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            },
            "sortCriteria": {"field": "UPDATED_AT", "sortOrder": "DESC"},
            "maxResults": _PAGE_SIZE,
        }
        if next_token is not None:
            request["nextToken"] = next_token
        try:
            payload = self._require().list_findings(**request)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {
                "AccessDeniedException",
                "InvalidClientTokenId",
                "UnrecognizedClientException",
            }:
                raise IntegrationAuthError(PROVIDER) from exc
            raise IntegrationError(
                "Amazon Inspector rejected ListFindings.", provider=PROVIDER
            ) from exc
        except BotoCoreError as exc:
            raise IntegrationError("Amazon Inspector could not be reached.", provider=PROVIDER) from exc
        findings = payload.get("findings") if isinstance(payload, dict) else None
        if (
            not isinstance(findings, list)
            or len(findings) > _PAGE_SIZE
            or any(not isinstance(item, dict) for item in findings)
        ):
            raise IntegrationError(
                "Amazon Inspector returned an invalid findings page.", provider=PROVIDER
            )
        allowed = set(accounts)
        if any(str(item.get("awsAccountId") or "") not in allowed for item in findings):
            raise IntegrationError(
                "Amazon Inspector returned a finding outside the selected accounts.",
                provider=PROVIDER,
            )
        token = payload.get("nextToken")
        if token in (None, ""):
            return findings, None
        if not isinstance(token, str) or len(token) > 1_000_000:
            raise IntegrationError(
                "Amazon Inspector returned an invalid pagination token.", provider=PROVIDER
            )
        return findings, token

    def _list_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        seen_arns: set[str] = set()
        for _ in range(_MAX_PAGES):
            page, next_token = self._page(token)
            for finding in page:
                arn = finding.get("findingArn")
                if not isinstance(arn, str) or not arn or arn in seen_arns:
                    raise IntegrationError(
                        "Amazon Inspector returned an invalid or repeated finding ARN.",
                        provider=PROVIDER,
                    )
                seen_arns.add(arn)
                findings.append(finding)
                if len(findings) > _MAX_FINDINGS:
                    raise IntegrationError(
                        "Amazon Inspector finding limit exceeded.", provider=PROVIDER
                    )
            if next_token is None:
                return findings
            if not page or next_token in seen_tokens:
                raise IntegrationError(
                    "Amazon Inspector pagination did not advance.", provider=PROVIDER
                )
            seen_tokens.add(next_token)
            token = next_token
        raise IntegrationError("Amazon Inspector page limit exceeded.", provider=PROVIDER)

    async def list_findings(self) -> list[dict[str, Any]]:
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await asyncio.to_thread(self._list_findings)
        except TimeoutError as exc:
            raise IntegrationTimeoutError("Amazon Inspector sync timed out.", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await asyncio.to_thread(self._page, None)
        return True

    async def aclose(self) -> None:
        self._client = None


__all__ = ["AwsInspectorClient", "PROVIDER"]
