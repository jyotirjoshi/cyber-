"""Read-only, tenant-scoped AWS Security Hub findings connector."""

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

PROVIDER = "AWS Security Hub"
_REGION = re.compile(r"\A[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_ACCOUNT_ID = re.compile(r"\A\d{12}\Z")
_PAGE_SIZE = 100
_MAX_PAGES = 500
_MAX_FINDINGS = 50_000
_MAX_SYNC_SECONDS = 300


class AwsSecurityHubClient:
    """Read complete, bounded active-finding snapshots using GetFindings only."""

    def __init__(self, settings: Settings) -> None:
        self._cfg = settings.aws_security_hub
        self._client: Any | None = None

    def _scope(self) -> tuple[str, list[str]]:
        if not self._cfg.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set region, access key ID, secret access key, and selected AWS account IDs.",
            )
        region = str(self._cfg.region or "")
        account_ids = list(self._cfg.account_ids)
        if (
            _REGION.fullmatch(region) is None
            or not 1 <= len(account_ids) <= 20
            or any(_ACCOUNT_ID.fullmatch(value) is None for value in account_ids)
            or len(set(account_ids)) != len(account_ids)
        ):
            raise IntegrationError("Invalid AWS region or account scope.", provider=PROVIDER)
        return region, account_ids

    def _require(self) -> Any:
        region, _ = self._scope()
        if self._client is None:
            self._client = boto3.client(
                "securityhub",
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
                    user_agent_extra="cynux-security-hub/1",
                ),
            )
        return self._client

    def _page(self, next_token: str | None) -> tuple[list[dict[str, Any]], str | None]:
        _, account_ids = self._scope()
        request: dict[str, Any] = {
            "Filters": {
                "AwsAccountId": [
                    {"Value": account_id, "Comparison": "EQUALS"} for account_id in account_ids
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [
                    {"Value": "NEW", "Comparison": "EQUALS"},
                    {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                ],
            },
            "SortCriteria": [{"Field": "UpdatedAt", "SortOrder": "desc"}],
            "MaxResults": _PAGE_SIZE,
        }
        if next_token is not None:
            request["NextToken"] = next_token
        try:
            payload = self._require().get_findings(**request)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {
                "AccessDenied",
                "AccessDeniedException",
                "InvalidAccessException",
                "InvalidClientTokenId",
                "UnrecognizedClientException",
            }:
                raise IntegrationAuthError(PROVIDER) from exc
            raise IntegrationError("AWS Security Hub rejected the findings request.", provider=PROVIDER) from exc
        except BotoCoreError as exc:
            raise IntegrationError("AWS Security Hub could not be reached.", provider=PROVIDER) from exc
        findings = payload.get("Findings") if isinstance(payload, dict) else None
        if (
            not isinstance(findings, list)
            or len(findings) > _PAGE_SIZE
            or any(not isinstance(item, dict) for item in findings)
        ):
            raise IntegrationError("AWS Security Hub returned an incomplete findings page.", provider=PROVIDER)
        allowed_accounts = set(account_ids)
        if any(str(item.get("AwsAccountId") or "") not in allowed_accounts for item in findings):
            raise IntegrationError("AWS Security Hub returned a finding outside the selected accounts.", provider=PROVIDER)
        token = payload.get("NextToken")
        if token in (None, ""):
            return findings, None
        if not isinstance(token, str) or len(token) > 4096:
            raise IntegrationError("AWS Security Hub returned an invalid pagination token.", provider=PROVIDER)
        return findings, token

    def _list_findings(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        seen_ids: set[str] = set()
        for _ in range(_MAX_PAGES):
            page, next_token = self._page(token)
            for finding in page:
                finding_id = finding.get("Id")
                if not isinstance(finding_id, str) or not finding_id or finding_id in seen_ids:
                    raise IntegrationError(
                        "AWS Security Hub returned an invalid or repeated finding ID.",
                        provider=PROVIDER,
                    )
                seen_ids.add(finding_id)
                records.append(finding)
                if len(records) > _MAX_FINDINGS:
                    raise IntegrationError("AWS Security Hub finding limit exceeded.", provider=PROVIDER)
            if next_token is None:
                return records
            if not page or next_token in seen_tokens:
                raise IntegrationError("AWS Security Hub pagination did not advance.", provider=PROVIDER)
            seen_tokens.add(next_token)
            token = next_token
        raise IntegrationError("AWS Security Hub page limit exceeded.", provider=PROVIDER)

    async def list_findings(self) -> list[dict[str, Any]]:
        try:
            async with asyncio.timeout(_MAX_SYNC_SECONDS):
                return await asyncio.to_thread(self._list_findings)
        except TimeoutError as exc:
            raise IntegrationTimeoutError("AWS Security Hub sync timed out.", provider=PROVIDER) from exc

    async def ping(self) -> bool:
        await asyncio.to_thread(self._page, None)
        return True

    async def aclose(self) -> None:
        self._client = None


__all__ = ["AwsSecurityHubClient", "PROVIDER"]
