"""Per-organization integration configuration and credential custody (FR-020, SEC-001,
SEC-002).

The central design question this module answers is: *where does a provider client get its
configuration from?*  Every client in :mod:`app.integrations` is constructed from
:class:`~app.core.config.Settings` — deliberately, because that keeps them usable from a
CLI, a test, or the worker without a database.  But Cynux is multi-tenant, and two
organizations legitimately point at two different Jira instances.

Rather than rewrite eight frozen clients to accept a different configuration source, this
module **projects a database row onto a copy of Settings** (:func:`resolve_settings`).
Shared platform services can use deployment defaults; in production, customer-owned
connectors use only their organization's configuration. A caller that needs a scoped client
therefore writes::

    scoped = await resolve_settings(session, principal, IntegrationKind.JIRA,
                                    settings=settings)
    client = JiraClient(scoped, redis)

and every existing client works per-tenant with no change.  The alternative — threading a
credential dict through every client constructor — would have spread secret handling across
eight modules instead of confining it to this one.

Three rules about credentials, all of which the type system cannot enforce for us:

**Credentials are write-only across the API boundary.**  They arrive on
:class:`~app.schemas.integration.IntegrationUpsertIn`, are encrypted before the row is
flushed, and no read path in this module returns plaintext to a caller other than
:func:`resolve_settings`, which hands it straight to a client constructor.  What the API
returns is a fingerprint and a four-character hint.

**Omitting a credential on update keeps the stored one.**  A settings form that submits
only the fields a human edited must not de-provision the ones it left blank.  Clearing a
credential is an explicit empty string, which is why :func:`_apply_credentials`
distinguishes "absent" from "present and empty".

**``config`` is scanned for secret-shaped keys and they are refused.**  ``config`` is
returned to the API in plaintext, so a token smuggled into it would be a disclosure. The
schema documents that the service strips such keys; this module is where that happens, and
it rejects rather than strips, because silently dropping the field an operator just typed
looks like the save failed.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import ipaddress
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.crypto import CredentialDecryptionError, Secret, get_cipher
from app.core.errors import (
    CynuxError,
    IntegrationError,
    IntegrationNotConfiguredError,
    InvalidConfigurationError,
    ResourceNotFoundError,
)
from app.db.base import utcnow
from app.db.enums import AuditOutcome, IntegrationKind, IntegrationStatus, Permission, ScannerName
from app.db.models.canonical import FindingObservation
from app.db.models.identity import Organization
from app.db.models.integration import Integration, IntegrationCredential
from app.db.repository import tenant_select
from app.integrations.aws_inspector import AwsInspectorClient
from app.integrations.aws_security_hub import AwsSecurityHubClient
from app.integrations.azure_defender import AzureDefenderClient
from app.integrations.azure_devops import AzureDevOpsClient
from app.integrations.bitbucket import BitbucketClient
from app.integrations.bugcrowd import BugcrowdClient
from app.integrations.burp_dast import BurpDastClient
from app.integrations.checkmarx import CheckmarxClient
from app.integrations.circuit import CircuitBreaker
from app.integrations.crowdstrike import CrowdStrikeClient
from app.integrations.defectdojo import DefectDojoClient
from app.integrations.dify import DifyClient
from app.integrations.email import EmailSender
from app.integrations.fortify import FortifySscClient
from app.integrations.gcp_scc import GcpSccClient
from app.integrations.github import GitHubClient
from app.integrations.gitlab import GitLabClient
from app.integrations.hackerone import HackerOneClient
from app.integrations.jira import JiraClient
from app.integrations.linear import LinearClient
from app.integrations.misp import MISPClient
from app.integrations.pagerduty import PagerDutyClient
from app.integrations.prisma_cloud import PrismaCloudClient
from app.integrations.qualys import QualysClient
from app.integrations.rapid7 import Rapid7Client
from app.integrations.servicenow import ServiceNowClient
from app.integrations.slack import SlackClient
from app.integrations.snyk import SnykClient
from app.integrations.sonarqube import SonarQubeClient
from app.integrations.splunk import SplunkHecClient
from app.integrations.tenable import TenableClient
from app.integrations.wazuh import WazuhClient
from app.integrations.wiz import WizClient
from app.integrations.zscaler import ZscalerClient
from app.llm.base import LLMMessage
from app.llm.gateway import LLMGateway
from app.scanners.base import ScannerRequest
from app.scanners.prowler import AWS_ADAPTER, AZURE_ADAPTER, GCP_ADAPTER
from app.schemas.integration import (
    ConnectorAssuranceCheckOut,
    ConnectorCertificationOut,
    ConnectorContractTestOut,
    CredentialOut,
    IntegrationHealthOut,
    IntegrationOut,
    IntegrationTestOut,
    IntegrationUpsertIn,
    SourceCoverageOut,
)
from app.services import audit as audit_service
from app.services.audit import AuditAction
from app.services.context import Principal
from app.services.entitlements import assert_integration_capacity, load_entitlements
from app.services.gcp_credentials import mint_gcp_access_token

log = structlog.get_logger(__name__)

#: Substrings that make a ``config`` key look like a credential. Matched against the
#: lowercased key, so ``apiToken`` and ``API_TOKEN`` are both caught.
_SECRET_KEY_MARKERS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "passphrase",
)

# Public numeric/runtime settings whose names describe token *budgets*, not bearer
# credentials. They remain subject to the per-kind config allowlist and value validation.
_PUBLIC_TOKEN_CONFIG_KEYS = frozenset({"max_output_tokens"})


@dataclass(frozen=True, slots=True)
class _KindSpec:
    """How one integration kind maps onto a section of :class:`Settings`.

    ``credentials`` and ``config`` are ``{stored name: settings field}``. The indirection
    exists because the stored names are the operator's vocabulary ("api_token") while the
    settings fields are the deployment's ("slack_bot_token"), and forcing either to match
    the other would make one of the two confusing.
    """

    section: str
    base_url_field: str | None = None
    # ``None`` marks a write-only credential consumed by a dedicated inbound path rather
    # than projected into deployment settings (for example a webhook signing secret).
    credentials: Mapping[str, str | None] = field(default_factory=dict)
    config: Mapping[str, str] = field(default_factory=dict)
    #: Credential slots without which the integration cannot work at all.
    required: tuple[str, ...] = ()


_SPECS: dict[IntegrationKind, _KindSpec] = {
    IntegrationKind.LLM: _KindSpec(
        section="llm",
        credentials={
            "anthropic_api_key": "anthropic_api_key",
            "openai_api_key": "openai_api_key",
            "openrouter_api_key": "openrouter_api_key",
            "google_api_key": "google_api_key",
            "azure_openai_api_key": "azure_openai_api_key",
            "ollama_api_key": "ollama_api_key",
            "vllm_api_key": "vllm_api_key",
        },
        config={
            "provider": "provider",
            "default_model": "default_model",
            "role_models": "role_models",
            "role_providers": "role_providers",
            "anthropic_base_url": "anthropic_base_url",
            "openai_base_url": "openai_base_url",
            "openrouter_base_url": "openrouter_base_url",
            "azure_openai_base_url": "azure_openai_base_url",
            "azure_openai_api_version": "azure_openai_api_version",
            "ollama_base_url": "ollama_base_url",
            "vllm_base_url": "vllm_base_url",
            "max_output_tokens": "max_output_tokens",
            "temperature": "temperature",
        },
    ),
    IntegrationKind.DEFECTDOJO: _KindSpec(
        section="defectdojo",
        base_url_field="base_url",
        credentials={"api_token": "api_token"},
        config={
            "verify_tls": "verify_tls",
            "product_type_name": "product_type_name",
            "deduplication_on_engagement": "deduplication_on_engagement",
            "close_old_findings": "close_old_findings",
        },
        required=("api_token",),
    ),
    IntegrationKind.JIRA: _KindSpec(
        section="jira",
        base_url_field="base_url",
        credentials={"api_token": "api_token", "webhook_secret": None},
        # ``user_email`` is the account the token belongs to, not a secret: Jira's API
        # needs both halves and the address is visible on every issue the bot files.
        config={
            "user_email": "user_email",
            "project_key": "project_key",
            "issue_type": "issue_type",
        },
        required=("api_token",),
    ),
    IntegrationKind.SLACK: _KindSpec(
        section="notify",
        credentials={"bot_token": "slack_bot_token", "webhook_url": "slack_webhook_url"},
        config={"default_channel": "slack_default_channel"},
        # Neither is individually required: a bot token and an incoming webhook are two
        # valid ways to post, and demanding both would reject a working setup.
    ),
    IntegrationKind.EMAIL: _KindSpec(
        section="notify",
        credentials={"smtp_password": "smtp_password"},
        config={
            "smtp_host": "smtp_host",
            "smtp_port": "smtp_port",
            "smtp_username": "smtp_username",
            "smtp_use_tls": "smtp_use_tls",
            "smtp_from": "smtp_from",
        },
    ),
    IntegrationKind.DIFY: _KindSpec(
        section="dify",
        base_url_field="base_url",
        credentials={"dataset_api_key": "dataset_api_key"},
        config={
            "dataset_id": "dataset_id",
            "top_k": "top_k",
            "score_threshold": "score_threshold",
        },
        required=("dataset_api_key",),
    ),
    IntegrationKind.MISP: _KindSpec(
        section="intel",
        base_url_field="misp_base_url",
        credentials={"api_key": "misp_api_key"},
        config={"verify_tls": "misp_verify_tls"},
        required=("api_key",),
    ),
    IntegrationKind.NVD: _KindSpec(
        section="intel",
        base_url_field="nvd_base_url",
        credentials={"api_key": "nvd_api_key"},
        # NVD serves unauthenticated callers at a lower rate limit, so a key is optional.
    ),
    IntegrationKind.GITHUB: _KindSpec(
        section="github",
        base_url_field="base_url",
        credentials={"api_token": "api_token", "webhook_secret": None},
        config={"organization": "organization", "repository": "repository"},
        required=("api_token",),
    ),
    IntegrationKind.GITLAB: _KindSpec(
        section="gitlab",
        base_url_field="base_url",
        credentials={"api_token": "api_token", "webhook_secret": None},
        config={"project_ids": "project_ids", "issue_project": "issue_project"},
        required=("api_token",),
    ),
    IntegrationKind.SERVICENOW: _KindSpec(
        section="servicenow",
        base_url_field="base_url",
        credentials={"api_token": "api_token", "webhook_secret": None},
        config={"table": "table", "assignment_group": "assignment_group"},
        required=("api_token",),
    ),
    IntegrationKind.AZURE_DEVOPS: _KindSpec(
        section="azure_devops",
        base_url_field="base_url",
        credentials={"api_token": "api_token", "webhook_secret": None},
        config={
            "organization": "organization",
            "project": "project",
            "work_item_type": "work_item_type",
        },
        required=("api_token",),
    ),
    IntegrationKind.LINEAR: _KindSpec(
        section="linear",
        base_url_field="base_url",
        credentials={"api_token": "api_token"},
        config={"team_id": "team_id"},
        required=("api_token",),
    ),
    IntegrationKind.PAGERDUTY: _KindSpec(
        section="pagerduty",
        base_url_field="base_url",
        credentials={"routing_key": "routing_key"},
        config={"source": "source"},
        required=("routing_key",),
    ),
    IntegrationKind.SPLUNK: _KindSpec(
        section="splunk",
        base_url_field="base_url",
        credentials={"hec_token": "hec_token"},
        config={
            "index": "index",
            "source": "source",
            "sourcetype": "sourcetype",
            "host": "host",
        },
        required=("hec_token",),
    ),
    IntegrationKind.BURP_DAST: _KindSpec(
        section="burp_dast",
        base_url_field="base_url",
        credentials={"api_key": "api_key"},
        config={"site_ids": "site_ids"},
        required=("api_key",),
    ),
    IntegrationKind.BITBUCKET: _KindSpec(
        section="bitbucket",
        credentials={"api_token": "api_token"},
        config={
            "account_email": "account_email",
            "workspace": "workspace",
            "repository": "repository",
        },
        required=("api_token",),
    ),
    IntegrationKind.WAZUH: _KindSpec(
        section="wazuh",
        base_url_field="base_url",
        credentials={
            "api_username": "api_username",
            "api_password": "api_password",
            "indexer_username": "indexer_username",
            "indexer_password": "indexer_password",
        },
        config={"verify_tls": "verify_tls", "indexer_base_url": "indexer_base_url"},
        required=("api_username", "api_password"),
    ),
    IntegrationKind.ZSCALER: _KindSpec(
        section="zscaler",
        base_url_field="base_url",
        credentials={"client_id": "client_id", "client_secret": "client_secret"},
        config={
            "customer_id": "customer_id",
            "audience": "audience",
            "verify_tls": "verify_tls",
        },
        required=("client_id", "client_secret"),
    ),
    IntegrationKind.SONARQUBE: _KindSpec(
        section="sonarqube",
        base_url_field="base_url",
        credentials={"api_token": "api_token"},
        config={"project_keys": "project_keys"},
        required=("api_token",),
    ),
    IntegrationKind.SNYK: _KindSpec(
        section="snyk",
        base_url_field="base_url",
        credentials={"api_token": "api_token"},
        config={"organization_id": "organization_id"},
        required=("api_token",),
    ),
    IntegrationKind.TENABLE: _KindSpec(
        section="tenable",
        base_url_field="base_url",
        credentials={"access_key": "access_key", "secret_key": "secret_key"},
        config={"scan_ids": "scan_ids"},
        required=("access_key", "secret_key"),
    ),
    IntegrationKind.QUALYS: _KindSpec(
        section="qualys",
        base_url_field="base_url",
        credentials={"username": "username", "password": "password"},
        config={"asset_ip": "asset_ip"},
        required=("username", "password"),
    ),
    IntegrationKind.RAPID7: _KindSpec(
        section="rapid7",
        base_url_field="base_url",
        credentials={"username": "username", "password": "password"},
        config={"asset_ids": "asset_ids"},
        required=("username", "password"),
    ),
    IntegrationKind.WIZ: _KindSpec(
        section="wiz",
        credentials={"client_id": "client_id", "client_secret": "client_secret"},
        config={"region": "region", "project_ids": "project_ids"},
        required=("client_id", "client_secret"),
    ),
    IntegrationKind.PRISMA_CLOUD: _KindSpec(
        section="prisma_cloud",
        base_url_field="base_url",
        credentials={"access_key_id": "access_key_id", "secret_key": "secret_key"},
        config={"cloud_account_ids": "cloud_account_ids"},
        required=("access_key_id", "secret_key"),
    ),
    IntegrationKind.CROWDSTRIKE: _KindSpec(
        section="crowdstrike",
        base_url_field="base_url",
        credentials={"client_id": "client_id", "client_secret": "client_secret"},
        required=("client_id", "client_secret"),
    ),
    IntegrationKind.AWS_SECURITY_HUB: _KindSpec(
        section="aws_security_hub",
        credentials={
            "access_key_id": "access_key_id",
            "secret_access_key": "secret_access_key",
            "session_token": "session_token",
        },
        config={"region": "region", "account_ids": "account_ids"},
        required=("access_key_id", "secret_access_key"),
    ),
    IntegrationKind.AWS_INSPECTOR: _KindSpec(
        section="aws_inspector",
        credentials={
            "access_key_id": "access_key_id",
            "secret_access_key": "secret_access_key",
            "session_token": "session_token",
        },
        config={"region": "region", "account_ids": "account_ids"},
        required=("access_key_id", "secret_access_key"),
    ),
    IntegrationKind.HACKERONE: _KindSpec(
        section="hackerone",
        credentials={"api_username": "api_username", "api_token": "api_token"},
        config={"program_handles": "program_handles"},
        required=("api_username", "api_token"),
    ),
    IntegrationKind.BUGCROWD: _KindSpec(section="bugcrowd", credentials={"token_username": "token_username", "token_password": "token_password"}, config={"engagement_codes": "engagement_codes"}, required=("token_username", "token_password")),
    IntegrationKind.CHECKMARX: _KindSpec(section="checkmarx", base_url_field="base_url", credentials={"client_id": "client_id", "client_secret": "client_secret"}, config={"auth_url": "auth_url", "tenant": "tenant", "projects": "projects"}, required=("client_id", "client_secret")),
    IntegrationKind.FORTIFY: _KindSpec(section="fortify", base_url_field="base_url", credentials={"automation_token": "automation_token"}, config={"application_versions": "application_versions"}, required=("automation_token",)),
    IntegrationKind.AZURE_DEFENDER: _KindSpec(
        section="azure_defender",
        credentials={
            "tenant_id": "tenant_id",
            "client_id": "client_id",
            "client_secret": "client_secret",
        },
        config={"subscription_id": "subscription_id"},
        required=("tenant_id", "client_id", "client_secret"),
    ),
    IntegrationKind.GCP_SCC: _KindSpec(
        section="gcp_scc",
        credentials={"service_account_json": "service_account_json"},
        config={"project_id": "project_id", "location": "location"},
        required=("service_account_json",),
    ),
    IntegrationKind.PROWLER_AWS: _KindSpec(
        section="scanner",
        credentials={
            "access_key_id": "aws_access_key_id",
            "secret_access_key": "aws_secret_access_key",
            "session_token": "aws_session_token",
        },
        config={"account_id": "aws_account_id"},
        required=("access_key_id", "secret_access_key"),
    ),
    IntegrationKind.PROWLER_AZURE: _KindSpec(
        section="scanner",
        credentials={
            "client_id": "azure_client_id",
            "tenant_id": "azure_tenant_id",
            "client_secret": "azure_client_secret",
        },
        config={"account_id": "azure_subscription_id"},
        required=("client_id", "tenant_id", "client_secret"),
    ),
    IntegrationKind.PROWLER_GCP: _KindSpec(
        section="scanner",
        credentials={"service_account_json": "gcp_service_account_json"},
        config={"account_id": "gcp_project_id"},
        required=("service_account_json",),
    ),
}

#: Kinds the MVP can store configuration for but cannot yet talk to (FR-028). Kept in the
#: table so the schema and UI can be built against them, and so an operator who configures
#: one is told plainly rather than seeing a silent no-op.
_UNIMPLEMENTED: frozenset[IntegrationKind] = frozenset()

# Providers whose APIs expose bounded finding feeds and therefore support the
# worker's durable continuous-ingestion scheduler.
CONTINUOUS_SYNC_KINDS: frozenset[IntegrationKind] = frozenset(
    {
        IntegrationKind.GITHUB,
        IntegrationKind.GITLAB,
        IntegrationKind.WAZUH,
        IntegrationKind.SONARQUBE,
        IntegrationKind.SNYK,
        IntegrationKind.TENABLE,
        IntegrationKind.QUALYS,
        IntegrationKind.RAPID7,
        IntegrationKind.WIZ,
        IntegrationKind.PRISMA_CLOUD,
        IntegrationKind.CROWDSTRIKE,
        IntegrationKind.AWS_SECURITY_HUB,
        IntegrationKind.AWS_INSPECTOR,
        IntegrationKind.HACKERONE,
        IntegrationKind.BUGCROWD,
        IntegrationKind.CHECKMARX,
        IntegrationKind.FORTIFY,
        IntegrationKind.AZURE_DEFENDER,
        IntegrationKind.GCP_SCC,
        IntegrationKind.BURP_DAST,
    }
)

# These connectors act on customer-owned accounts. A deployment credential must never
# become an implicit credential for an unrelated organization in a hosted SaaS.
_TENANT_PRIVATE_KINDS: frozenset[IntegrationKind] = frozenset(
    {
        IntegrationKind.JIRA,
        IntegrationKind.SERVICENOW,
        IntegrationKind.AZURE_DEVOPS,
        IntegrationKind.LINEAR,
        IntegrationKind.PAGERDUTY,
        IntegrationKind.SPLUNK,
        IntegrationKind.BURP_DAST,
        IntegrationKind.DIFY,
        IntegrationKind.MISP,
        IntegrationKind.GITHUB,
        IntegrationKind.GITLAB,
        IntegrationKind.BITBUCKET,
        IntegrationKind.WAZUH,
        IntegrationKind.SONARQUBE,
        IntegrationKind.SNYK,
        IntegrationKind.TENABLE,
        IntegrationKind.QUALYS,
        IntegrationKind.RAPID7,
        IntegrationKind.WIZ,
        IntegrationKind.PRISMA_CLOUD,
        IntegrationKind.CROWDSTRIKE,
        IntegrationKind.AWS_SECURITY_HUB,
        IntegrationKind.AWS_INSPECTOR,
        IntegrationKind.HACKERONE,
        IntegrationKind.BUGCROWD,
        IntegrationKind.CHECKMARX,
        IntegrationKind.FORTIFY,
        IntegrationKind.AZURE_DEFENDER,
        IntegrationKind.GCP_SCC,
        IntegrationKind.PROWLER_AWS,
        IntegrationKind.PROWLER_AZURE,
        IntegrationKind.PROWLER_GCP,
        IntegrationKind.ZSCALER,
    }
)

_DEFAULT_NAMES: dict[IntegrationKind, str] = {
    IntegrationKind.LLM: "Bring your own AI provider",
    IntegrationKind.DEFECTDOJO: "DefectDojo",
    IntegrationKind.JIRA: "Jira",
    IntegrationKind.SERVICENOW: "ServiceNow",
    IntegrationKind.AZURE_DEVOPS: "Azure DevOps",
    IntegrationKind.LINEAR: "Linear",
    IntegrationKind.PAGERDUTY: "PagerDuty",
    IntegrationKind.SPLUNK: "Splunk HEC",
    IntegrationKind.BURP_DAST: "Burp Suite DAST",
    IntegrationKind.SLACK: "Slack",
    IntegrationKind.EMAIL: "Email",
    IntegrationKind.DIFY: "Dify Knowledge Base",
    IntegrationKind.MISP: "MISP",
    IntegrationKind.NVD: "NVD",
    IntegrationKind.GITHUB: "GitHub",
    IntegrationKind.GITLAB: "GitLab",
    IntegrationKind.BITBUCKET: "Bitbucket",
    IntegrationKind.WAZUH: "Wazuh",
    IntegrationKind.SONARQUBE: "SonarQube",
    IntegrationKind.SNYK: "Snyk",
    IntegrationKind.TENABLE: "Tenable VM",
    IntegrationKind.QUALYS: "Qualys VM",
    IntegrationKind.RAPID7: "Rapid7 InsightVM",
    IntegrationKind.WIZ: "Wiz",
    IntegrationKind.PRISMA_CLOUD: "Prisma Cloud",
    IntegrationKind.CROWDSTRIKE: "CrowdStrike Falcon Spotlight",
    IntegrationKind.AWS_SECURITY_HUB: "AWS Security Hub",
    IntegrationKind.AWS_INSPECTOR: "Amazon Inspector",
    IntegrationKind.HACKERONE: "HackerOne",
    IntegrationKind.BUGCROWD: "Bugcrowd",
    IntegrationKind.CHECKMARX: "Checkmarx One",
    IntegrationKind.FORTIFY: "Fortify SSC",
    IntegrationKind.AZURE_DEFENDER: "Microsoft Defender for Cloud",
    IntegrationKind.GCP_SCC: "Google Security Command Center",
    IntegrationKind.PROWLER_AWS: "Prowler AWS account",
    IntegrationKind.PROWLER_AZURE: "Prowler Azure subscription",
    IntegrationKind.PROWLER_GCP: "Prowler GCP project",
    IntegrationKind.ZSCALER: "Zscaler Zero Trust Exchange",
}


def validate_aws_account_config(config: Mapping[str, Any]) -> str:
    account = config.get("account_id")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        raise InvalidConfigurationError(
            "invalid AWS account ID",
            user_message="AWS account_id must be exactly 12 digits.",
        )
    return account


def validate_azure_subscription_config(config: Mapping[str, Any]) -> str:
    account = config.get("account_id")
    if (
        not isinstance(account, str)
        or re.fullmatch(
            r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}",
            account,
        )
        is None
    ):
        raise InvalidConfigurationError(
            "invalid Azure subscription ID",
            user_message="Azure account_id must be a subscription UUID.",
        )
    return account.lower()


def validate_gcp_project_config(config: Mapping[str, Any]) -> str:
    project = config.get("account_id")
    if (
        not isinstance(project, str)
        or re.fullmatch(
            r"[a-z][a-z0-9-]{4,28}[a-z0-9]",
            project,
        )
        is None
    ):
        raise InvalidConfigurationError(
            "invalid GCP project ID",
            user_message="GCP account_id must be a canonical project ID.",
        )
    return project


def validate_bitbucket_config(config: Mapping[str, Any]) -> None:
    """Reject malformed repository coordinates before they reach an outbound client."""
    email = config.get("account_email")
    if email is not None and (
        not isinstance(email, str)
        or len(email) > 254
        or re.fullmatch(r"[^\s:@]+@[^\s:@]+", email) is None
    ):
        raise InvalidConfigurationError(
            "invalid Bitbucket account email",
            user_message="Bitbucket account_email must be a valid email address.",
        )
    for config_field in ("workspace", "repository"):
        value = config.get(config_field)
        if value is not None and (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", value) is None
        ):
            raise InvalidConfigurationError(
                f"invalid Bitbucket {config_field}",
                user_message=f"Bitbucket {config_field} must be a repository identifier.",
            )


def validate_qualys_config(config: dict[str, Any]) -> None:
    """Keep direct Qualys pulls bound to a single explicit IP asset."""
    value = config.get("asset_ip")
    if value is None:
        return
    try:
        config["asset_ip"] = str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise InvalidConfigurationError(
            "invalid Qualys asset IP",
            user_message="Qualys asset_ip must be one IPv4 or IPv6 address.",
        ) from exc


def validate_aws_security_hub_config(config: Mapping[str, Any]) -> None:
    """Require an explicit region and bounded account allow-list before saving."""
    region = config.get("region")
    account_ids = config.get("account_ids")
    if not isinstance(region, str) or re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region) is None:
        raise InvalidConfigurationError(
            "invalid AWS Security Hub region",
            user_message="AWS Security Hub region must be an AWS region such as us-east-1.",
        )
    if not (
        isinstance(account_ids, list)
        and 1 <= len(account_ids) <= 20
        and all(isinstance(item, str) and re.fullmatch(r"\d{12}", item) for item in account_ids)
        and len(set(account_ids)) == len(account_ids)
    ):
        raise InvalidConfigurationError(
            "invalid AWS Security Hub account scope",
            user_message="AWS Security Hub account_ids must contain 1-20 unique 12-digit IDs.",
        )


def validate_rapid7_config(config: dict[str, Any]) -> None:
    """Require a small, explicit InsightVM asset scope for every tenant."""
    asset_ids = config.get("asset_ids")
    valid = (
        isinstance(asset_ids, list)
        and 1 <= len(asset_ids) <= 20
        and all(
            isinstance(item, str)
            and item.isdecimal()
            and 0 < int(item) <= 9_223_372_036_854_775_807
            for item in asset_ids
        )
        and len(set(asset_ids)) == len(asset_ids)
    )
    if not valid:
        raise InvalidConfigurationError(
            "invalid Rapid7 asset IDs",
            user_message="Rapid7 asset_ids must be 1-20 unique positive InsightVM asset IDs.",
        )


def validate_wiz_config(config: dict[str, Any]) -> None:
    """Bind every Wiz service account to a small explicit project set."""
    region = config.get("region")
    project_ids = config.get("project_ids")
    valid = (
        isinstance(region, str)
        and re.fullmatch(r"[a-z][a-z0-9-]{1,23}", region) is not None
        and isinstance(project_ids, list)
        and 1 <= len(project_ids) <= 100
        and all(
            isinstance(item, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item) is not None
            for item in project_ids
        )
        and len(set(project_ids)) == len(project_ids)
    )
    if not valid:
        raise InvalidConfigurationError(
            "invalid Wiz scope",
            user_message="Wiz requires a valid region and 1-100 unique project IDs.",
        )


def validate_prisma_cloud_config(config: dict[str, Any]) -> None:
    """Require an explicit bounded cloud-account scope."""
    account_ids = config.get("cloud_account_ids")
    valid = (
        isinstance(account_ids, list)
        and 1 <= len(account_ids) <= 100
        and all(
            isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.:/-]{2,256}", item) is not None
            for item in account_ids
        )
        and len(set(account_ids)) == len(account_ids)
    )
    if not valid:
        raise InvalidConfigurationError(
            "invalid Prisma Cloud account scope",
            user_message="Prisma Cloud requires 1-100 unique cloud account IDs.",
        )


def validate_ticket_repository_config(config: Mapping[str, Any], *, field: str) -> None:
    """Ensure ticket destinations are a single safe repository/project coordinate."""
    value = config.get(field)
    if value is None:
        return
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", value) is None
    ):
        raise InvalidConfigurationError(
            f"invalid {field}",
            user_message=f"{field} must be a safe repository or project identifier.",
        )


def validate_servicenow_ticket_config(config: Mapping[str, Any]) -> None:
    """Only permit the two incident tables whose correlation contract we implement."""
    table = config.get("table")
    if table is not None and table not in {"incident", "sn_si_incident"}:
        raise InvalidConfigurationError(
            "invalid ServiceNow table",
            user_message="ServiceNow table must be incident or sn_si_incident.",
        )
    group = config.get("assignment_group")
    if group is not None and (not isinstance(group, str) or not 1 <= len(group.strip()) <= 160):
        raise InvalidConfigurationError(
            "invalid ServiceNow assignment group",
            user_message="ServiceNow assignment_group must be 1-160 characters.",
        )


def validate_azure_devops_ticket_config(config: Mapping[str, Any]) -> None:
    """Reject malformed Azure DevOps destination names before outbound use."""
    for config_field, maximum in (("organization", 128), ("project", 128), ("work_item_type", 80)):
        value = config.get(config_field)
        if value is not None and (
            not isinstance(value, str)
            or re.fullmatch(rf"[A-Za-z0-9][A-Za-z0-9_. -]{{0,{maximum - 1}}}", value) is None
        ):
            raise InvalidConfigurationError(
                f"invalid Azure DevOps {config_field}",
                user_message=f"Azure DevOps {config_field} must be a safe non-empty identifier.",
            )


def validate_splunk_config(config: Mapping[str, Any]) -> None:
    """Keep tenant-controlled HEC metadata bounded and free of control characters."""
    patterns = {
        "index": (r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", 128),
        "source": (r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}", 256),
        "sourcetype": (r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", 256),
        "host": (r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}", 255),
    }
    for field_name, (pattern, maximum) in patterns.items():
        value = config.get(field_name)
        if value is not None and (
            not isinstance(value, str)
            or len(value) > maximum
            or re.fullmatch(pattern, value) is None
        ):
            raise InvalidConfigurationError(
                f"invalid Splunk {field_name}",
                user_message=f"Splunk {field_name} must be a safe non-empty identifier.",
            )


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------


def _fingerprint(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()[:8]


def _hint(plaintext: str) -> str:
    """Last four characters, or fewer for a short value.

    A three-character secret would otherwise be fully disclosed by its own hint.
    """
    return plaintext[-4:] if len(plaintext) >= 8 else ""


def _reject_secret_shaped_config(config: Mapping[str, Any]) -> None:
    offenders = sorted(
        key
        for key in config
        if key not in _PUBLIC_TOKEN_CONFIG_KEYS
        and any(marker in key.lower() for marker in _SECRET_KEY_MARKERS)
    )
    if offenders:
        raise InvalidConfigurationError(
            "secret-shaped key in integration config",
            user_message=(
                "These settings look like credentials and must be sent as credentials, "
                f"not configuration: {', '.join(offenders)}."
            ),
            context={"keys": offenders},
        )


def _spec_for(kind: IntegrationKind) -> _KindSpec:
    spec = _SPECS.get(kind)
    if spec is None:
        raise IntegrationNotConfiguredError(
            kind.value,
            hint=f"{kind.value} integrations are not available in this release.",
        )
    return spec


def _decrypt(credential: IntegrationCredential, *, settings: Settings) -> Secret | None:
    """Reveal one stored credential, or ``None`` if it cannot be decrypted.

    A row sealed with a key that is no longer configured is a real operational state (a
    key was rotated out without re-encrypting). It degrades to "this credential is
    missing", which surfaces as an honest ``IntegrationNotConfiguredError`` at the point
    of use, rather than propagating a decryption traceback out of a settings page.
    """
    cipher = get_cipher(settings)
    try:
        return cipher.decrypt(credential.ciphertext.decode("utf-8"))
    except (CredentialDecryptionError, UnicodeDecodeError):
        log.error(
            "integration.credential_undecryptable",
            credential_id=str(credential.id),
            name=credential.name,
            key_version=credential.key_version,
        )
        return None


def _apply_credentials(
    integration: Integration,
    submitted: Mapping[str, str],
    *,
    settings: Settings,
    actor_id: uuid.UUID | None,
    now: dt.datetime,
) -> list[str]:
    """Encrypt and store submitted credentials. Returns the slot names that changed.

    ``integration.credentials`` must already be loaded. An absent key keeps its stored
    value; a present-but-empty key deletes it. See the module docstring.
    """
    spec = _spec_for(integration.kind_enum)
    unknown = sorted(set(submitted) - set(spec.credentials))
    if unknown:
        raise InvalidConfigurationError(
            "unknown credential slot",
            user_message=(
                f"{integration.name} does not use these credentials: {', '.join(unknown)}. "
                f"Expected: {', '.join(sorted(spec.credentials))}."
            ),
            context={"unknown": unknown},
        )

    cipher = get_cipher(settings)
    existing = {credential.name: credential for credential in integration.credentials}
    changed: list[str] = []

    for name, plaintext in submitted.items():
        current = existing.get(name)
        if not plaintext:
            if current is not None:
                integration.credentials.remove(current)
                changed.append(name)
            continue
        fingerprint = _fingerprint(plaintext)
        if current is not None and current.fingerprint == fingerprint:
            continue  # Same value resubmitted; rewriting it would only churn ``rotated_at``.
        ciphertext = cipher.encrypt(plaintext).encode("utf-8")
        if current is None:
            integration.credentials.append(
                IntegrationCredential(
                    organization_id=integration.organization_id,
                    name=name,
                    ciphertext=ciphertext,
                    key_version=1,
                    fingerprint=fingerprint,
                    hint=_hint(plaintext),
                    created_by_id=actor_id,
                )
            )
        else:
            current.ciphertext = ciphertext
            current.fingerprint = fingerprint
            current.hint = _hint(plaintext)
            current.rotated_at = now
            current.key_version = 1
        changed.append(name)

    return changed


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def list_integrations(session: AsyncSession, principal: Principal) -> Sequence[Integration]:
    """Every configured integration for the principal's organization, credentials loaded."""
    principal.require(Permission.INTEGRATION_READ)
    stmt = tenant_select(
        Integration,
        principal.organization_id,
        selectinload(Integration.credentials),
    ).order_by(Integration.kind)
    return (await session.execute(stmt)).scalars().all()


async def find_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
) -> Integration | None:
    """The organization's integration of this kind, or ``None``.

    Kind-only flows prefer the oldest usable connection when several rows share a kind.
    If all are disabled, return the oldest so the configuration API can re-enable it.
    """
    stmt = (
        tenant_select(
            Integration,
            principal.organization_id,
            selectinload(Integration.credentials),
        )
        .where(Integration.kind == kind.value)
        .order_by(Integration.created_at, Integration.id)
    )
    rows = (await session.execute(stmt)).scalars().all()
    if not rows:
        return None
    return next((row for row in rows if row.is_usable), rows[0])


async def get_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
) -> Integration:
    principal.require(Permission.INTEGRATION_READ)
    integration = await find_integration(session, principal, kind)
    if integration is None:
        raise ResourceNotFoundError(
            "integration not configured",
            user_message=f"No {kind.value} integration has been configured.",
            context={"kind": kind.value},
        )
    return integration


def integration_out(integration: Integration) -> IntegrationOut:
    """Serialize for the API. Requires ``credentials`` to be eager-loaded."""
    return IntegrationOut(
        id=integration.id,
        kind=integration.kind_enum,
        name=integration.name,
        status=integration.status_enum,
        is_enabled=integration.is_enabled,
        base_url=integration.base_url,
        config=dict(integration.config or {}),
        credentials=[
            CredentialOut(
                name=credential.name,
                fingerprint=credential.fingerprint,
                hint=credential.hint,
                key_version=credential.key_version,
                expires_at=credential.expires_at,
                last_used_at=credential.last_used_at,
                rotated_at=credential.rotated_at,
                created_at=credential.created_at,
            )
            for credential in sorted(integration.credentials, key=lambda c: c.name)
        ],
        last_verified_at=integration.last_verified_at,
        last_error=integration.last_error,
        last_error_at=integration.last_error_at,
        failure_count=integration.failure_count,
        sync_interval_minutes=integration.sync_interval_minutes,
        next_sync_at=integration.next_sync_at,
        last_sync_at=integration.last_sync_at,
        last_sync_status=integration.last_sync_status,
        last_sync_error=integration.last_sync_error,
        sync_failure_count=integration.sync_failure_count,
        created_at=integration.created_at,
    )


def mark_sync_succeeded(integration: Integration | None, *, completed_at: dt.datetime | None = None) -> None:
    """Apply the shared success transition for manual, agent and scheduled pulls."""
    if integration is None:
        return
    completed = completed_at or utcnow()
    integration.last_sync_at = completed
    integration.last_sync_status = "succeeded"
    integration.last_sync_error = None
    integration.sync_failure_count = 0
    integration.next_sync_at = (
        completed + dt.timedelta(minutes=integration.sync_interval_minutes)
        if integration.is_enabled and integration.sync_interval_minutes is not None
        else None
    )


@dataclass(frozen=True, slots=True)
class SyncQuality:
    freshness_seconds: int | None
    coverage_state: str
    confidence: float
    reason: str


_WEBHOOK_KINDS = frozenset(
    {
        IntegrationKind.GITHUB,
        IntegrationKind.GITLAB,
        IntegrationKind.JIRA,
        IntegrationKind.SERVICENOW,
        IntegrationKind.AZURE_DEVOPS,
    }
)
_TICKET_PUSH_KINDS = frozenset(
    {
        IntegrationKind.JIRA,
        IntegrationKind.SERVICENOW,
        IntegrationKind.AZURE_DEVOPS,
        IntegrationKind.GITLAB,
        IntegrationKind.LINEAR,
    }
)
_NOTIFICATION_KINDS = frozenset(
    {IntegrationKind.SLACK, IntegrationKind.EMAIL, IntegrationKind.PAGERDUTY}
)


def connector_capabilities(kind: IntegrationKind) -> list[str]:
    capabilities = ["connectivity_test"]
    if kind in CONTINUOUS_SYNC_KINDS:
        capabilities.extend(("finding_ingestion", "scheduled_sync"))
    if kind in _WEBHOOK_KINDS:
        capabilities.append("webhook_ingestion")
    if kind in _TICKET_PUSH_KINDS:
        capabilities.append("ticket_or_work_item_push")
    if kind in _NOTIFICATION_KINDS:
        capabilities.append("notification_delivery")
    if kind is IntegrationKind.LLM:
        capabilities.append("ai_inference")
    if kind in {IntegrationKind.MISP, IntegrationKind.NVD}:
        capabilities.append("threat_intelligence")
    return capabilities


def certify_connector(
    *,
    kind: IntegrationKind,
    name: str,
    is_enabled: bool,
    configured_credentials: set[str],
    required_credentials: set[str],
    last_verified_at: dt.datetime | None,
    status: str,
    quality: SyncQuality,
    circuit_open: bool,
    now: dt.datetime | None = None,
) -> ConnectorCertificationOut:
    """Produce an explainable operational certification without contacting the provider."""

    checked_at = now or utcnow()
    missing = sorted(required_credentials - configured_credentials)
    if last_verified_at is not None and last_verified_at.tzinfo is None:
        last_verified_at = last_verified_at.replace(tzinfo=dt.UTC)
    verification_current = bool(
        last_verified_at and checked_at - last_verified_at <= dt.timedelta(days=7)
    )
    operational = status == IntegrationStatus.CONFIGURED.value
    coverage_passed = (
        quality.coverage_state == "current"
        if kind in CONTINUOUS_SYNC_KINDS
        else operational
    )
    checks = [
        ConnectorAssuranceCheckOut(
            key="enabled", passed=is_enabled, weight=10,
            detail="Connector is enabled." if is_enabled else "Connector is disabled.",
        ),
        ConnectorAssuranceCheckOut(
            key="credentials", passed=not missing, weight=20,
            detail=(
                "All required credentials are configured."
                if not missing
                else f"Missing required credentials: {', '.join(missing)}."
            ),
        ),
        ConnectorAssuranceCheckOut(
            key="verification", passed=verification_current, weight=30,
            detail=(
                "Provider authentication was verified within seven days."
                if verification_current
                else "Provider authentication has not been verified within seven days."
            ),
        ),
        ConnectorAssuranceCheckOut(
            key="circuit", passed=not circuit_open, weight=15,
            detail=(
                "Provider circuit is closed."
                if not circuit_open
                else "Provider circuit breaker is open."
            ),
        ),
        ConnectorAssuranceCheckOut(
            key="coverage", passed=coverage_passed, weight=25,
            detail=(
                quality.reason
                if kind in CONTINUOUS_SYNC_KINDS
                else "Connector is operational." if operational else "Connector is not operational."
            ),
        ),
    ]
    score = sum(check.weight for check in checks if check.passed)
    blockers = [check.detail for check in checks if not check.passed]
    grade = (
        "certified"
        if score >= 90 and not blockers
        else "operational"
        if score >= 70
        else "degraded"
        if score >= 40
        else "failed"
    )
    return ConnectorCertificationOut(
        kind=kind,
        name=name,
        grade=grade,
        score=score,
        capabilities=connector_capabilities(kind),
        checks=checks,
        blockers=blockers,
        checked_at=checked_at,
    )


def connector_contract_result(
    live: IntegrationTestOut,
    certification: ConnectorCertificationOut,
) -> ConnectorContractTestOut:
    """Combine a real provider probe with configuration and coverage assertions."""

    live_check = ConnectorAssuranceCheckOut(
        key="live_auth",
        passed=live.healthy,
        weight=50,
        detail=live.detail or ("Provider authenticated." if live.healthy else "Provider probe failed."),
    )
    checks = [live_check, *certification.checks]
    score = round(((100 if live.healthy else 0) + certification.score) / 2)
    blockers = [check.detail for check in checks if not check.passed]
    return ConnectorContractTestOut(
        kind=live.kind,
        passed=live.healthy and not certification.blockers,
        score=score,
        checks=checks,
        capabilities=certification.capabilities,
        blockers=blockers,
        latency_ms=live.latency_ms,
        checked_at=live.checked_at or certification.checked_at,
    )


def integration_sync_quality(
    integration: Integration,
    *,
    now: dt.datetime | None = None,
    circuit_open: bool = False,
) -> SyncQuality:
    """Turn schedule, freshness, and failures into an explainable coverage confidence."""
    measured_at = now or utcnow()
    last_sync_at = integration.last_sync_at
    freshness = None
    if last_sync_at is not None:
        if last_sync_at.tzinfo is None:
            last_sync_at = last_sync_at.replace(tzinfo=dt.UTC)
        freshness = max(0, int((measured_at - last_sync_at).total_seconds()))

    if not integration.is_enabled:
        quality = SyncQuality(freshness, "disabled", 0.0, "Connector is disabled.")
    elif integration.sync_interval_minutes is None:
        quality = SyncQuality(
            freshness,
            "manual" if last_sync_at is not None else "not_scheduled",
            0.75 if integration.last_sync_status == "succeeded" else 0.4,
            "Connector is manual; confidence reflects its latest recorded result.",
        )
    elif last_sync_at is None:
        quality = SyncQuality(
            None,
            "never_synced",
            0.0,
            "Scheduled connector has never completed a sync.",
        )
    else:
        expected = max(300, int(integration.sync_interval_minutes) * 60)
        ratio = (freshness or 0) / expected
        if integration.last_sync_status == "failed":
            confidence = max(0.05, 0.45 - (0.1 * int(integration.sync_failure_count or 0)))
            state = "degraded"
            reason = "The latest sync failed; absence cannot be treated as clean coverage."
        elif ratio <= 1.5:
            confidence = max(0.8, 1.0 - (ratio * 0.1))
            state = "current"
            reason = "The latest successful sync is within its expected collection window."
        elif ratio <= 3:
            confidence = max(0.45, 0.8 - ((ratio - 1.5) * 0.2))
            state = "stale"
            reason = "The connector is past its expected collection window."
        else:
            confidence = max(0.1, 0.45 / ratio)
            state = "stale"
            reason = "Connector coverage is substantially older than its schedule."
        quality = SyncQuality(freshness, state, round(confidence, 4), reason)

    if circuit_open:
        return SyncQuality(
            quality.freshness_seconds,
            "blocked",
            round(quality.confidence * 0.4, 4),
            "Provider circuit breaker is open; new coverage is blocked.",
        )
    if integration.status == IntegrationStatus.ERROR.value:
        return SyncQuality(
            quality.freshness_seconds,
            "degraded",
            round(quality.confidence * 0.6, 4),
            "Connector health is in an error state.",
        )
    return quality


async def integration_health(
    session: AsyncSession,
    principal: Principal,
    *,
    redis: Redis | None = None,
) -> list[IntegrationHealthOut]:
    """Dashboard rows (FR-031), including live circuit-breaker state.

    The breaker lives in Redis and is keyed per provider, so it is deployment-wide rather
    than per-organization -- an open circuit means Cynux is not calling that provider for
    anyone. Reported here anyway because "why are my tickets not being created" is
    answered by exactly that fact.
    """
    principal.require(Permission.INTEGRATION_READ)
    rows = await list_integrations(session, principal)
    out: list[IntegrationHealthOut] = []
    for integration in rows:
        circuit_open = False
        if redis is not None:
            status = await CircuitBreaker(redis, provider=integration.kind).status()
            circuit_open = status.is_open
        quality = integration_sync_quality(integration, circuit_open=circuit_open)
        out.append(
            IntegrationHealthOut(
                kind=integration.kind_enum,
                name=integration.name,
                status=integration.status_enum,
                is_enabled=integration.is_enabled,
                last_verified_at=integration.last_verified_at,
                failure_count=integration.failure_count,
                sync_interval_minutes=integration.sync_interval_minutes,
                last_sync_at=integration.last_sync_at,
                last_sync_status=integration.last_sync_status,
                sync_failure_count=integration.sync_failure_count,
                freshness_seconds=quality.freshness_seconds,
                coverage_state=quality.coverage_state,
                sync_confidence=quality.confidence,
                coverage_reason=quality.reason,
                circuit_open=circuit_open,
            )
        )
    return out


async def connector_certifications(
    session: AsyncSession,
    principal: Principal,
    *,
    redis: Redis | None = None,
) -> list[ConnectorCertificationOut]:
    principal.require(Permission.INTEGRATION_READ)
    rows = await list_integrations(session, principal)
    checked_at = utcnow()
    output: list[ConnectorCertificationOut] = []
    for integration in rows:
        circuit_open = False
        if redis is not None:
            breaker = await CircuitBreaker(redis, provider=integration.kind).status()
            circuit_open = breaker.is_open
        quality = integration_sync_quality(
            integration, now=checked_at, circuit_open=circuit_open
        )
        output.append(
            certify_connector(
                kind=integration.kind_enum,
                name=integration.name,
                is_enabled=integration.is_enabled,
                configured_credentials={item.name for item in integration.credentials},
                required_credentials=set(_spec_for(integration.kind_enum).required),
                last_verified_at=integration.last_verified_at,
                status=integration.status,
                quality=quality,
                circuit_open=circuit_open,
                now=checked_at,
            )
        )
    return output


async def source_coverage(
    session: AsyncSession,
    principal: Principal,
    *,
    redis: Redis | None = None,
) -> list[SourceCoverageOut]:
    """Summarize actual canonical-source coverage beside connector sync confidence."""
    principal.require(Permission.INTEGRATION_READ, Permission.FINDING_READ)
    health_rows = await integration_health(session, principal, redis=redis)
    health_by_kind = {row.kind.value: row for row in health_rows}
    rows = (
        await session.execute(
            select(
                FindingObservation.provider,
                func.count(FindingObservation.id),
                func.count(func.distinct(FindingObservation.canonical_finding_id)),
                func.sum(
                    case(
                        (
                            FindingObservation.source_status.not_in(("absent", "superseded")),
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            (FindingObservation.missing_sync_count > 0)
                            | FindingObservation.source_status.in_(("absent", "superseded")),
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.max(FindingObservation.last_seen_at),
            )
            .where(FindingObservation.organization_id == principal.organization_id)
            .group_by(FindingObservation.provider)
            .order_by(FindingObservation.provider)
        )
    ).all()

    def health_for(provider: str) -> IntegrationHealthOut | None:
        direct = health_by_kind.get(provider)
        if direct is not None:
            return direct
        return next(
            (
                health
                for kind, health in health_by_kind.items()
                if provider.startswith(f"{kind}_") or provider.startswith(f"{kind}:")
            ),
            None,
        )

    output: list[SourceCoverageOut] = []
    observed_provider_keys: set[str] = set()
    for provider, total, canonical, active, missing, last_seen in rows:
        provider_name = str(provider)
        health = health_for(provider_name)
        if health is not None:
            observed_provider_keys.add(health.kind.value)
        output.append(
            SourceCoverageOut(
                provider=provider_name,
                observations_total=int(total or 0),
                canonical_findings=int(canonical or 0),
                active_observations=int(active or 0),
                missing_observations=int(missing or 0),
                last_observed_at=last_seen,
                coverage_state=health.coverage_state if health else "unmanaged_import",
                sync_confidence=health.sync_confidence if health else 0.5,
                coverage_reason=(
                    health.coverage_reason
                    if health
                    else "Source records exist without a scheduled connector health record."
                ),
            )
        )
    for health in health_rows:
        if health.kind not in CONTINUOUS_SYNC_KINDS or health.kind.value in observed_provider_keys:
            continue
        output.append(
            SourceCoverageOut(
                provider=health.kind.value,
                observations_total=0,
                canonical_findings=0,
                active_observations=0,
                missing_observations=0,
                coverage_state=health.coverage_state,
                sync_confidence=health.sync_confidence,
                coverage_reason=health.coverage_reason,
            )
        )
    return sorted(output, key=lambda row: row.provider)


# ---------------------------------------------------------------------------
# Settings projection
# ---------------------------------------------------------------------------


def _without_deployment_provider_config(base: Settings, kind: IntegrationKind) -> Settings:
    """Keep operational defaults but clear tenant-owned endpoints, scope, and secrets."""
    spec = _spec_for(kind)
    scoped = base.model_copy(deep=True)
    section = getattr(scoped, spec.section)
    fields = {field for field in spec.credentials.values() if field is not None} | set(
        spec.config.values()
    )
    if spec.base_url_field:
        fields.add(spec.base_url_field)
    for name in fields:
        default = type(section).model_fields[name].get_default(call_default_factory=True)
        setattr(section, name, default)
    return scoped


def _overlay(
    base: Settings,
    integration: Integration,
    credentials: Mapping[str, Secret],
) -> Settings:
    spec = _spec_for(integration.kind_enum)
    scoped = base.model_copy(deep=True)
    section = getattr(scoped, spec.section)

    if spec.base_url_field and integration.base_url:
        setattr(section, spec.base_url_field, integration.base_url)

    stored_config = integration.config or {}
    for key, target in spec.config.items():
        if key in stored_config and stored_config[key] is not None:
            setattr(section, target, stored_config[key])

    for name, target in spec.credentials.items():
        secret = credentials.get(name)
        if secret is not None and target is not None:
            # Every credential-bearing settings field is a ``SecretStr``; wrapping here
            # keeps the plaintext inside a type that will not render itself into a log.
            setattr(section, target, SecretStr(secret.reveal()))

    return scoped


def credentials_for(
    integration: Integration,
    *,
    settings: Settings,
    mark_used: bool = True,
) -> dict[str, Secret]:
    """Decrypt every credential on an already-loaded integration.

    Synchronous, and takes no session: it only reads bytes already in memory and mutates
    loaded objects. ``mark_used`` stamps ``last_used_at``, which is how an operator
    distinguishes a credential that is actually in the request path from one left over
    from a half-finished setup. That is a write, so the caller still owns the transaction.
    """
    now = utcnow()
    resolved: dict[str, Secret] = {}
    for credential in integration.credentials:
        secret = _decrypt(credential, settings=settings)
        if secret is None:
            continue
        resolved[credential.name] = secret
        if mark_used:
            credential.last_used_at = now
    return resolved


async def resolve_settings(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    *,
    settings: Settings,
    require: bool = False,
    mark_used: bool = True,
) -> Settings:
    """Resolve a provider configuration for this organization.

    In production, customer-owned connectors cannot inherit deployment credentials,
    endpoints, or account scope. Shared platform services (LLM, DefectDojo, NVD) and
    development deployments retain the environment fallback.

    ``require=True`` raises :class:`IntegrationNotConfiguredError` when the resulting
    configuration still lacks a required credential -- use it at the point of a real
    outbound call, so the error names the provider the user was waiting on.
    """
    tenant_private = kind in {
        IntegrationKind.PROWLER_AWS,
        IntegrationKind.PROWLER_AZURE,
        IntegrationKind.PROWLER_GCP,
    } or (settings.is_production and kind in _TENANT_PRIVATE_KINDS)
    base = _without_deployment_provider_config(settings, kind) if tenant_private else settings
    integration = await find_integration(session, principal, kind)
    if integration is None:
        if require:
            if tenant_private:
                raise IntegrationNotConfiguredError(
                    kind.value,
                    hint=f"Configure this organization's {kind.value} integration first.",
                )
            _assert_env_configured(settings, kind)
        return base
    if not integration.is_usable:
        raise IntegrationNotConfiguredError(
            kind.value,
            hint=f"The {integration.name} integration is disabled.",
        )

    credentials = credentials_for(integration, settings=settings, mark_used=mark_used)
    if require:
        spec = _spec_for(kind)
        missing = [name for name in spec.required if name not in credentials]
        if missing:
            raise IntegrationNotConfiguredError(
                kind.value,
                hint=f"Missing credential(s): {', '.join(missing)}.",
            )
    return _overlay(base, integration, credentials)


def _assert_env_configured(settings: Settings, kind: IntegrationKind) -> None:
    """Check the deployment-wide fallback before reporting a provider unusable."""
    spec = _spec_for(kind)
    section = getattr(settings, spec.section)
    for name in spec.required:
        value = getattr(section, spec.credentials[name], None)
        if not value:
            raise IntegrationNotConfiguredError(
                kind.value,
                hint=f"Configure the {kind.value} integration, or set it in the environment.",
            )


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


async def upsert_integration(
    session: AsyncSession,
    principal: Principal,
    payload: IntegrationUpsertIn,
    *,
    settings: Settings,
) -> Integration:
    """Create or update one integration, encrypting any submitted credentials (FR-032).

    Configuration and credential changes are audited as two separate actions even though
    they arrive in one request: ``INTEGRATION_CONFIGURE`` is routine and
    ``INTEGRATION_CREDENTIAL_UPDATE`` is the one an incident responder greps for. Only the
    *names* of the changed credential slots are recorded -- never a value, not even a
    fingerprint, since a fingerprint over a low-entropy secret is guessable.
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    kind = payload.kind
    if kind in _UNIMPLEMENTED:
        raise InvalidConfigurationError(
            "integration kind not implemented",
            user_message=(
                f"{kind.value} integrations are not available in this release. "
                "Configuration for them cannot be saved yet."
            ),
            context={"kind": kind.value},
        )
    spec = _spec_for(kind)
    _reject_secret_shaped_config(payload.config)
    if payload.sync_interval_minutes is not None and kind not in CONTINUOUS_SYNC_KINDS:
        raise InvalidConfigurationError(
            "continuous sync is unavailable for this integration",
            user_message=f"{kind.value} does not provide a continuously ingested finding feed.",
        )

    unknown_config = sorted(set(payload.config) - set(spec.config))
    if unknown_config:
        raise InvalidConfigurationError(
            "unknown integration config key",
            user_message=(
                f"Unrecognized settings for {kind.value}: {', '.join(unknown_config)}. "
                f"Expected: {', '.join(sorted(spec.config)) or 'none'}."
            ),
            context={"unknown": unknown_config},
        )

    if kind == IntegrationKind.SONARQUBE and "project_keys" in payload.config:
        project_keys = payload.config["project_keys"]
        valid = (
            isinstance(project_keys, list)
            and 1 <= len(project_keys) <= 100
            and all(
                isinstance(key, str)
                and key == key.strip()
                and 1 <= len(key) <= 400
                and all(char.isalnum() or char in "-_.:" for char in key)
                for key in project_keys
            )
            and len(set(project_keys)) == len(project_keys)
        )
        if not valid:
            raise InvalidConfigurationError(
                "invalid SonarQube project keys",
                user_message="SonarQube project_keys must be a list of 1-100 unique project keys.",
            )

    if kind == IntegrationKind.SNYK:
        org_id = payload.config.get("organization_id")
        if org_id is not None:
            try:
                if not isinstance(org_id, str) or str(uuid.UUID(org_id)) != org_id.lower():
                    raise ValueError
            except ValueError as exc:
                raise InvalidConfigurationError(
                    "invalid Snyk organization ID",
                    user_message="Snyk organization_id must be a UUID.",
                ) from exc

    if kind == IntegrationKind.TENABLE and "scan_ids" in payload.config:
        scans = payload.config["scan_ids"]
        try:
            valid = (
                isinstance(scans, list)
                and 1 <= len(scans) <= 20
                and all(
                    isinstance(item, str) and str(uuid.UUID(item)) == item.lower() for item in scans
                )
                and len(set(scans)) == len(scans)
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise InvalidConfigurationError(
                "invalid Tenable scan IDs",
                user_message="Tenable scan_ids must be 1-20 unique scan UUIDs.",
            )

    if kind is IntegrationKind.PROWLER_AWS and "account_id" in payload.config:
        validate_aws_account_config(payload.config)
    if kind is IntegrationKind.PROWLER_AZURE and "account_id" in payload.config:
        payload.config["account_id"] = validate_azure_subscription_config(payload.config)
    if kind is IntegrationKind.PROWLER_GCP and "account_id" in payload.config:
        payload.config["account_id"] = validate_gcp_project_config(payload.config)
    if kind is IntegrationKind.BITBUCKET:
        validate_bitbucket_config(payload.config)
    if kind is IntegrationKind.QUALYS:
        validate_qualys_config(payload.config)
    if kind is IntegrationKind.RAPID7:
        validate_rapid7_config(payload.config)
    if kind is IntegrationKind.WIZ:
        validate_wiz_config(payload.config)
    if kind is IntegrationKind.PRISMA_CLOUD:
        validate_prisma_cloud_config(payload.config)
    if kind is IntegrationKind.AWS_SECURITY_HUB:
        validate_aws_security_hub_config(payload.config)
    if kind is IntegrationKind.AWS_INSPECTOR:
        validate_aws_security_hub_config(payload.config)
    if kind is IntegrationKind.HACKERONE:
        handles = payload.config.get("program_handles")
        if not (
            isinstance(handles, list)
            and 1 <= len(handles) <= 100
            and all(
                isinstance(handle, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", handle)
                for handle in handles
            )
            and len(set(handles)) == len(handles)
        ):
            raise InvalidConfigurationError(
                "invalid HackerOne program handles",
                user_message="HackerOne program_handles must contain 1-100 unique handles.",
            )
    if kind is IntegrationKind.BUGCROWD:
        codes = payload.config.get("engagement_codes")
        if not (
            isinstance(codes, list)
            and 1 <= len(codes) <= 100
            and all(
                isinstance(code, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", code)
                for code in codes
            )
            and len(set(codes)) == len(codes)
        ):
            raise InvalidConfigurationError(
                "invalid Bugcrowd engagement codes",
                user_message="Bugcrowd engagement_codes must contain 1-100 unique codes.",
            )
    if kind is IntegrationKind.CHECKMARX:
        projects = payload.config.get("projects")
        tenant = payload.config.get("tenant")
        auth_url = payload.config.get("auth_url")
        try:
            projects_valid = (
                isinstance(projects, dict)
                and 1 <= len(projects) <= 100
                and all(
                    isinstance(project_id, str)
                    and str(uuid.UUID(project_id)) == project_id.lower()
                    and isinstance(asset, str)
                    and 3 <= len(asset) <= 500
                    and "/" in asset
                    for project_id, asset in projects.items()
                )
            )
        except (TypeError, ValueError):
            projects_valid = False
        if not projects_valid:
            raise InvalidConfigurationError(
                "invalid Checkmarx projects",
                user_message="Checkmarx projects must map 1-100 project UUIDs to repository identities.",
            )
        if not isinstance(tenant, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", tenant) is None:
            raise InvalidConfigurationError("invalid Checkmarx tenant")
        if not isinstance(auth_url, str) or not auth_url:
            raise InvalidConfigurationError("invalid Checkmarx identity URL")
    if kind is IntegrationKind.FORTIFY:
        versions = payload.config.get("application_versions")
        if not (
            isinstance(versions, dict)
            and 1 <= len(versions) <= 100
            and all(
                isinstance(version_id, str)
                and re.fullmatch(r"[1-9]\d{0,18}", version_id)
                and isinstance(asset, str)
                and 3 <= len(asset) <= 500
                for version_id, asset in versions.items()
            )
        ):
            raise InvalidConfigurationError(
                "invalid Fortify application versions",
                user_message="Fortify application_versions must map 1-100 SSC version IDs to asset identities.",
            )
    if kind is IntegrationKind.AZURE_DEFENDER:
        payload.config["subscription_id"] = validate_azure_subscription_config(
            {"account_id": payload.config.get("subscription_id")}
        )
    if kind is IntegrationKind.GCP_SCC:
        project = payload.config.get("project_id")
        location = payload.config.get("location", "global")
        if not isinstance(project, str) or re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project) is None:
            raise InvalidConfigurationError(
                "invalid GCP SCC project ID",
                user_message="GCP SCC project_id must be a canonical project ID.",
            )
        if (
            not isinstance(location, str)
            or re.fullmatch(r"(?:global|[a-z][a-z0-9-]{1,30})", location) is None
        ):
            raise InvalidConfigurationError(
                "invalid GCP SCC location",
                user_message="GCP SCC location must be global or a supported data-residency location.",
            )
    if kind is IntegrationKind.BURP_DAST:
        site_ids = payload.config.get("site_ids")
        if not (
            isinstance(site_ids, list)
            and 1 <= len(site_ids) <= 100
            and all(isinstance(value, str) and re.fullmatch(r"[1-9]\d{0,18}", value) for value in site_ids)
            and len(set(site_ids)) == len(site_ids)
        ):
            raise InvalidConfigurationError(
                "invalid Burp DAST site IDs",
                user_message="Burp DAST site_ids must contain 1-100 unique numeric site IDs.",
            )
    if kind is IntegrationKind.SPLUNK:
        validate_splunk_config(payload.config)
    if kind is IntegrationKind.GITHUB:
        validate_ticket_repository_config(payload.config, field="repository")
    if kind is IntegrationKind.GITLAB:
        validate_ticket_repository_config(payload.config, field="issue_project")
    if kind is IntegrationKind.SERVICENOW:
        validate_servicenow_ticket_config(payload.config)
    if kind is IntegrationKind.AZURE_DEVOPS:
        validate_azure_devops_ticket_config(payload.config)
    if (
        kind is IntegrationKind.LINEAR
        and "team_id" in payload.config
        and (
            not isinstance(payload.config["team_id"], str)
            or re.fullmatch(r"[0-9a-fA-F-]{8,64}", payload.config["team_id"]) is None
        )
    ):
        raise InvalidConfigurationError(
            "invalid Linear team ID", user_message="Linear team_id must be a team UUID."
        )

    # Serialize connector creation per organization.  This prevents two concurrent settings
    # requests from both seeing the last available slot and storing more integrations than
    # the self-service entitlement permits.
    organization = (
        await session.execute(
            select(Organization)
            .where(Organization.id == principal.organization_id)
            .with_for_update()
        )
    ).scalar_one()

    now = utcnow()
    integration = await find_integration(session, principal, kind)
    created = integration is None
    if integration is None:
        assert_integration_capacity(
            current_integrations=await _count_organization_integrations(
                session, principal.organization_id
            ),
            new_integrations=1,
            entitlements=load_entitlements(organization.entitlements),
        )
        integration = Integration(
            organization_id=principal.organization_id,
            kind=kind.value,
            name=payload.name or _DEFAULT_NAMES[kind],
            status=IntegrationStatus.UNVERIFIED.value,
            is_enabled=payload.is_enabled,
            base_url=payload.base_url,
            config=dict(payload.config),
            sync_interval_minutes=payload.sync_interval_minutes,
            next_sync_at=(
                now
                if payload.is_enabled and payload.sync_interval_minutes is not None
                else None
            ),
            created_by_id=principal.user_id,
        )
        session.add(integration)
        # Flushed before credentials are attached so the child rows have a parent id and
        # so a unique-constraint violation surfaces here rather than at the route's commit.
        await session.flush()
        await session.refresh(integration, ["credentials"])
    else:
        if payload.name:
            integration.name = payload.name
        if payload.base_url is not None:
            integration.base_url = payload.base_url
        integration.is_enabled = payload.is_enabled
        # Merged, not replaced: a form that submits one field must not blank the rest.
        integration.config = {**(integration.config or {}), **payload.config}
        if "sync_interval_minutes" in payload.model_fields_set:
            integration.sync_interval_minutes = payload.sync_interval_minutes
        integration.next_sync_at = (
            now
            if integration.is_enabled and integration.sync_interval_minutes is not None
            else None
        )

    changed = _apply_credentials(
        integration,
        payload.credentials,
        settings=settings,
        actor_id=principal.user_id,
        now=now,
    )

    # Any change invalidates the previous verdict: the old one described a configuration
    # that no longer exists. Re-verification is an explicit test call.
    integration.status = (
        IntegrationStatus.DISABLED.value
        if not integration.is_enabled
        else IntegrationStatus.UNVERIFIED.value
    )
    integration.last_verified_at = None
    integration.last_error = None
    integration.last_error_at = None
    integration.failure_count = 0
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_CONFIGURE,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id,
        detail={
            "kind": kind.value,
            "created": created,
            "is_enabled": integration.is_enabled,
            "config_keys": sorted(payload.config),
            "continuous_sync": integration.sync_interval_minutes is not None,
            "sync_interval_minutes": integration.sync_interval_minutes,
        },
    )
    if changed:
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_CREDENTIAL_UPDATE,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id,
            detail={"kind": kind.value, "slots": sorted(changed)},
        )
    log.info(
        "integration.configured",
        kind=kind.value,
        integration_id=str(integration.id),
        created=created,
        credential_slots=len(changed),
    )
    return integration


async def _count_organization_integrations(
    session: AsyncSession, organization_id: uuid.UUID
) -> int:
    """Count saved connector configurations, including disabled ones.

    Disabling a connector is reversible and intentionally retains its encrypted credentials;
    it therefore still consumes a plan slot until the organization explicitly removes it.
    """
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Integration)
                .where(Integration.organization_id == organization_id)
            )
        ).scalar_one()
    )


async def disable_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
) -> Integration:
    """Stop using an integration without discarding its credentials.

    Deliberately not a delete. Turning an integration off during an incident and back on
    afterwards should not require an operator to find the API token again.
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    integration = await get_integration(session, principal, kind)
    integration.is_enabled = False
    integration.status = IntegrationStatus.DISABLED.value
    integration.next_sync_at = None
    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_DISABLE,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id,
        detail={"kind": kind.value},
    )
    log.info("integration.disabled", kind=kind.value, integration_id=str(integration.id))
    return integration


# ---------------------------------------------------------------------------
# Connectivity probe
# ---------------------------------------------------------------------------


async def _ping(kind: IntegrationKind, scoped: Settings, redis: Redis | None) -> bool:
    if kind is IntegrationKind.LLM:
        # Exercise the exact tenant-scoped provider/model path that assessments use.  A
        # deliberately tiny completion verifies the key, model entitlement and endpoint
        # together while keeping the operator's connectivity check inexpensive.
        gateway = LLMGateway(scoped)
        try:
            response = await gateway.complete(
                "classification",
                [LLMMessage(role="user", content="Reply with exactly OK.")],
                max_output_tokens=8,
                temperature=0.0,
            )
            return bool(response.text.strip())
        finally:
            await gateway.aclose()
    if kind is IntegrationKind.PROWLER_AWS:
        account = validate_aws_account_config({"account_id": scoped.scanner.aws_account_id})
        access = scoped.scanner.aws_access_key_id
        secret = scoped.scanner.aws_secret_access_key
        if access is None or secret is None:
            raise IntegrationNotConfiguredError("prowler_aws", hint="Both AWS keys are required.")
        credentials = {
            "AWS_ACCESS_KEY_ID": access.get_secret_value(),
            "AWS_SECRET_ACCESS_KEY": secret.get_secret_value(),
        }
        if scoped.scanner.aws_session_token is not None:
            credentials["AWS_SESSION_TOKEN"] = scoped.scanner.aws_session_token.get_secret_value()
        request = ScannerRequest(
            scanner=ScannerName.PROWLER_AWS,
            targets=(f"aws:{account}",),
            workdir=Path("."),
            timeout_seconds=1,
        )
        await asyncio.to_thread(AWS_ADAPTER.verify_credential_scope, request, credentials)
        return True
    if kind is IntegrationKind.PROWLER_AZURE:
        account = validate_azure_subscription_config(
            {"account_id": scoped.scanner.azure_subscription_id}
        )
        client_id = scoped.scanner.azure_client_id
        tenant_id = scoped.scanner.azure_tenant_id
        secret = scoped.scanner.azure_client_secret
        if not all((client_id, tenant_id, secret)):
            raise IntegrationNotConfiguredError(
                "prowler_azure", hint="Azure service-principal credentials are required."
            )
        credentials = {
            "AZURE_CLIENT_ID": client_id.get_secret_value(),
            "AZURE_TENANT_ID": tenant_id.get_secret_value(),
            "AZURE_CLIENT_SECRET": secret.get_secret_value(),
        }
        request = ScannerRequest(
            scanner=ScannerName.PROWLER_AZURE,
            targets=(f"azure:{account}",),
            workdir=Path("."),
            timeout_seconds=1,
        )
        await asyncio.to_thread(AZURE_ADAPTER.verify_credential_scope, request, credentials)
        return True
    if kind is IntegrationKind.PROWLER_GCP:
        project = validate_gcp_project_config({"account_id": scoped.scanner.gcp_project_id})
        key = scoped.scanner.gcp_service_account_json
        if key is None:
            raise IntegrationNotConfiguredError(
                "prowler_gcp", hint="Service-account JSON is required."
            )
        token = await asyncio.to_thread(mint_gcp_access_token, key.get_secret_value(), project)
        request = ScannerRequest(
            scanner=ScannerName.PROWLER_GCP,
            targets=(f"gcp:{project}",),
            workdir=Path("."),
            timeout_seconds=1,
        )
        await asyncio.to_thread(
            GCP_ADAPTER.verify_credential_scope,
            request,
            {
                "CLOUDSDK_AUTH_ACCESS_TOKEN": token,
                "GOOGLE_CLOUD_PROJECT": project,
            },
        )
        return True
    if kind is IntegrationKind.DEFECTDOJO:
        return await DefectDojoClient(scoped, redis).ping()
    if kind is IntegrationKind.JIRA:
        return await JiraClient(scoped, redis).ping()
    if kind is IntegrationKind.SERVICENOW:
        client = ServiceNowClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.AZURE_DEVOPS:
        client = AzureDevOpsClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.LINEAR:
        client = LinearClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.PAGERDUTY:
        # Events API v2 has no side-effect-free health endpoint. Treat a saved routing key
        # as configured; the durable outbox records the real delivery result on first use.
        return PagerDutyClient(scoped, redis).configured
    if kind is IntegrationKind.SPLUNK:
        client = SplunkHecClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.SLACK:
        return await SlackClient(scoped, redis).ping()
    if kind is IntegrationKind.DIFY:
        return await DifyClient(scoped, redis).ping()
    if kind is IntegrationKind.MISP:
        return await MISPClient(scoped, redis).ping()
    if kind is IntegrationKind.EMAIL:
        return await EmailSender(scoped).ping()
    if kind is IntegrationKind.WAZUH:
        return await WazuhClient(scoped, redis).ping()
    if kind is IntegrationKind.ZSCALER:
        client = ZscalerClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.GITHUB:
        return await GitHubClient(scoped, redis).ping()
    if kind is IntegrationKind.GITLAB:
        return await GitLabClient(scoped, redis).ping()
    if kind is IntegrationKind.BITBUCKET:
        client = BitbucketClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.SONARQUBE:
        client = SonarQubeClient(scoped, redis)
        try:
            return await client.ping()
        finally:
            await client.aclose()
    if kind is IntegrationKind.SNYK:
        snyk_client = SnykClient(scoped, redis)
        try:
            return await snyk_client.ping()
        finally:
            await snyk_client.aclose()
    if kind is IntegrationKind.TENABLE:
        tenable_client = TenableClient(scoped, redis)
        try:
            return await tenable_client.ping()
        finally:
            await tenable_client.aclose()
    if kind is IntegrationKind.QUALYS:
        qualys_client = QualysClient(scoped, redis)
        try:
            return await qualys_client.ping()
        finally:
            await qualys_client.aclose()
    if kind is IntegrationKind.RAPID7:
        rapid7_client = Rapid7Client(scoped, redis)
        try:
            return await rapid7_client.ping()
        finally:
            await rapid7_client.aclose()
    if kind is IntegrationKind.WIZ:
        wiz_client = WizClient(scoped, redis)
        try:
            return await wiz_client.ping()
        finally:
            await wiz_client.aclose()
    if kind is IntegrationKind.PRISMA_CLOUD:
        prisma_client = PrismaCloudClient(scoped, redis)
        try:
            return await prisma_client.ping()
        finally:
            await prisma_client.aclose()
    if kind is IntegrationKind.CROWDSTRIKE:
        crowdstrike_client = CrowdStrikeClient(scoped, redis)
        try:
            return await crowdstrike_client.ping()
        finally:
            await crowdstrike_client.aclose()
    if kind is IntegrationKind.AWS_SECURITY_HUB:
        security_hub_client = AwsSecurityHubClient(scoped)
        try:
            return await security_hub_client.ping()
        finally:
            await security_hub_client.aclose()
    if kind is IntegrationKind.AWS_INSPECTOR:
        inspector_client = AwsInspectorClient(scoped)
        try:
            return await inspector_client.ping()
        finally:
            await inspector_client.aclose()
    if kind is IntegrationKind.HACKERONE:
        hackerone_client = HackerOneClient(scoped, redis)
        try:
            return await hackerone_client.ping()
        finally:
            await hackerone_client.aclose()
    if kind is IntegrationKind.BUGCROWD:
        bugcrowd_client = BugcrowdClient(scoped, redis)
        try:
            return await bugcrowd_client.ping()
        finally:
            await bugcrowd_client.aclose()
    if kind is IntegrationKind.CHECKMARX:
        checkmarx_client = CheckmarxClient(scoped, redis)
        try:
            return await checkmarx_client.ping()
        finally:
            await checkmarx_client.aclose()
    if kind is IntegrationKind.FORTIFY:
        fortify_client = FortifySscClient(scoped, redis)
        try:
            return await fortify_client.ping()
        finally:
            await fortify_client.aclose()
    if kind is IntegrationKind.AZURE_DEFENDER:
        defender_client = AzureDefenderClient(scoped, redis)
        try:
            return await defender_client.ping()
        finally:
            await defender_client.aclose()
    if kind is IntegrationKind.GCP_SCC:
        scc_client = GcpSccClient(scoped, redis)
        try:
            return await scc_client.ping()
        finally:
            await scc_client.aclose()
    if kind is IntegrationKind.BURP_DAST:
        burp_client = BurpDastClient(scoped, redis)
        try:
            return await burp_client.ping()
        finally:
            await burp_client.aclose()
    # NVD needs no credential and has no cheap authenticated endpoint to probe; reporting
    # it healthy on the strength of its configuration is more honest than an unrelated
    # request that would count against the shared rate limit.
    if kind is IntegrationKind.NVD:
        return True
    raise IntegrationNotConfiguredError(
        kind.value, hint=f"{kind.value} cannot be tested in this release."
    )


async def tenable_scan_status(
    session: AsyncSession,
    principal: Principal,
    scan_id: str,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> str:
    """Read live status of a tenant-configured Tenable scan."""
    principal.require(Permission.INTEGRATION_READ)
    await require_tenant_tenable_integration(session, principal, scan_id)
    scoped = await resolve_settings(
        session, principal, IntegrationKind.TENABLE, settings=settings, require=True
    )
    client = TenableClient(scoped, redis)
    try:
        return await client.latest_scan_status(scan_id)
    finally:
        await client.aclose()
async def require_tenant_tenable_integration(
    session: AsyncSession,
    principal: Principal,
    scan_id: str | None = None,
) -> Integration:
    """Never let an organization launch with another tenant's deployment fallback."""
    integration = await find_integration(session, principal, IntegrationKind.TENABLE)
    if integration is None or not integration.is_usable:
        raise IntegrationNotConfiguredError(
            "Tenable VM", hint="Configure an enabled integration first."
        )
    scan_ids = integration.config.get("scan_ids")
    credential_names = {credential.name for credential in integration.credentials}
    if (
        not isinstance(scan_ids, list)
        or not scan_ids
        or (scan_id is not None and scan_id not in scan_ids)
        or not {"access_key", "secret_key"}.issubset(credential_names)
    ):
        raise IntegrationNotConfiguredError(
            "Tenable VM", hint="Save this scan UUID and both API keys in your organization first."
        )
    return integration


async def launch_tenable_scan(
    session: AsyncSession,
    principal: Principal,
    scan_id: str,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> str | None:
    """Launch an already configured scan, then record the action in this tenant's audit trail."""
    principal.require(Permission.INTEGRATION_MANAGE)
    integration = await require_tenant_tenable_integration(session, principal, scan_id)
    scoped = await resolve_settings(
        session, principal, IntegrationKind.TENABLE, settings=settings, require=True
    )
    client = TenableClient(scoped, redis)
    try:
        launched_uuid = await client.launch_scan(scan_id)
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_SCAN_LAUNCH,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id if integration else None,
            detail={"provider": "tenable", "scan_id": scan_id, "run_uuid": launched_uuid},
        )
        return launched_uuid
    finally:
        await client.aclose()


async def test_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> IntegrationTestOut:
    """Probe a provider live and record the verdict on the row (FR-028, FR-032).

    Never raises for a provider-side failure: an unreachable Jira is the *answer* to
    "test this integration", not an error in answering. Only a caller-side problem
    (missing permission, no such integration) raises. The recorded ``last_error`` is the
    user-safe message from the error taxonomy -- never a provider response body, which
    can echo back a credential (SEC-002).
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    integration = await find_integration(session, principal, kind)
    now = utcnow()
    started = time.monotonic()

    healthy = False
    detail: str | None = None
    try:
        scoped = await resolve_settings(session, principal, kind, settings=settings, require=True)
        healthy = await _ping(kind, scoped, redis)
        detail = "Reachable and authenticated." if healthy else "Provider rejected the probe."
    except CynuxError as exc:
        detail = exc.user_message
        log.warning(
            "integration.test_failed",
            kind=kind.value,
            code=exc.code,
            **exc.to_log_fields(),
        )
    except Exception as exc:  # - an unexpected client bug is still a test result
        detail = "The connectivity test failed unexpectedly. See the server logs."
        log.error("integration.test_error", kind=kind.value, error=type(exc).__name__)

    latency_ms = int((time.monotonic() - started) * 1000)

    if integration is not None:
        if healthy:
            integration.status = IntegrationStatus.CONFIGURED.value
            integration.last_verified_at = now
            integration.last_error = None
            integration.last_error_at = None
            integration.failure_count = 0
        else:
            integration.status = IntegrationStatus.ERROR.value
            integration.last_error = detail
            integration.last_error_at = now
            integration.failure_count += 1

    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_TEST,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id if integration is not None else None,
        outcome=AuditOutcome.SUCCESS if healthy else AuditOutcome.FAILURE,
        detail={"kind": kind.value, "latency_ms": latency_ms},
        reason=None if healthy else detail,
    )
    return IntegrationTestOut(
        kind=kind,
        healthy=healthy,
        detail=detail,
        latency_ms=latency_ms,
        checked_at=now,
    )


async def record_failure(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    error: IntegrationError,
) -> None:
    """Note a provider failure observed during normal work, not during a test.

    Best-effort and silent: it is called from an exception path, and a bookkeeping failure
    must not replace the original provider error with a less useful one.
    """
    try:
        integration = await find_integration(session, principal, kind)
        if integration is None:
            return
        integration.failure_count += 1
        integration.last_error = error.user_message
        integration.last_error_at = utcnow()
        if integration.status == IntegrationStatus.CONFIGURED.value:
            integration.status = IntegrationStatus.ERROR.value
    except Exception:  # - see docstring
        log.warning("integration.failure_not_recorded", kind=kind.value, exc_info=True)


__all__ = [
    "certify_connector",
    "connector_capabilities",
    "connector_certifications",
    "connector_contract_result",
    "credentials_for",
    "disable_integration",
    "find_integration",
    "get_integration",
    "integration_health",
    "integration_sync_quality",
    "integration_out",
    "list_integrations",
    "record_failure",
    "resolve_settings",
    "source_coverage",
    "test_integration",
    "upsert_integration",
]
