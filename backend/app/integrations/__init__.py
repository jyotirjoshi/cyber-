"""External integrations (FR-016 .. FR-021, FR-027, FR-029, FR-015, FR-020).

Every outbound HTTP request Cynux makes goes through :mod:`app.integrations.http`.  That is
the point of this package: retries, rate limits, circuit breaking, secret redaction and
response caching are decided once, in one place, rather than re-argued in each client.  A
client here is thin -- it knows a provider's URL shapes and response schema, and nothing about
transport policy.

Two conventions hold across all of them, and both exist because of how this data is used.

**An unconfigured integration raises.**  :class:`~app.core.errors.IntegrationNotConfiguredError`
on first use, never a silent no-op returning empty results.  A no-op looks like success to the
agent, and an agent that believes it checked CISA KEV and found nothing will write exactly
that in a report (FR-024).

**A failed lookup and an authoritative negative are different values.**  ``None``/``False``
means "the provider answered and has no record"; an exception means "we could not ask".
:class:`~app.db.enums.EnrichmentStatus` carries that distinction to the database, and
``Finding.in_kev`` is ``bool | None`` for the same reason.  Collapsing the two would put a
fabricated negative in front of a security engineer.

Secrets are unwrapped at exactly one named function, :func:`app.integrations.http.reveal`, so
"where does a plaintext credential exist?" is a greppable question (SEC-002).
"""

from __future__ import annotations

from app.integrations.circuit import (
    BreakerConfig,
    BreakerStatus,
    CircuitBreaker,
    CircuitState,
)
from app.integrations.defectdojo import (
    SCAN_TYPES,
    DDEngagement,
    DDFinding,
    DDImportResult,
    DDProduct,
    DefectDojoClient,
    map_severity,
    scan_type_for,
)
from app.integrations.dify import DifyClient, KnowledgeChunk
from app.integrations.email import EmailSender, SentEmail
from app.integrations.epss import EPSSClient, EPSSScore
from app.integrations.http import (
    ResilientClient,
    RetryPolicy,
    build_client,
    parse_retry_after,
    redact_headers,
    reveal,
)
from app.integrations.jira import (
    PRIORITY_NAMES,
    SEVERITY_PRIORITY,
    JiraClient,
    JiraIssue,
    finding_label,
    to_adf,
)
from app.integrations.kev import KEVCatalog, KEVClient, KEVEntry
from app.integrations.misp import MISPClient, MISPHit
from app.integrations.nvd import CVSSMetric, NVDClient, NVDRecord
from app.integrations.slack import (
    SlackClient,
    SlackMessage,
    escape_slack,
    severity_emoji,
)
from app.integrations.storage import (
    ObjectStorage,
    StoredObject,
    artifact_key,
    report_key,
)

__all__ = [
    "PRIORITY_NAMES",
    "SCAN_TYPES",
    "SEVERITY_PRIORITY",
    "BreakerConfig",
    "BreakerStatus",
    "CVSSMetric",
    "CircuitBreaker",
    "CircuitState",
    "DDEngagement",
    "DDFinding",
    "DDImportResult",
    "DDProduct",
    "DefectDojoClient",
    "DifyClient",
    "EPSSClient",
    "EPSSScore",
    "EmailSender",
    "JiraClient",
    "JiraIssue",
    "KEVCatalog",
    "KEVClient",
    "KEVEntry",
    "KnowledgeChunk",
    "MISPClient",
    "MISPHit",
    "NVDClient",
    "NVDRecord",
    "ObjectStorage",
    "ResilientClient",
    "RetryPolicy",
    "SentEmail",
    "SlackClient",
    "SlackMessage",
    "StoredObject",
    "artifact_key",
    "build_client",
    "escape_slack",
    "finding_label",
    "map_severity",
    "parse_retry_after",
    "redact_headers",
    "report_key",
    "reveal",
    "scan_type_for",
    "severity_emoji",
    "to_adf",
]
