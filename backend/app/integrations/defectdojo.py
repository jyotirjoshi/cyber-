"""DefectDojo client (FR-017, FR-018).

DefectDojo is Cynux's vulnerability-management system of record, and the PRD's out-of-scope
list is explicit that Cynux must not build its own.  Two consequences shape this module.

**Cynux does not parse scanner output.**  Raw artifacts are uploaded verbatim to
``/api/v2/import-scan/`` and DefectDojo's own parser turns them into findings.  The
``scan_type`` strings below are DefectDojo parser names, matched exactly -- ``"Nuclei Scan"``
is a different parser from ``"Nuclei"``, and a wrong string is accepted by the API and then
produces zero findings, which looks like a clean scan.  That failure mode is why
:func:`scan_type_for` raises rather than falling back to a guess.

**Cynux does not deduplicate.**  FR-018 delegates deduplication to DefectDojo, which is why
``deduplication_on_engagement`` is set from configuration on every import and why re-running
a scanner against the same engagement uses :meth:`DefectDojoClient.reimport_scan` -- reimport
is the operation that closes findings absent from the new run and reopens ones that came
back, and reproducing that logic locally would be exactly the custom dedup engine the PRD
forbids.

Failures here are not degradable (:class:`~app.core.errors.DefectDojoError` sets
``degradable = False``).  Every other integration can be missing and the assessment still
means something; without DefectDojo there are no findings at all, so the assessment fails
rather than reporting an empty result set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from json import JSONDecodeError
from json import loads as json_loads
from pathlib import Path
from typing import Any

import structlog

from app.core.config import Settings
from app.core.errors import (
    DefectDojoError,
    IntegrationError,
    IntegrationNotConfiguredError,
)
from app.db.enums import ScannerName, Severity
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

logger = structlog.get_logger(__name__)

PROVIDER = "DefectDojo"

#: Exact DefectDojo parser names. Verified against the DefectDojo parser registry; do not
#: "tidy" these strings. ReconFTW is absent deliberately: it is a discovery tool whose
#: output becomes assets in Cynux, not findings in DefectDojo (FR-008, FR-009).
SCAN_TYPES: dict[ScannerName, str] = {
    ScannerName.NMAP: "Nmap Scan",
    ScannerName.NUCLEI: "Nuclei Scan",
    ScannerName.ZAP: "ZAP Scan",
}

#: DefectDojo's severity vocabulary, mapped onto ours. Anything unrecognised becomes
#: ``INFO`` rather than a guess -- an unknown severity silently promoted to ``CRITICAL``
#: would page someone at 3am for a parser change.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}


def scan_type_for(scanner: ScannerName) -> str:
    """The DefectDojo parser name for ``scanner``.

    Raises rather than defaulting: see the module docstring on why a wrong ``scan_type``
    is worse than a hard failure.
    """
    try:
        return SCAN_TYPES[scanner]
    except KeyError as exc:
        raise DefectDojoError(
            f"No DefectDojo parser is mapped for scanner {scanner.value!r}.",
            context={"scanner": scanner.value},
        ) from exc


def map_severity(value: str | None) -> Severity:
    return _SEVERITY_MAP.get((value or "").strip().lower(), Severity.INFO)


@dataclass(frozen=True, slots=True)
class DDProduct:
    id: int
    name: str


@dataclass(frozen=True, slots=True)
class DDEngagement:
    id: int
    name: str
    product_id: int


@dataclass(frozen=True, slots=True)
class DDImportResult:
    """What one ``import-scan`` / ``reimport-scan`` call produced.

    The counts come from DefectDojo's own response and are recorded on the scanner job so
    the agent can say "12 new, 3 reactivated, 5 closed" instead of re-counting findings and
    risking a different answer than the system of record.
    """

    test_id: int
    engagement_id: int
    scan_type: str
    findings_created: int = 0
    findings_closed: int = 0
    findings_reactivated: int = 0
    findings_untouched: int = 0

    @property
    def total_touched(self) -> int:
        return (
            self.findings_created
            + self.findings_closed
            + self.findings_reactivated
            + self.findings_untouched
        )


@dataclass(frozen=True, slots=True)
class DDFinding:
    """A finding as DefectDojo holds it.

    Kept deliberately close to the wire format. The translation into Cynux's internal
    representation (FR-017) happens in the finding service, not here, so this module stays
    a transport and the mapping stays testable without a DefectDojo instance.
    """

    id: int
    title: str
    severity: Severity
    description: str = ""
    mitigation: str = ""
    cve: str | None = None
    cwe: int | None = None
    cvssv3_score: float | None = None
    cvssv3: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    file_path: str | None = None
    line: int | None = None
    active: bool = True
    verified: bool = False
    false_p: bool = False
    duplicate: bool = False
    risk_accepted: bool = False
    out_of_scope: bool = False
    is_mitigated: bool = False
    test_id: int | None = None
    hash_code: str | None = None
    unique_id_from_tool: str | None = None
    vuln_id_from_tool: str | None = None
    endpoints: list[str] = field(default_factory=list)
    references: str = ""
    steps_to_reproduce: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def cves(self) -> list[str]:
        """Every CVE DefectDojo associated with this finding.

        DefectDojo has moved the canonical location over releases -- ``cve`` on older
        versions, a ``vulnerability_ids`` list on newer ones -- and both may be populated.
        Reading both and deduplicating is the only version-independent answer.
        """
        found: list[str] = []
        if self.cve:
            found.append(self.cve.strip().upper())
        for entry in self.raw.get("vulnerability_ids") or []:
            value = entry.get("vulnerability_id") if isinstance(entry, dict) else entry
            if isinstance(value, str) and value.strip().upper().startswith("CVE-"):
                found.append(value.strip().upper())
        #: Ordered de-duplication via ``dict``, matching the convention in
        #: :mod:`app.scanners.nmap` and :mod:`app.scanners.zap`. The terser
        #: ``set.add``-in-a-comprehension idiom works but reads as a bug.
        seen: dict[str, None] = {}
        for value in found:
            seen.setdefault(value, None)
        return list(seen)


def _parse_finding(payload: dict[str, Any]) -> DDFinding:
    def _int(key: str) -> int | None:
        value = payload.get(key)
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _float(key: str) -> float | None:
        value = payload.get(key)
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    endpoints: list[str] = []
    for entry in payload.get("endpoints") or []:
        if isinstance(entry, str):
            endpoints.append(entry)
        elif isinstance(entry, dict):
            #: Depending on the serializer depth DefectDojo returns either an id or a
            #: nested object. Only the human-readable form is useful to us.
            label = entry.get("endpoint") or entry.get("host") or entry.get("id")
            if label is not None:
                endpoints.append(str(label))

    return DDFinding(
        id=int(payload["id"]),
        title=str(payload.get("title") or "Untitled finding"),
        severity=map_severity(payload.get("severity")),
        description=str(payload.get("description") or ""),
        mitigation=str(payload.get("mitigation") or ""),
        cve=payload.get("cve"),
        cwe=_int("cwe"),
        cvssv3_score=_float("cvssv3_score"),
        cvssv3=payload.get("cvssv3"),
        component_name=payload.get("component_name"),
        component_version=payload.get("component_version"),
        file_path=payload.get("file_path"),
        line=_int("line"),
        active=bool(payload.get("active", True)),
        verified=bool(payload.get("verified", False)),
        false_p=bool(payload.get("false_p", False)),
        duplicate=bool(payload.get("duplicate", False)),
        risk_accepted=bool(payload.get("risk_accepted", False)),
        out_of_scope=bool(payload.get("out_of_scope", False)),
        is_mitigated=bool(payload.get("is_mitigated", False)),
        test_id=_int("test"),
        hash_code=payload.get("hash_code"),
        unique_id_from_tool=payload.get("unique_id_from_tool"),
        vuln_id_from_tool=payload.get("vuln_id_from_tool"),
        endpoints=endpoints,
        references=str(payload.get("references") or ""),
        steps_to_reproduce=str(payload.get("steps_to_reproduce") or ""),
        raw=payload,
    )


class DefectDojoClient:
    """Typed wrapper over the DefectDojo v2 REST API."""

    def __init__(self, settings: Settings, redis: Any | None = None) -> None:
        self.settings = settings
        self._cfg = settings.defectdojo
        self._client: ResilientClient | None = None
        self._redis = redis

    @property
    def configured(self) -> bool:
        return bool(self._cfg.configured)

    def _require(self) -> ResilientClient:
        """Return the transport, raising if DefectDojo was never set up.

        Never a silent no-op. An agent that receives ``{"findings": []}`` from an
        unconfigured integration concludes the target is clean and says so; a raised
        :class:`IntegrationNotConfiguredError` becomes a visible degradation instead.
        """
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set CYNUX_DEFECTDOJO__BASE_URL and CYNUX_DEFECTDOJO__API_TOKEN.",
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url or "",
                settings=self.settings,
                redis=self._redis,
                headers={
                    #: DefectDojo's scheme is literally "Token <key>", not "Bearer".
                    "Authorization": f"Token {reveal(self._cfg.api_token)}",
                    "Accept": "application/json",
                },
                timeout=float(self._cfg.timeout_seconds),
                verify=self._cfg.verify_tls,
                #: Imports are long and expensive. Retrying a 60-second multipart upload
                #: three times turns one slow import into three minutes of held worker.
                retry=RetryPolicy(max_attempts=2, backoff_base=1.0),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=90),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- product type / product / engagement ---------------------------------

    async def _find_one(self, path: str, params: dict[str, Any]) -> dict[str, Any] | None:
        client = self._require()
        payload = await client.get_json(path, params={**params, "limit": 1})
        results = (payload or {}).get("results") or []
        return results[0] if results else None

    async def ensure_product_type(self) -> int:
        name = self._cfg.product_type_name
        existing = await self._find_one("/api/v2/product_types/", {"name": name})
        if existing:
            return int(existing["id"])
        created = await self._require().post_json(
            "/api/v2/product_types/",
            json={"name": name, "description": "Products created by Cynux assessments."},
        )
        return int(created["id"])

    async def ensure_product(self, name: str, *, description: str = "") -> DDProduct:
        """Find or create the product for an organization.

        Cynux maps one organization to one DefectDojo product, so the name must already be
        namespaced by the caller (``org-{slug}``). Product names are globally unique in
        DefectDojo -- two tenants that both picked "Website" would otherwise land in the
        same product and violate SEC-003.
        """
        existing = await self._find_one("/api/v2/products/", {"name": name})
        if existing:
            return DDProduct(id=int(existing["id"]), name=str(existing["name"]))

        product_type = await self.ensure_product_type()
        created = await self._require().post_json(
            "/api/v2/products/",
            json={
                "name": name,
                "description": description or f"Cynux-managed product for {name}.",
                "prod_type": product_type,
                "enable_simple_risk_acceptance": False,
            },
        )
        logger.info("defectdojo.product_created", product=name, product_id=created["id"])
        return DDProduct(id=int(created["id"]), name=str(created["name"]))

    async def ensure_engagement(
        self,
        *,
        product_id: int,
        name: str,
        target_start: str,
        target_end: str,
        description: str = "",
        tags: list[str] | None = None,
    ) -> DDEngagement:
        """Find or create the engagement for one assessment.

        One assessment is one engagement. That boundary is what makes
        ``deduplication_on_engagement`` mean "within this assessment" (FR-018) and what lets
        an assessment be closed without touching another's findings.
        """
        existing = await self._find_one(
            "/api/v2/engagements/", {"name": name, "product": product_id}
        )
        if existing:
            return DDEngagement(
                id=int(existing["id"]),
                name=str(existing["name"]),
                product_id=int(existing["product"]),
            )

        created = await self._require().post_json(
            "/api/v2/engagements/",
            json={
                "name": name,
                "product": product_id,
                "target_start": target_start,
                "target_end": target_end,
                "description": description,
                "status": "In Progress",
                "engagement_type": "CI/CD",
                "deduplication_on_engagement": self._cfg.deduplication_on_engagement,
                "tags": tags or ["cynux"],
                "active": True,
            },
        )
        logger.info("defectdojo.engagement_created", engagement=name, engagement_id=created["id"])
        return DDEngagement(
            id=int(created["id"]),
            name=str(created["name"]),
            product_id=int(created["product"]),
        )

    async def close_engagement(self, engagement_id: int) -> None:
        await self._require().patch_json(
            f"/api/v2/engagements/{engagement_id}/",
            json={"status": "Completed", "active": False},
        )

    # -- import / reimport ---------------------------------------------------

    def _import_fields(
        self,
        *,
        engagement_id: int,
        scan_type: str,
        scan_date: str | None,
        test_title: str | None,
        minimum_severity: Severity,
        tags: list[str] | None,
        service: str | None,
    ) -> dict[str, str]:
        """Multipart form fields shared by import and reimport.

        Everything is a string because this is a multipart body, not JSON: DefectDojo's
        form parser reads ``"true"``/``"false"``, and sending a Python ``True`` produces a
        field of ``"True"`` that some DefectDojo versions read as false.
        """
        fields: dict[str, str] = {
            "scan_type": scan_type,
            "engagement": str(engagement_id),
            #: New findings are active but unverified: FR-017 makes verification a human
            #: or AI-assisted step, and auto-verifying scanner output would assert a
            #: confidence nothing has established.
            "active": "true",
            "verified": "false",
            "close_old_findings": "true" if self._cfg.close_old_findings else "false",
            "deduplication_on_engagement": (
                "true" if self._cfg.deduplication_on_engagement else "false"
            ),
            "minimum_severity": minimum_severity.value.capitalize(),
            #: Cynux never pushes to Jira through DefectDojo. FR-027 routes ticketing
            #: through Cynux so the ticket carries the AI analysis and the link is recorded
            #: in ``ticket_links``; letting DefectDojo also push would double-file.
            "push_to_jira": "false",
        }
        if scan_date:
            fields["scan_date"] = scan_date
        if test_title:
            fields["test_title"] = test_title
        if service:
            fields["service"] = service
        if tags:
            fields["tags"] = ",".join(tags)
        return fields

    async def import_scan(
        self,
        *,
        engagement_id: int,
        scan_type: str,
        file: Path | bytes,
        filename: str | None = None,
        scan_date: str | None = None,
        test_title: str | None = None,
        minimum_severity: Severity = Severity.INFO,
        tags: list[str] | None = None,
        service: str | None = None,
    ) -> DDImportResult:
        """Upload a raw scanner artifact for DefectDojo to parse (FR-017)."""
        client = self._require()
        content, name = _read_upload(file, filename)
        response = await client.request(
            "POST",
            "/api/v2/import-scan/",
            data=self._import_fields(
                engagement_id=engagement_id,
                scan_type=scan_type,
                scan_date=scan_date,
                test_title=test_title,
                minimum_severity=minimum_severity,
                tags=tags,
                service=service,
            ),
            files={"file": (name, content, "application/octet-stream")},
        )
        body = _decode_import(response.text, path="/api/v2/import-scan/")
        result = _import_result(body, engagement_id=engagement_id, scan_type=scan_type)
        logger.info(
            "defectdojo.import_complete",
            engagement_id=engagement_id,
            scan_type=scan_type,
            test_id=result.test_id,
            created=result.findings_created,
        )
        return result

    async def reimport_scan(
        self,
        *,
        test_id: int,
        engagement_id: int,
        scan_type: str,
        file: Path | bytes,
        filename: str | None = None,
        scan_date: str | None = None,
        minimum_severity: Severity = Severity.INFO,
        tags: list[str] | None = None,
        service: str | None = None,
    ) -> DDImportResult:
        """Re-upload against an existing test so DefectDojo reconciles the delta (FR-018).

        This is the operation that closes findings which no longer appear and reopens ones
        that returned. Cynux must not compute that delta itself.
        """
        client = self._require()
        content, name = _read_upload(file, filename)
        fields = self._import_fields(
            engagement_id=engagement_id,
            scan_type=scan_type,
            scan_date=scan_date,
            test_title=None,
            minimum_severity=minimum_severity,
            tags=tags,
            service=service,
        )
        fields["test"] = str(test_id)
        #: Reimport is where closing stale findings is the point, regardless of the
        #: configured default for a first import.
        fields["close_old_findings"] = "true"
        response = await client.request(
            "POST",
            "/api/v2/reimport-scan/",
            data=fields,
            files={"file": (name, content, "application/octet-stream")},
        )
        body = _decode_import(response.text, path="/api/v2/reimport-scan/")
        return _import_result(body, engagement_id=engagement_id, scan_type=scan_type)

    # -- findings ------------------------------------------------------------

    async def list_findings(
        self,
        *,
        test_id: int | None = None,
        engagement_id: int | None = None,
        limit: int = 100,
        max_records: int = 2000,
        active_only: bool = False,
    ) -> list[DDFinding]:
        """Page through findings for a test or an engagement.

        ``max_records`` is a hard stop, and hitting it is logged. An engagement with
        50,000 informational findings would otherwise page forever and hand the caller a
        list too large to put anywhere near an LLM (SEC-006).
        """
        if test_id is None and engagement_id is None:
            raise ValueError("one of test_id or engagement_id is required")

        client = self._require()
        params: dict[str, Any] = {"limit": min(limit, 200), "offset": 0}
        if test_id is not None:
            params["test"] = test_id
        if engagement_id is not None:
            params["test__engagement"] = engagement_id
        if active_only:
            params["active"] = "true"
            params["duplicate"] = "false"

        findings: list[DDFinding] = []
        while True:
            payload = await client.get_json("/api/v2/findings/", params=dict(params))
            results = (payload or {}).get("results") or []
            for entry in results:
                try:
                    findings.append(_parse_finding(entry))
                except (KeyError, TypeError, ValueError):
                    #: One malformed record must not lose the other 99. The count of
                    #: skipped records is what the caller needs to know, not the record.
                    logger.warning("defectdojo.finding_unparseable", finding_id=entry.get("id"))
            if len(findings) >= max_records:
                logger.warning(
                    "defectdojo.findings_truncated",
                    max_records=max_records,
                    test_id=test_id,
                    engagement_id=engagement_id,
                )
                break
            if not (payload or {}).get("next") or not results:
                break
            params["offset"] = int(params["offset"]) + len(results)
        return findings

    async def get_finding(self, finding_id: int) -> DDFinding:
        payload = await self._require().get_json(f"/api/v2/findings/{finding_id}/")
        if not payload:
            raise DefectDojoError(
                f"DefectDojo returned no body for finding {finding_id}.",
                context={"finding_id": finding_id},
            )
        return _parse_finding(payload)

    async def update_finding(self, finding_id: int, **fields: Any) -> DDFinding:
        """Patch a finding's triage state.

        Only triage fields are ever written back -- ``active``, ``verified``, ``false_p``,
        ``risk_accepted``, ``out_of_scope``, ``mitigated``, ``notes``. Cynux does not
        rewrite titles, severities or descriptions in DefectDojo: it is the system of
        record, and an AI-adjusted severity belongs on Cynux's own finding row where it is
        labelled as AI-derived (FR-023).
        """
        allowed = {
            "active",
            "verified",
            "false_p",
            "duplicate",
            "risk_accepted",
            "out_of_scope",
            "is_mitigated",
            "tags",
            "notes",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"fields not permitted on a DefectDojo update: {sorted(unknown)}")
        payload = await self._require().patch_json(f"/api/v2/findings/{finding_id}/", json=fields)
        return _parse_finding(payload)

    # -- health --------------------------------------------------------------

    async def ping(self) -> bool:
        """Cheap authenticated round-trip for the integration-test endpoint."""
        await self._require().get_json("/api/v2/user_profile/")
        return True


def _read_upload(file: Path | bytes, filename: str | None) -> tuple[bytes, str]:
    if isinstance(file, bytes):
        return file, filename or "scan.out"
    path = Path(file)
    return path.read_bytes(), filename or path.name


def _decode_import(text: str, *, path: str) -> dict[str, Any]:
    try:
        body = json_loads(text) if text else {}
    except JSONDecodeError as exc:
        raise DefectDojoError(
            "DefectDojo returned a non-JSON response to a scan import.",
            context={"path": path},
            cause=exc,
        ) from exc
    if not isinstance(body, dict):
        raise DefectDojoError(
            "DefectDojo returned an unexpected shape for a scan import.",
            context={"path": path},
        )
    return body


def _count(body: dict[str, Any], *keys: str) -> int:
    """Read a finding count from whichever key this DefectDojo version used.

    The import response has changed shape across releases: some versions return an integer
    under ``findings_created``, others a list of finding ids, others a list under
    ``new_findings``. Accepting all three keeps the counts honest across upgrades instead of
    silently reporting zero after a DefectDojo bump.
    """
    for key in keys:
        value = body.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, list):
            return len(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                continue
    return 0


def _import_result(body: dict[str, Any], *, engagement_id: int, scan_type: str) -> DDImportResult:
    test_id = body.get("test") or body.get("test_id")
    if test_id is None:
        #: Without a test id the artifact is unreachable: nothing can list its findings.
        #: Reporting a successful import here would produce an assessment with zero
        #: findings and no explanation.
        raise DefectDojoError(
            "DefectDojo accepted the import but returned no test id.",
            context={"engagement_id": engagement_id, "scan_type": scan_type},
        )
    return DDImportResult(
        test_id=int(test_id),
        engagement_id=engagement_id,
        scan_type=scan_type,
        findings_created=_count(body, "findings_created", "new_findings"),
        findings_closed=_count(body, "findings_closed", "closed_findings"),
        findings_reactivated=_count(body, "findings_reactivated", "reactivated_findings"),
        findings_untouched=_count(body, "findings_untouched", "untouched_findings"),
    )


def wrap_transport_error(exc: IntegrationError) -> DefectDojoError:
    """Re-raise a generic transport failure as the non-degradable DefectDojo variant.

    The HTTP spine raises ``IntegrationError``, which is ``degradable = True``. For
    DefectDojo that is wrong: the error handler node must treat a DefectDojo outage as a
    failed assessment, not a partial one.
    """
    return DefectDojoError(
        exc.message,
        context=exc.context,
        cause=exc.cause or exc,
        retryable=exc.retryable,
    )


__all__ = [
    "PROVIDER",
    "SCAN_TYPES",
    "DDEngagement",
    "DDFinding",
    "DDImportResult",
    "DDProduct",
    "DefectDojoClient",
    "map_severity",
    "scan_type_for",
    "wrap_transport_error",
]
