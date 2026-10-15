"""Bounded scanner export parsing for the existing canonical intake path."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cloud_identity import resource_within_account
from app.core.errors import InvalidConfigurationError, PermissionDeniedError
from app.core.logging_conf import redact_text
from app.db.base import utcnow
from app.db.enums import ArtifactKind, JobStatus, Permission, ScannerName
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.scanner import ScannerJob
from app.db.queries import pg_any
from app.integrations.storage import ObjectStorage
from app.services import audit as audit_service
from app.services import external_alert
from app.services.canonical_identity import normalized_asset_identity, valid_cves
from app.services.canonical_ingest import link_scan_observations
from app.services.context import Principal
from app.services.external_alert import NormalizedExternalAlert

MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_IMPORT_FINDINGS = 10_000
_PROVIDER = re.compile(r"[a-z][a-z0-9_-]{1,39}\Z")
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_FIELD_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){0,2}\Z")
_GENERIC_FIELDS = frozenset({"id", "title", "severity", "status", "cve", "package", "location"})
_RAPID7_POSITIVE = frozenset({"ve", "vv", "vp"})
_RAPID7_NEGATIVE = frozenset({"nv", "ov"})
_RAPID7_IGNORED = frozenset({"ds", "ee", "ep", "er", "ev", "nt", "sd", "sv", "uk"})


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _stable_id(*parts: object) -> str:
    raw = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _severity(value: object, *, score: object = None) -> str:
    try:
        numeric = float(score) if score is not None else None
    except (TypeError, ValueError):
        numeric = None
    if numeric is not None and 0 <= numeric <= 10:
        if numeric >= 9:
            return "critical"
        if numeric >= 7:
            return "high"
        if numeric >= 4:
            return "medium"
        if numeric > 0:
            return "low"
        return "info"
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }.get(str(value or "").lower(), "info")


def _sarif_index(items: list[Any], index: object, label: str) -> dict[str, Any]:
    if type(index) is not int or index < 0 or index >= len(items):
        raise ValueError(f"{label} index is outside the declared array")
    return _object(items[index], label)


def _sarif_artifact_uri(run: dict[str, Any], location: dict[str, Any]) -> str:
    """Resolve inline/indexed artifact locations without accessing the filesystem."""
    uri = str(location.get("uri") or "")
    index = location.get("index", -1)
    if index != -1:
        artifact = _sarif_index(
            _array(run.get("artifacts", []), "SARIF artifacts"), index, "SARIF artifact"
        )
        declared = _object(artifact.get("location", {}), "SARIF artifact location")
        declared_uri = str(declared.get("uri") or "")
        if uri and declared_uri and uri != declared_uri:
            raise ValueError("SARIF artifact URI and index disagree")
        uri = uri or declared_uri
    return uri


def _sarif(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if document.get("version") != "2.1.0":
        raise ValueError("SARIF version 2.1.0 is required")
    runs = _array(document.get("runs"), "SARIF runs")
    result: list[NormalizedExternalAlert] = []
    for run in runs:
        run = _object(run, "SARIF run")
        driver = _object(_object(run.get("tool"), "SARIF tool").get("driver"), "SARIF driver")
        rule_list = _array(driver.get("rules", []), "SARIF rules")
        rules = {
            str(rule.get("id")): rule
            for rule in rule_list
            if isinstance(rule, dict) and rule.get("id")
        }
        for finding in _array(run.get("results"), "SARIF results"):
            finding = _object(finding, "SARIF result")
            rule_id = str(finding.get("ruleId") or "").strip()
            rule_index = finding.get("ruleIndex", -1)
            if rule_index != -1:
                indexed_rule = _sarif_index(rule_list, rule_index, "SARIF rule")
                indexed_id = str(indexed_rule.get("id") or "").strip()
                if rule_id and indexed_id != rule_id:
                    raise ValueError("SARIF rule ID and index disagree")
                rule_id = rule_id or indexed_id
            rule = _object(rules.get(rule_id, {}), "SARIF rule")
            message = _object(finding.get("message"), "SARIF message")
            # Some producers store message templates on the rule rather than
            # repeating the same text in every result.
            message_text = message.get("text") or message.get("markdown")
            if not message_text and message.get("id"):
                messages = _object(rule.get("messageStrings", {}), "SARIF rule messages")
                template = _object(
                    messages.get(str(message["id"]), {}), "SARIF message template"
                )
                message_text = template.get("text") or template.get("markdown")
                if message_text:
                    arguments = _array(message.get("arguments", []), "SARIF message arguments")
                    # Replace only SARIF numeric placeholders, never evaluate
                    # formatting expressions supplied by an imported document.
                    message_text = re.sub(
                        r"\{(\d+)\}",
                        lambda match: str(arguments[int(match[1])])[:1000]
                        if len(match[1]) < 6 and int(match[1]) < len(arguments)
                        else match[0],
                        str(message_text)[:1000],
                    )
            title = str(message_text or rule_id).strip()
            if not title:
                raise ValueError("SARIF result has no title")
            locations = _array(finding.get("locations", []), "SARIF locations")
            physical = {}
            if locations:
                physical = _object(
                    _object(locations[0], "SARIF location").get("physicalLocation", {}),
                    "SARIF physical location",
                )
            file_uri = _sarif_artifact_uri(
                run, _object(physical.get("artifactLocation", {}), "SARIF artifact")
            )
            region = _object(physical.get("region", {}), "SARIF region")
            line = region.get("startLine")
            fingerprints = finding.get("partialFingerprints") or finding.get("fingerprints") or {}
            fingerprints = _object(fingerprints, "SARIF fingerprints")
            stable_fingerprint = next(
                (str(value) for _, value in sorted(fingerprints.items()) if value), ""
            )
            if not stable_fingerprint and not (rule_id and file_uri):
                raise ValueError("SARIF result has no stable source identity")
            rule_properties = _object(rule.get("properties", {}), "SARIF rule properties")
            configuration = _object(
                rule.get("defaultConfiguration", {}), "SARIF rule configuration"
            )
            tags = _array(rule_properties.get("tags", []), "SARIF rule tags")
            cves = valid_cves(_CVE_IN_TEXT.findall(" ".join([rule_id, *map(str, tags)])))
            external_id = _stable_id(
                provider, kind, asset, rule_id, stable_fingerprint or [file_uri, line]
            )
            result.append(
                NormalizedExternalAlert(
                    external_id=external_id,
                    category="sast",
                    title=title[:1000],
                    severity=_severity(
                        finding.get("level", configuration.get("level", "warning")),
                        score=rule_properties.get("security-severity"),
                    ),
                    status="open",
                    resource=asset,
                    source_url=None,
                    cve_ids=cves,
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "file": file_uri[:500],
                        "line": line if isinstance(line, int) else None,
                        "rule_id": rule_id[:200],
                        "tool": str(driver.get("name") or provider)[:100],
                    },
                    raw_payload={},
                )
            )
            if len(result) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    return result


def _trivy(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    results = _array(document.get("Results"), "Trivy Results")
    alerts: list[NormalizedExternalAlert] = []
    for result in results:
        result = _object(result, "Trivy result")
        target = str(result.get("Target") or "").strip()
        for misconfiguration in _array(
            result.get("Misconfigurations", []), "Trivy misconfigurations"
        ):
            issue = _object(misconfiguration, "Trivy misconfiguration")
            if str(issue.get("Status") or "FAIL").upper() != "FAIL":
                continue
            rule_id = str(issue.get("ID") or "").strip()
            cause = _object(issue.get("CauseMetadata", {}), "Trivy cause metadata")
            line = cause.get("StartLine")
            if not rule_id or not target:
                raise ValueError("Trivy misconfiguration lacks stable rule and target identity")
            if not isinstance(line, int) or line < 1:
                line = None
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, target, rule_id, line),
                    category="misconfiguration",
                    title=redact_text(str(issue.get("Title") or rule_id)[:1000]),
                    severity=_severity(issue.get("Severity")),
                    status="open",
                    resource=asset,
                    source_url=None,
                    cve_ids=[],
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "target": target[:500],
                        "rule_id": rule_id[:200],
                        "line": line,
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
        for secret in _array(result.get("Secrets", []), "Trivy secrets"):
            secret = _object(secret, "Trivy secret")
            rule_id = str(secret.get("RuleID") or "").strip()
            line = secret.get("StartLine")
            if not rule_id or not target or not isinstance(line, int) or line < 1:
                raise ValueError("Trivy secret lacks stable rule and location identity")
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, target, rule_id, line),
                    category="secret",
                    title=f"Secret exposure: {rule_id[:150]}",
                    severity=_severity(secret.get("Severity")),
                    status="open",
                    resource=asset,
                    source_url=None,
                    cve_ids=[],
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "target": target[:500],
                        "rule_id": rule_id[:200],
                        "start_line": line,
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
        for vulnerability in _array(result.get("Vulnerabilities", []), "Trivy vulnerabilities"):
            vulnerability = _object(vulnerability, "Trivy vulnerability")
            vuln_id = str(vulnerability.get("VulnerabilityID") or "").strip()
            package = str(vulnerability.get("PkgName") or "").strip()
            installed = str(vulnerability.get("InstalledVersion") or "").strip()
            if not vuln_id or not package or not target:
                raise ValueError("Trivy vulnerability lacks stable package identity")
            title = str(vulnerability.get("Title") or vuln_id).strip()[:1000]
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(
                        provider, kind, asset, target, vuln_id, package, installed
                    ),
                    category="sca",
                    title=title,
                    severity=_severity(vulnerability.get("Severity")),
                    status="open",
                    resource=asset,
                    source_url=None,
                    cve_ids=valid_cves([vuln_id]),
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "target": target[:500],
                        "package": package[:200],
                        "installed_version": installed[:100],
                        "fixed_version": str(vulnerability.get("FixedVersion") or "")[:100],
                        "vulnerability_id": vuln_id[:100],
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    return alerts


def _nessus_xml(
    data: bytes,
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if kind not in {"domain", "ip"}:
        raise ValueError("Nessus XML requires a selected domain or IP asset")
    try:
        root = SafeET.fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("Nessus XML is invalid or contains prohibited XML declarations") from exc
    if root.tag != "NessusClientData_v2":
        raise ValueError("Nessus XML has an unsupported root")

    def matches_selected(name: str) -> bool:
        if not name.strip():
            return False
        try:
            return normalized_asset_identity(kind, name)[1] == asset
        except ValueError:
            return False

    alerts: list[NormalizedExternalAlert] = []
    matched = False
    for host in root.findall("./Report/ReportHost"):
        names = [host.get("name") or ""]
        names.extend(
            tag.text or ""
            for tag in host.findall("./HostProperties/tag")
            if tag.get("name") in {"host-ip", "host-fqdn", "hostname"}
        )
        if not any(matches_selected(name) for name in names):
            continue
        matched = True
        for item in host.findall("ReportItem"):
            plugin_id = str(item.get("pluginID") or "").strip()
            title = str(item.get("pluginName") or plugin_id).strip()
            protocol = str(item.get("protocol") or "").strip().lower()
            try:
                port = int(item.get("port") or "")
            except ValueError as exc:
                raise ValueError("Nessus finding has an invalid port") from exc
            if not plugin_id.isdigit() or not title or not 0 <= port <= 65535 or not protocol:
                raise ValueError("Nessus finding lacks stable plugin and service identity")
            severity = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}.get(
                str(item.get("severity") or ""),
            )
            if severity is None:
                severity = _severity(
                    item.findtext("risk_factor"), score=item.findtext("cvss3_base_score")
                )
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, plugin_id, port, protocol),
                    category="network",
                    title=redact_text(title[:1000]),
                    severity=severity,
                    status="open",
                    resource=asset,
                    source_url=None,
                    cve_ids=valid_cves([child.text or "" for child in item.findall("cve")]),
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "plugin_id": plugin_id[:100],
                        "port": port,
                        "protocol": protocol[:20],
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    if not matched:
        raise ValueError("Nessus XML contains no report for the selected asset")
    return alerts


def _burp_xml(
    data: bytes,
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if kind not in {"domain", "ip", "url"}:
        raise ValueError("Burp XML requires a selected web asset")
    if re.search(rb"<!DOCTYPE\s+issues\s+(?:SYSTEM|PUBLIC)\b", data, re.I):
        raise ValueError("Burp XML cannot reference an external DTD")
    try:
        # Burp exports normally contain an internal DTD. Allow declarations, never entities.
        root = SafeET.fromstring(
            data,
            forbid_dtd=False,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("Burp XML is malformed or contains unsafe XML") from exc
    if root.tag != "issues":
        raise ValueError("Burp XML must have an issues root")

    selected_url = urlsplit(asset) if kind == "url" else None
    selected_host = selected_url.hostname if selected_url else asset
    selected_path = (selected_url.path.rstrip("/") or "/") if selected_url else "/"
    alerts: list[NormalizedExternalAlert] = []
    matched_host = False
    issues = root.findall("issue")
    for issue in issues:
        host_node = issue.find("host")
        host_text = (host_node.text or "").strip() if host_node is not None else ""
        try:
            host_url = urlsplit(host_text if "://" in host_text else f"//{host_text}")
            host_name = (host_url.hostname or "").rstrip(".").lower()
            host_port = host_url.port
        except ValueError:
            raise ValueError("Burp XML has an invalid issue host") from None
        if host_url.username or host_url.password or host_url.query or host_url.fragment:
            raise ValueError("Burp XML has an invalid issue host")
        host_ip = (host_node.get("ip") or "").strip() if host_node is not None else ""
        if kind == "ip":
            in_scope = selected_host in {host_name, host_ip}
        else:
            in_scope = selected_host == host_name
        if not in_scope:
            continue
        if selected_url is not None:
            report_scheme = host_url.scheme.lower() if host_url.scheme else selected_url.scheme
            report_port = host_port or (443 if report_scheme == "https" else 80)
            selected_port = selected_url.port or (443 if selected_url.scheme == "https" else 80)
            if report_scheme != selected_url.scheme or report_port != selected_port:
                continue
        raw_path = (issue.findtext("path") or "").strip()
        try:
            path_url = urlsplit(raw_path)
        except ValueError:
            raise ValueError("Burp XML has an invalid issue path") from None
        if path_url.scheme:
            if path_url.hostname != selected_host:
                continue
            if selected_url is not None:
                try:
                    path_port = path_url.port or (443 if path_url.scheme == "https" else 80)
                except ValueError:
                    continue
                if path_url.scheme != selected_url.scheme or path_port != selected_port:
                    continue
            path = path_url.path or "/"
        else:
            path = path_url.path or "/"
        if not path.startswith("/"):
            raise ValueError("Burp issue has an invalid path")
        if (
            selected_path != "/"
            and path != selected_path
            and not path.startswith(selected_path + "/")
        ):
            continue
        matched_host = True
        serial = (issue.findtext("serialNumber") or "").strip()
        issue_type = (issue.findtext("type") or "").strip()
        name = (issue.findtext("name") or "").strip()
        if not serial or not issue_type or not name:
            raise ValueError("Burp issue lacks stable identity or name")
        confidence = (issue.findtext("confidence") or "").strip().lower()
        if confidence not in {"certain", "firm", "tentative"}:
            confidence = "unknown"
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, kind, asset, serial, issue_type, path),
                category="dast",
                title=redact_text(name[:1000]),
                severity=_severity(issue.findtext("severity")),
                status="open",
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(_CVE_IN_TEXT.findall(name)),
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "issue_type": issue_type[:100],
                    "path": path[:500],
                    "confidence": confidence,
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if issues and not matched_host:
        raise ValueError("Burp XML has no issues for the selected asset")
    return alerts


def _qualys_host_detection_xml(
    data: bytes,
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if kind not in {"domain", "ip"}:
        raise ValueError("Qualys host detection XML requires a selected domain or IP")
    try:
        # Qualys emits an external DTD reference; defusedxml never resolves it.
        root = SafeET.fromstring(
            data,
            forbid_dtd=False,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("Qualys XML is malformed or contains unsafe XML") from exc
    if root.tag != "HOST_LIST_VM_DETECTION_OUTPUT":
        raise ValueError("Qualys XML has an unsupported root")
    response = root.find("RESPONSE")
    if response is None:
        raise ValueError("Qualys XML has no response")
    if response.find("WARNING") is not None:
        raise ValueError("Qualys XML response is truncated or incomplete")

    alerts: list[NormalizedExternalAlert] = []
    matched = False
    for host in response.findall("./HOST_LIST/HOST"):
        host_names = [host.findtext("IP") or "", host.findtext("DNS") or ""]
        host_names.append(host.findtext("./DNS_DATA/FQDN") or "")
        for name in host_names:
            try:
                if normalized_asset_identity(kind, name)[1] == asset:
                    matched = True
                    break
            except ValueError:
                continue
        else:
            continue
        for detection in host.findall("./DETECTION_LIST/DETECTION"):
            unique_id = (detection.findtext("UNIQUE_VULN_ID") or "").strip()
            qid = (detection.findtext("QID") or "").strip()
            if not unique_id.isdigit() or not qid.isdigit():
                raise ValueError("Qualys detection lacks a stable ID or QID")
            try:
                port_text = (detection.findtext("PORT") or "").strip()
                port = int(port_text) if port_text else None
            except ValueError:
                raise ValueError("Qualys detection has an invalid port") from None
            if port is not None and not 0 <= port <= 65535:
                raise ValueError("Qualys detection has an invalid port")
            severity = {
                "1": "low",
                "2": "medium",
                "3": "high",
                "4": "critical",
                "5": "critical",
            }.get((detection.findtext("SEVERITY") or "").strip())
            if severity is None:
                raise ValueError("Qualys detection has an invalid severity")
            source_status = (detection.findtext("STATUS") or "").strip().lower()
            if source_status not in {"new", "active", "reopened", "fixed"}:
                raise ValueError("Qualys detection has an unsupported status")
            dismissed = any(
                (detection.findtext(field) or "").strip() == "1"
                for field in ("IS_IGNORED", "IS_DISABLED")
            )
            status = (
                "dismissed" if dismissed else ("resolved" if source_status == "fixed" else "open")
            )
            detection_type = (detection.findtext("TYPE") or "").strip().lower()
            if detection_type not in {"confirmed", "potential", "information"}:
                detection_type = "unknown"
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, unique_id),
                    category="network",
                    title=f"Qualys QID {qid[:50]}",
                    severity=severity,
                    status=status,
                    resource=asset,
                    source_url=None,
                    cve_ids=valid_cves([node.text or "" for node in detection.iter("CVE_ID")]),
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "qid": qid[:50],
                        "unique_vuln_id": unique_id[:100],
                        "port": port,
                        "protocol": (detection.findtext("PROTOCOL") or "").strip().lower()[:20],
                        "detection_type": detection_type,
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    if not matched:
        raise ValueError("Qualys XML contains no host for the selected asset")
    return alerts


def _gitleaks(
    rows: list[Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    alerts: list[NormalizedExternalAlert] = []
    for row in rows:
        finding = _object(row, "Gitleaks finding")
        rule_id = str(finding.get("RuleID") or "").strip()
        file_path = str(finding.get("File") or "").strip()
        line = finding.get("StartLine")
        if not rule_id or not file_path or not isinstance(line, int) or line < 1:
            raise ValueError("Gitleaks finding lacks stable rule and location identity")
        fingerprint = str(finding.get("Fingerprint") or "").strip()
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(
                    provider, kind, asset, fingerprint or [rule_id, file_path, line]
                ),
                category="secret",
                title="Potential secret exposure",
                severity="high",
                status="open",
                resource=asset,
                source_url=None,
                cve_ids=[],
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "file": file_path[:500],
                    "line": line,
                    "rule_id": rule_id[:200],
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    return alerts


def _nuclei_jsonl(
    data: bytes,
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """Read finding lines, discarding request/response bodies and out-of-scope matches."""
    if kind not in {"domain", "ip", "url"}:
        raise ValueError("Nuclei requires a web or host asset")
    asset_host = urlsplit(asset).hostname if kind == "url" else asset
    alerts: list[NormalizedExternalAlert] = []
    for line_number, raw_line in enumerate(io.BytesIO(data), start=1):
        if not raw_line.strip():
            continue
        try:
            finding = _object(json.loads(raw_line), "Nuclei result")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Nuclei line {line_number} is not valid UTF-8 JSON") from exc
        if finding.get("matcher-status") is False:
            continue
        template_id = str(finding.get("template-id") or "").strip()
        matched_at = str(finding.get("matched-at") or "").strip()
        host_value = str(finding.get("host") or matched_at).strip()
        if not template_id or not matched_at or not host_value:
            raise ValueError(f"Nuclei line {line_number} lacks a stable template and match")
        parsed_host = urlsplit(host_value if "://" in host_value else f"//{host_value}")
        parsed_match = urlsplit(matched_at if "://" in matched_at else f"//{matched_at}")
        if not parsed_host.hostname or not parsed_match.hostname:
            raise ValueError(f"Nuclei line {line_number} has no matched host")
        if (
            parsed_host.hostname.lower() != asset_host
            or parsed_match.hostname.lower() != asset_host
        ):
            continue
        info = _object(finding.get("info"), "Nuclei info")
        title = str(info.get("name") or template_id).strip()
        if not title:
            raise ValueError(f"Nuclei line {line_number} has no title")
        path = parsed_match.path or "/"
        matcher = str(finding.get("matcher-name") or "").strip()
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, kind, asset, template_id, matcher, path),
                category="dast",
                title=redact_text(title[:1000]),
                severity=_severity(info.get("severity")),
                status="open",
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(_CVE_IN_TEXT.findall(template_id[:300])),
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "template_id": template_id[:200],
                    "matcher_name": matcher[:200],
                    "path": redact_text(path[:500]),
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    return alerts


def _cyclonedx(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") not in {
        "1.4",
        "1.5",
        "1.6",
        "1.7",
    }:
        raise ValueError("supported CycloneDX JSON is required")
    components: dict[str, dict[str, Any]] = {}
    component_count = 0
    pending = list(_array(document.get("components", []), "CycloneDX components"))
    metadata = _object(document.get("metadata", {}), "CycloneDX metadata")
    if metadata.get("component") is not None:
        pending.append(metadata["component"])
    while pending:
        component = _object(pending.pop(), "CycloneDX component")
        component_count += 1
        if component_count > 50_000:
            raise ValueError("CycloneDX has too many components")
        reference = str(component.get("bom-ref") or "").strip()
        if reference:
            if reference in components:
                raise ValueError("CycloneDX component references must be unique")
            components[reference] = component
        pending.extend(_array(component.get("components", []), "nested CycloneDX components"))

    alerts: list[NormalizedExternalAlert] = []
    for item in _array(document.get("vulnerabilities", []), "CycloneDX vulnerabilities"):
        vulnerability = _object(item, "CycloneDX vulnerability")
        vuln_id = str(vulnerability.get("id") or "").strip()
        if not vuln_id:
            raise ValueError("CycloneDX vulnerability has no identifier")
        analysis = _object(vulnerability.get("analysis", {}), "CycloneDX analysis")
        analysis_state = analysis.get("state")
        if analysis_state in {
            "not_affected",
            "false_positive",
        }:
            continue
        # An explicit remediation assertion must update an earlier open source
        # observation. Skipping it leaves the canonical finding open forever.
        source_status = (
            "fixed" if analysis_state in {"resolved", "resolved_with_pedigree"} else "open"
        )
        ratings = _array(vulnerability.get("ratings", []), "CycloneDX ratings")
        rating = _object(ratings[0], "CycloneDX rating") if ratings else {}
        for affected in _array(vulnerability.get("affects", []), "CycloneDX affects"):
            reference = str(_object(affected, "CycloneDX affected component").get("ref") or "")
            component = components.get(reference)
            if component is None:
                continue
            package = str(component.get("name") or "").strip()
            if not package:
                continue
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, vuln_id, reference),
                    category="sca",
                    title=f"{vuln_id[:100]} in software component",
                    severity=_severity(rating.get("severity"), score=rating.get("score")),
                    status=source_status,
                    resource=asset,
                    source_url=None,
                    cve_ids=valid_cves([vuln_id]),
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "package": package[:200],
                        "version": str(component.get("version") or "")[:100],
                        "purl": str(component.get("purl") or "")[:500],
                        "bom_ref": reference[:500],
                        "vulnerability_id": vuln_id[:100],
                        "analysis_state": str(analysis_state or "")[:60],
                        "analysis_justification": str(analysis.get("justification") or "")[:100],
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    return alerts


def _spdx(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if document.get("spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
        raise ValueError("supported SPDX JSON is required")
    alerts: list[NormalizedExternalAlert] = []
    for item in _array(document.get("packages", []), "SPDX packages"):
        package = _object(item, "SPDX package")
        package_id = str(package.get("SPDXID") or "").strip()
        name = str(package.get("name") or "").strip()
        if not package_id or not name:
            raise ValueError("SPDX package lacks stable identity")
        cves: set[str] = set()
        for item_ref in _array(package.get("externalRefs", []), "SPDX external references"):
            reference = _object(item_ref, "SPDX external reference")
            if (
                reference.get("referenceCategory") == "SECURITY"
                and reference.get("referenceType") == "advisory"
            ):
                locator = str(reference.get("referenceLocator") or "")
                cves.update(valid_cves(_CVE_IN_TEXT.findall(locator[:2048])))
        for cve in sorted(cves):
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, package_id, cve),
                    category="sca",
                    title=f"{cve} in software component",
                    severity="info",
                    status="open",
                    resource=asset,
                    source_url=None,
                    cve_ids=[cve],
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "package": name[:200],
                        "version": str(package.get("versionInfo") or "")[:100],
                        "spdx_id": package_id[:200],
                        "vulnerability_id": cve,
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    return alerts


def _generic(
    rows: Iterable[Any],
    *,
    provider: str,
    kind: str,
    asset: str,
    field_mapping: Mapping[str, str] | None,
) -> list[NormalizedExternalAlert]:
    if (
        not isinstance(field_mapping, dict)
        or not {"id", "title"}.issubset(field_mapping)
        or set(field_mapping) - _GENERIC_FIELDS
        or any(
            not isinstance(path, str) or not _FIELD_PATH.fullmatch(path)
            for path in field_mapping.values()
        )
    ):
        raise ValueError("generic import requires valid id and title field mappings")

    def mapped(row: dict[str, Any], field: str) -> object:
        path = field_mapping.get(field)
        if path is None:
            return None
        value: object = row
        for part in path.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    alerts: list[NormalizedExternalAlert] = []
    for item in rows:
        row = _object(item, "generic finding")
        record_id = str(mapped(row, "id") or "").strip()
        title = str(mapped(row, "title") or "").strip()
        if not record_id or not title or len(record_id) > 5000:
            raise ValueError("generic finding lacks stable id or title")
        raw_status = str(mapped(row, "status") or "open").strip().lower()
        status = {
            "open": "open",
            "new": "open",
            "active": "open",
            "resolved": "resolved",
            "closed": "resolved",
            "fixed": "fixed",
            "dismissed": "dismissed",
            "false_positive": "dismissed",
        }.get(raw_status)
        if status is None:
            raise ValueError("generic finding has unsupported status")
        cve_value = mapped(row, "cve")
        cve_text = (
            " ".join(map(str, cve_value)) if isinstance(cve_value, list) else str(cve_value or "")
        )
        evidence: dict[str, Any] = {"asset_type": kind, "asset_value": asset}
        for field in ("package", "location"):
            value = mapped(row, field)
            if value is not None:
                evidence[field] = redact_text(str(value)[:500])
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, kind, asset, record_id),
                category="generic",
                title=redact_text(title[:1000]),
                severity=_severity(mapped(row, "severity")),
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(_CVE_IN_TEXT.findall(cve_text[:5000])),
                evidence=evidence,
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    return alerts


def _rapid7_csv(
    rows: csv.DictReader[str],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if kind not in {"ip", "domain"}:
        raise ValueError("Rapid7 CSV import requires an IP or domain asset")
    required = {
        "Vulnerability ID",
        "Vulnerability Title",
        "Vulnerability Test Result Code",
        "Asset IP Address" if kind == "ip" else "Asset Names",
    }
    if not required.issubset(set(rows.fieldnames or ())):
        raise ValueError("Rapid7 CSV is missing required columns")
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for row_number, row in enumerate(rows, 1):
        if row_number > 100_000:
            raise ValueError("Rapid7 CSV has too many rows")
        if None in row or any(value is None for value in row.values()):
            raise ValueError("Rapid7 CSV has a malformed row")
        if kind == "ip":
            matches = row["Asset IP Address"].strip() == asset
        else:
            matches = asset in {name.strip().lower() for name in row["Asset Names"].split(",")}
        if not matches:
            continue
        matched_asset = True
        code = row["Vulnerability Test Result Code"].strip().lower()
        if code in _RAPID7_IGNORED:
            continue
        if code not in _RAPID7_POSITIVE | _RAPID7_NEGATIVE:
            raise ValueError("Rapid7 CSV has an unsupported result code")
        vulnerability_id = row["Vulnerability ID"].strip()
        title = row["Vulnerability Title"].strip()
        if not vulnerability_id or len(vulnerability_id) > 200 or not title or len(title) > 1000:
            raise ValueError("Rapid7 CSV finding lacks a stable identity or title")
        port_text = (row.get("Service Port") or "").strip()
        if port_text and (not port_text.isdecimal() or int(port_text) > 65535):
            raise ValueError("Rapid7 CSV has an invalid service port")
        port = int(port_text) if port_text else None
        protocol = (row.get("Service Protocol") or "").strip().lower()
        if protocol and protocol not in {"tcp", "udp"}:
            raise ValueError("Rapid7 CSV has an invalid service protocol")
        severity_level = (row.get("Vulnerability Severity Level") or "").strip()
        cvss = (row.get("Vulnerability CVSSv3 Score") or "").strip() or (
            row.get("Vulnerability CVSS Score") or ""
        ).strip()
        if cvss:
            severity = _severity(None, score=cvss)
        elif severity_level:
            try:
                level = int(severity_level)
            except ValueError as exc:
                raise ValueError("Rapid7 CSV has an invalid severity level") from exc
            if not 1 <= level <= 10:
                raise ValueError("Rapid7 CSV has an invalid severity level")
            severity = "critical" if level >= 8 else "high" if level >= 4 else "medium"
        else:
            severity = "info"
        evidence: dict[str, Any] = {
            "asset_type": kind,
            "asset_value": asset,
            "vulnerability_id": redact_text(vulnerability_id),
            "result_code": code,
        }
        if port is not None:
            evidence["port"] = port
        if protocol:
            evidence["protocol"] = protocol
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, kind, asset, vulnerability_id, port, protocol),
                category="network",
                title=redact_text(title),
                severity=severity,
                status="open" if code in _RAPID7_POSITIVE else "fixed",
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(
                    _CVE_IN_TEXT.findall((row.get("Vulnerability CVE IDs") or "")[:5000])
                ),
                evidence=evidence,
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if not matched_asset:
        raise ValueError("Rapid7 CSV has no results for the selected asset")
    return alerts


def _aws_inspector_csv(
    rows: csv.DictReader[str],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    match = re.fullmatch(r"(\d{12}):([^\x00-\x1f]+)", asset) if kind == "cloud" else None
    if match is None:
        raise ValueError("AWS Inspector CSV requires an account-qualified cloud asset")
    account_id, resource_id = match.groups()
    required = {"AWS Account Id", "Resource ID", "Finding ARN", "Title", "Severity", "Status"}
    if not required.issubset(set(rows.fieldnames or ())):
        raise ValueError("AWS Inspector CSV is missing required columns")
    statuses = {"ACTIVE": "open", "CLOSED": "fixed", "SUPPRESSED": "dismissed"}
    severities = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "info",
        "UNTRIAGED": "info",
    }
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for row_number, row in enumerate(rows, 1):
        if row_number > 100_000:
            raise ValueError("AWS Inspector CSV has too many rows")
        if None in row or any(value is None for value in row.values()):
            raise ValueError("AWS Inspector CSV has a malformed row")
        if row["AWS Account Id"].strip() != account_id or row["Resource ID"].strip() != resource_id:
            continue
        matched_asset = True
        finding_arn = row["Finding ARN"].strip()
        title = row["Title"].strip()
        severity = severities.get(row["Severity"].strip().upper())
        status = statuses.get(row["Status"].strip().upper())
        if (
            not finding_arn
            or len(finding_arn) > 200
            or not title
            or len(title) > 1000
            or severity is None
            or status is None
        ):
            raise ValueError("AWS Inspector CSV has an invalid finding")
        vulnerability_id = (row.get("Vulnerability Id") or "").strip()
        evidence: dict[str, Any] = {
            "asset_type": kind,
            "asset_value": asset,
            "aws_account_id": account_id,
            "resource_id": resource_id,
        }
        if vulnerability_id:
            evidence["vulnerability_id"] = redact_text(vulnerability_id[:200])
        exploit = (row.get("Exploit Available") or "").strip().upper()
        if exploit in {"YES", "NO"}:
            evidence["exploit_available"] = exploit == "YES"
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, account_id, finding_arn),
                category="cloud",
                title=redact_text(title),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(_CVE_IN_TEXT.findall(vulnerability_id[:5000])),
                evidence=evidence,
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if not matched_asset:
        raise ValueError("AWS Inspector CSV has no results for the selected asset")
    return alerts


def _gcp_scc_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if kind != "cloud" or not asset.startswith("//"):
        raise ValueError("GCP SCC import requires a full cloud resource name")
    if document.get("nextPageToken"):
        raise ValueError("GCP SCC export is incomplete; include all pages")
    rows = _array(document.get("listFindingsResults"), "GCP SCC findings")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    severities = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "SEVERITY_UNSPECIFIED": "info",
    }
    states = {"ACTIVE": "open", "INACTIVE": "fixed"}
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        finding = _object(_object(item, "GCP SCC result").get("finding"), "GCP SCC finding")
        if finding.get("resourceName") != asset:
            continue
        matched_asset = True
        name = finding.get("name")
        category = finding.get("category")
        severity = severities.get(finding.get("severity"))
        status = states.get(finding.get("state"))
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 500
            or not isinstance(category, str)
            or not category
            or len(category) > 200
            or severity is None
            or status is None
        ):
            raise ValueError("GCP SCC finding lacks valid identity or state")
        vulnerability = finding.get("vulnerability") or {}
        if not isinstance(vulnerability, dict):
            raise ValueError("GCP SCC vulnerability must be an object")
        cve = vulnerability.get("cve") or {}
        if not isinstance(cve, dict):
            raise ValueError("GCP SCC CVE must be an object")
        cve_id = cve.get("id")
        evidence: dict[str, Any] = {
            "asset_type": kind,
            "asset_value": asset,
            "category": redact_text(category),
        }
        if isinstance(cve.get("observedInTheWild"), bool):
            evidence["observed_in_the_wild"] = cve["observedInTheWild"]
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, name),
                category="cloud",
                title=redact_text(category.replace("_", " ")),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=valid_cves([cve_id]) if isinstance(cve_id, str) else [],
                evidence=evidence,
                raw_payload={},
            )
        )
    if not matched_asset:
        raise ValueError("GCP SCC export has no results for the selected asset")
    return alerts


def _azure_defender_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    if (
        kind != "cloud"
        or not asset.casefold().startswith("/subscriptions/")
        or "/providers/" not in asset.casefold()
    ):
        raise ValueError("Azure Defender import requires a full Azure resource ID")
    if document.get("nextLink"):
        raise ValueError("Azure Defender export is incomplete; include all pages")
    rows = _array(document.get("value"), "Azure Defender assessments")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    severities = {"High": "high", "Medium": "medium", "Low": "low"}
    statuses = {"Unhealthy": "open", "Healthy": "fixed"}
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    assessment_prefix = f"{asset}/providers/Microsoft.Security/assessments/".casefold()
    for item in rows:
        assessment = _object(item, "Azure Defender assessment")
        properties = _object(assessment.get("properties"), "Azure Defender properties")
        details = _object(properties.get("resourceDetails"), "Azure Defender resource")
        resource_id = details.get("id")
        if (
            details.get("source") != "Azure"
            or not isinstance(resource_id, str)
            or resource_id.casefold() != asset.casefold()
        ):
            continue
        matched_asset = True
        assessment_id = assessment.get("id")
        title = properties.get("displayName")
        code = _object(properties.get("status"), "Azure Defender status").get("code")
        metadata = properties.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("Azure Defender metadata must be an object")
        severity_raw = metadata.get("severity")
        severity = severities.get(severity_raw) if severity_raw is not None else "info"
        if (
            not isinstance(assessment_id, str)
            or not assessment_id.casefold().startswith(assessment_prefix)
            or len(assessment_id) > 2000
            or not isinstance(title, str)
            or not title.strip()
            or len(title) > 1000
            or severity is None
        ):
            raise ValueError("Azure Defender assessment lacks valid identity or severity")
        if code == "NotApplicable":
            continue
        status = statuses.get(code)
        if status is None:
            raise ValueError("Azure Defender assessment has an invalid status")
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, assessment_id.casefold()),
                category="cloud",
                title=redact_text(title.strip()),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=[],
                evidence={"asset_type": kind, "asset_value": asset},
                raw_payload={},
            )
        )
    if not matched_asset:
        raise ValueError("Azure Defender export has no results for the selected asset")
    return alerts


def _prowler_ocsf(
    rows: list[Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    account_match = (
        re.fullmatch(
            r"(aws|azure|gcp):([A-Za-z0-9][A-Za-z0-9._-]{1,127})",
            asset,
            re.I,
        )
        if kind == "cloud_account"
        else None
    )
    if account_match is None:
        raise ValueError("Prowler OCSF import requires an account-scoped cloud asset")
    selected_provider, selected_account = account_match.groups()
    selected_provider = selected_provider.lower()
    if (
        (selected_provider == "aws" and not re.fullmatch(r"\d{12}", selected_account))
        or (
            selected_provider == "azure"
            and not re.fullmatch(
                r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", selected_account, re.I
            )
        )
        or (
            selected_provider == "gcp"
            and not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", selected_account)
        )
    ):
        raise ValueError("Prowler OCSF import requires an account-scoped cloud asset")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")

    alerts: list[NormalizedExternalAlert] = []
    matched_account = False
    statuses = {"FAIL": "open", "PASS": "fixed"}
    for item in rows:
        finding = _object(item, "Prowler OCSF finding")
        cloud = _object(finding.get("cloud"), "Prowler cloud")
        account = _object(cloud.get("account"), "Prowler cloud account")
        cloud_provider = cloud.get("provider")
        account_uid = account.get("uid")
        if not isinstance(cloud_provider, str) or not isinstance(account_uid, str):
            raise ValueError("Prowler OCSF finding lacks cloud identity")
        if (cloud_provider.lower(), account_uid.lower()) != (
            selected_provider,
            selected_account.lower(),
        ):
            continue
        matched_account = True
        status_code = finding.get("status_code")
        if status_code == "MANUAL":
            continue
        status = statuses.get(status_code)
        if status is None:
            raise ValueError("Prowler OCSF finding has invalid status")
        info = _object(finding.get("finding_info"), "Prowler finding info")
        metadata = _object(finding.get("metadata"), "Prowler metadata")
        uid, title, rule_id = info.get("uid"), info.get("title"), metadata.get("event_code")
        if any(
            not isinstance(value, str) or not value.strip() or len(value) > limit
            for value, limit in ((uid, 1000), (title, 1000), (rule_id, 200))
        ):
            raise ValueError("Prowler OCSF finding lacks stable identity")
        resources = _array(finding.get("resources"), "Prowler resources")
        if not resources or len(resources) > 20:
            raise ValueError("Prowler OCSF finding needs bounded resources")
        region = cloud.get("region")
        for raw_resource in resources:
            resource = _object(raw_resource, "Prowler resource")
            resource_uid = resource.get("uid")
            if (
                not isinstance(resource_uid, str)
                or not resource_uid.strip()
                or len(resource_uid) > 2000
                or any(ord(char) < 32 for char in resource_uid)
                or any(char in resource_uid for char in "?#")
            ):
                raise ValueError("Prowler OCSF resource lacks a safe identity")
            if not resource_within_account(selected_provider, selected_account, resource_uid):
                raise ValueError("Prowler OCSF resource is outside selected account")
            evidence: dict[str, Any] = {
                "asset_type": "cloud",
                "asset_value": resource_uid,
                "account_uid": selected_account,
                "cloud_provider": selected_provider,
                "rule_id": rule_id,
            }
            if isinstance(region, str) and re.fullmatch(r"[A-Za-z0-9-]{1,64}", region):
                evidence["region"] = region
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(
                        provider, selected_provider, selected_account, uid, resource_uid
                    ),
                    category="cloud",
                    title=redact_text(title.strip()),
                    severity=_severity(finding.get("severity")),
                    status=status,
                    resource=resource_uid,
                    source_url=None,
                    cve_ids=valid_cves(_CVE_IN_TEXT.findall(rule_id)),
                    evidence=evidence,
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    if not matched_account:
        raise ValueError("Prowler OCSF export has no results for the selected account")
    return alerts


def _hackerone_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    links = document.get("links") or {}
    if not isinstance(links, dict):
        raise ValueError("HackerOne links must be an object")
    if links.get("next"):
        raise ValueError("HackerOne export is incomplete; include all pages")
    data = document.get("data")
    rows = [data] if isinstance(data, dict) else _array(data, "HackerOne reports")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    statuses = {
        "new": "open",
        "pending-program-review": "open",
        "triaged": "open",
        "needs-more-info": "open",
        "retesting": "open",
        "resolved": "fixed",
        "not-applicable": "dismissed",
        "informative": "dismissed",
        "duplicate": "dismissed",
        "spam": "dismissed",
    }
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        report = _object(item, "HackerOne report")
        if report.get("type") != "report":
            raise ValueError("HackerOne export contains a non-report object")
        relationships = _object(report.get("relationships"), "HackerOne relationships")
        scope = _object(
            _object(relationships.get("structured_scope"), "HackerOne scope").get("data"),
            "HackerOne scope data",
        )
        scope_attributes = _object(scope.get("attributes"), "HackerOne scope attributes")
        identifier = scope_attributes.get("asset_identifier")
        if not isinstance(identifier, str):
            continue
        try:
            scope_kind, scope_asset = normalized_asset_identity(kind, identifier)
        except ValueError:
            continue
        if (scope_kind, scope_asset) != (kind, asset):
            continue
        matched_asset = True
        attributes = _object(report.get("attributes"), "HackerOne report attributes")
        report_id = report.get("id")
        title = attributes.get("title")
        status = statuses.get(attributes.get("state"))
        if (
            not isinstance(report_id, str)
            or not report_id
            or len(report_id) > 300
            or not isinstance(title, str)
            or not title.strip()
            or len(title) > 1000
            or status is None
        ):
            raise ValueError("HackerOne report lacks valid identity or state")
        severity = "info"
        severity_relation = relationships.get("severity")
        if isinstance(severity_relation, dict) and isinstance(severity_relation.get("data"), dict):
            rating = _object(severity_relation["data"].get("attributes"), "HackerOne severity").get(
                "rating"
            )
            if rating not in {"none", "low", "medium", "high", "critical"}:
                raise ValueError("HackerOne report has an invalid severity")
            severity = "info" if rating == "none" else rating
        cves = attributes.get("cve_ids") or []
        if not isinstance(cves, list) or any(not isinstance(cve, str) for cve in cves):
            raise ValueError("HackerOne CVE IDs must be a list of strings")
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, report_id),
                category="bug_bounty",
                title=redact_text(title.strip()),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(cves[:100]),
                evidence={"asset_type": kind, "asset_value": asset},
                raw_payload={},
            )
        )
    if not matched_asset:
        raise ValueError("HackerOne export has no results for the selected asset")
    return alerts


def _wiz_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """Wiz Issues export (JSON) — single-page, resource-scoped.

    Wiz exports a ``{issues: [...]}`` envelope from its GraphQL API or the Issues
    CSV-to-JSON converter. Each issue carries a ``sourceRule`` with a control ID and
    a ``projects``/``entitySnapshot`` with the target resource. We accept only issues
    whose ``entitySnapshot.externalId`` or ``projects[*].name`` matches the selected
    asset so a multi-tenant Wiz export cannot pollute a single-tenant scope.
    """
    if kind not in {"cloud", "cloud_account", "domain", "ip", "url"}:
        raise ValueError("Wiz import requires a cloud, network, or web asset")
    rows_raw = document.get("issues") or document.get("data")
    if rows_raw is None:
        raise ValueError("Wiz JSON has no issues array")
    rows = _array(rows_raw, "Wiz issues")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    severities = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "info",
    }
    statuses = {
        "OPEN": "open",
        "IN_PROGRESS": "open",
        "RESOLVED": "fixed",
        "REJECTED": "dismissed",
    }
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        issue = _object(item, "Wiz issue")
        issue_id = issue.get("id")
        snapshot = issue.get("entitySnapshot") or {}
        if not isinstance(snapshot, dict):
            raise ValueError("Wiz issue entitySnapshot must be an object")
        external_id_raw = str(snapshot.get("externalId") or "").strip()
        # Accept any resource whose external id contains the selected asset value
        # (Wiz external ids for cloud resources are ARNs, Azure IDs, etc.).
        if kind in {"cloud", "cloud_account"}:
            in_scope = asset.lower() in external_id_raw.lower() or external_id_raw.lower() == asset.lower()
        else:
            in_scope = external_id_raw.lower() == asset.lower()
        if not in_scope:
            continue
        matched_asset = True
        severity_raw = issue.get("severity")
        severity = severities.get(severity_raw)
        status_raw = issue.get("status")
        status = statuses.get(status_raw)
        source_rule = _object(issue.get("sourceRule") or {}, "Wiz sourceRule")
        rule_id = str(source_rule.get("id") or "").strip()
        title_raw = str(issue.get("name") or source_rule.get("name") or rule_id).strip()
        if (
            not isinstance(issue_id, str)
            or not issue_id.strip()
            or len(issue_id) > 300
            or not title_raw
            or len(title_raw) > 1000
            or severity is None
            or status is None
        ):
            raise ValueError("Wiz issue lacks valid identity, severity, or status")
        cve_ids = valid_cves(_CVE_IN_TEXT.findall(title_raw + " " + rule_id))
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, issue_id.strip()),
                category="cloud",
                title=redact_text(title_raw),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=cve_ids,
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "rule_id": rule_id[:200],
                    "external_resource_id": external_id_raw[:500],
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if not matched_asset:
        raise ValueError("Wiz JSON has no issues for the selected asset")
    return alerts


def _prisma_cloud_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """Prisma Cloud Alerts export (JSON) — paged-aware, resource-scoped.

    Prisma exports ``{items: [...]}`` from its Alerts v2 API. Each alert carries a
    ``resource.rrn`` (Prisma resource name) and ``policy.name``/``severity``. We
    require a single page (no ``nextPageToken``) so callers cannot silently import
    a partial result.
    """
    if kind not in {"cloud", "cloud_account"}:
        raise ValueError("Prisma Cloud import requires a cloud asset")
    if document.get("nextPageToken"):
        raise ValueError("Prisma Cloud export is incomplete; include all pages")
    rows = _array(document.get("items") or document.get("data", []), "Prisma Cloud alerts")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    severities = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    }
    statuses = {
        "open": "open",
        "resolved": "fixed",
        "dismissed": "dismissed",
        "snoozed": "dismissed",
    }
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        alert = _object(item, "Prisma Cloud alert")
        alert_id = alert.get("id")
        resource = _object(alert.get("resource") or {}, "Prisma resource")
        rrn = str(resource.get("rrn") or resource.get("id") or "").strip()
        account_id = str(resource.get("accountId") or "").strip()
        # Match on account ID embedded in the selected asset or on the full RRN
        in_scope = (
            (account_id and account_id in asset)
            or rrn.lower() == asset.lower()
            or asset.lower() in rrn.lower()
        )
        if not in_scope:
            continue
        matched_asset = True
        policy = _object(alert.get("policy") or {}, "Prisma policy")
        policy_id = str(policy.get("policyId") or "").strip()
        title_raw = str(policy.get("name") or policy_id).strip()
        severity = severities.get(str(policy.get("severity") or "").lower())
        status = statuses.get(str(alert.get("status") or "").lower())
        if (
            not isinstance(alert_id, str)
            or not alert_id.strip()
            or len(alert_id) > 300
            or not title_raw
            or len(title_raw) > 1000
            or severity is None
            or status is None
        ):
            raise ValueError("Prisma Cloud alert lacks valid identity, severity, or status")
        cve_ids = valid_cves(_CVE_IN_TEXT.findall(title_raw + " " + policy_id))
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, alert_id.strip()),
                category="cloud",
                title=redact_text(title_raw),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=cve_ids,
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "policy_id": policy_id[:200],
                    "rrn": rrn[:500],
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if not matched_asset:
        raise ValueError("Prisma Cloud JSON has no alerts for the selected asset")
    return alerts


def _checkmarx_xml(
    data: bytes,
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """Checkmarx SAST XML report (CxXML format).

    Checkmarx One / CxSAST exports ``<CxXMLResults>`` with ``<Query>`` groups each
    containing ``<Result>`` elements. We extract path-level identity (file + line) to
    make stable fingerprints. Checkmarx embeds target info in ``<CxXMLResults
    ProjectName="...">``; we accept any export whose project or target matches the
    selected asset (checked case-insensitively) or skip the check when the asset is
    a repo (the export is always scoped to one project).
    """
    if kind not in {"repo", "application", "domain", "url"}:
        raise ValueError("Checkmarx XML import requires a repo, application, or web asset")
    try:
        root = SafeET.fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("Checkmarx XML is malformed or contains unsafe XML") from exc
    if root.tag != "CxXMLResults":
        raise ValueError("Checkmarx XML must have a CxXMLResults root")
    project_name = (root.get("ProjectName") or "").strip()
    # Loose match: accept if the project name contains the asset value or vice versa
    if project_name and kind in {"repo", "application"}:
        asset_lower = asset.lower().split("/")[-1]  # bare repo name
        if asset_lower not in project_name.lower() and project_name.lower() not in asset.lower():
            raise ValueError("Checkmarx XML project does not match the selected asset")
    alerts: list[NormalizedExternalAlert] = []
    for query in root.findall("Query"):
        query_id = (query.get("id") or "").strip()
        query_name = (query.get("name") or query_id).strip()
        if not query_id or not query_name:
            raise ValueError("Checkmarx query lacks a stable ID or name")
        severity_raw = (query.get("Severity") or "").strip()
        severity = _severity(severity_raw)
        for result in query.findall("Result"):
            result_state = (result.get("state") or "0").strip()
            # 0=TO_VERIFY, 1=NOT_EXPLOITABLE, 2=CONFIRMED, 3=URGENT, 4=PROPOSED_NOT_EXPLOITABLE
            status = "dismissed" if result_state in {"1", "4"} else "open"
            path = result.find("Path")
            if path is None:
                continue
            path_id = (path.get("PathId") or "").strip()
            first_node = path.find("PathNode")
            file_name = ""
            line = None
            if first_node is not None:
                file_name = (first_node.findtext("FileName") or "").strip()
                try:
                    line = int(first_node.findtext("Line") or "")
                except ValueError:
                    line = None
            if not path_id or not file_name:
                raise ValueError("Checkmarx result lacks stable path identity")
            alerts.append(
                NormalizedExternalAlert(
                    external_id=_stable_id(provider, kind, asset, query_id, path_id),
                    category="sast",
                    title=redact_text(query_name[:1000]),
                    severity=severity,
                    status=status,
                    resource=asset,
                    source_url=None,
                    cve_ids=valid_cves(_CVE_IN_TEXT.findall(query_name)),
                    evidence={
                        "asset_type": kind,
                        "asset_value": asset,
                        "query_id": query_id[:100],
                        "file": file_name[:500],
                        "line": line,
                    },
                    raw_payload={},
                )
            )
            if len(alerts) > MAX_IMPORT_FINDINGS:
                raise ValueError("scanner export has too many findings")
    return alerts


def _fortify_fvdl(
    data: bytes,
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """Fortify Static Code Analyzer FVDL/FPR XML report.

    Fortify FPR archives are ZIP files; the FVDL (findings) document inside is named
    ``audit.fvdl``. Callers that have already extracted it may pass the raw XML bytes
    directly. We detect ZIP by magic bytes and extract ``audit.fvdl`` automatically.
    The FVDL schema uses ``<FVDL>`` as root with ``<Vulnerabilities>`` children.
    """
    import zipfile

    if kind not in {"repo", "application"}:
        raise ValueError("Fortify FPR/FVDL import requires a repo or application asset")
    # Detect and unpack FPR (ZIP) automatically
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if "audit.fvdl" not in zf.namelist():
                    raise ValueError("Fortify FPR archive does not contain audit.fvdl")
                inner = zf.read("audit.fvdl")
        except zipfile.BadZipFile as exc:
            raise ValueError("Fortify FPR is not a valid ZIP archive") from exc
        if len(inner) > MAX_IMPORT_BYTES:
            raise ValueError("Fortify FVDL inside FPR exceeds the size limit")
        data = inner
    try:
        root = SafeET.fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("Fortify FVDL is malformed or contains unsafe XML") from exc
    # FVDL root may be namespaced; strip namespace for simpler matching
    tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    if tag != "FVDL":
        raise ValueError("Fortify FVDL must have an FVDL root element")

    def ns(element: Any, local: str) -> Any:
        """Find a child stripping any namespace prefix."""
        for child in element:
            child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child_tag == local:
                return child
        return None

    def all_ns(element: Any, local: str) -> list[Any]:
        return [
            child
            for child in element
            if (child.tag.split("}")[-1] if "}" in child.tag else child.tag) == local
        ]

    vulnerabilities_container = ns(root, "Vulnerabilities")
    if vulnerabilities_container is None:
        return []
    alerts: list[NormalizedExternalAlert] = []
    for vuln in all_ns(vulnerabilities_container, "Vulnerability"):
        class_info = ns(vuln, "ClassInfo")
        analysis_info = ns(vuln, "AnalysisInfo")
        if class_info is None or analysis_info is None:
            raise ValueError("Fortify vulnerability lacks ClassInfo or AnalysisInfo")
        vuln_id_el = ns(class_info, "ClassID")
        vuln_id = (vuln_id_el.text or "").strip() if vuln_id_el is not None else ""
        kingdom_el = ns(class_info, "Kingdom")
        kingdom = (kingdom_el.text or "").strip() if kingdom_el is not None else ""
        type_el = ns(class_info, "Type")
        vuln_type = (type_el.text or "").strip() if type_el is not None else ""
        subtype_el = ns(class_info, "Subtype")
        subtype = (subtype_el.text or "").strip() if subtype_el is not None else ""
        title_raw = ": ".join(filter(None, [kingdom, vuln_type, subtype])) or vuln_id
        if not vuln_id or not title_raw:
            raise ValueError("Fortify vulnerability lacks stable identity")
        severity_raw_el = ns(class_info, "DefaultSeverity")
        severity_raw = (severity_raw_el.text or "").strip() if severity_raw_el is not None else ""
        try:
            severity_float = float(severity_raw)
        except ValueError:
            severity_float = None
        severity = _severity(None, score=severity_float * 2.5 if severity_float is not None else None)
        unified = ns(analysis_info, "Unified")
        trace = ns(unified, "Trace") if unified is not None else None
        entry = ns(trace, "Entry") if trace is not None else None
        node = ns(entry, "Node") if entry is not None else None
        location = ns(node, "SourceLocation") if node is not None else None
        file_path = ""
        line = None
        if location is not None:
            file_path = (location.get("path") or "").strip()
            try:
                line = int(location.get("line") or "")
            except ValueError:
                line = None
        if not file_path:
            raise ValueError("Fortify vulnerability lacks source location")
        instance_el = ns(vuln, "InstanceInfo")
        instance_id = ""
        if instance_el is not None:
            iid_el = ns(instance_el, "InstanceID")
            instance_id = (iid_el.text or "").strip() if iid_el is not None else ""
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(
                    provider, kind, asset, vuln_id, instance_id or [file_path, line]
                ),
                category="sast",
                title=redact_text(title_raw[:1000]),
                severity=severity,
                status="open",
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(_CVE_IN_TEXT.findall(title_raw)),
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "vuln_id": vuln_id[:100],
                    "file": file_path[:500],
                    "line": line,
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    return alerts


def _sonarqube_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """SonarQube Issues API JSON export — single page, project-scoped.

    The SonarQube Issues search API returns ``{issues: [...], components: [...], ...}``.
    We check ``paging.total <= issues.length`` to ensure completeness and bind to the
    selected asset via the component ``key`` field.
    """
    if kind not in {"repo", "application"}:
        raise ValueError("SonarQube JSON import requires a repo or application asset")
    paging = document.get("paging") or {}
    if isinstance(paging, dict):
        total = paging.get("total") or 0
        page_index = paging.get("pageIndex") or 1
        page_size = paging.get("pageSize") or 500
        if total > page_size * page_index:
            raise ValueError("SonarQube JSON export is incomplete; include all pages")
    rows = _array(document.get("issues"), "SonarQube issues")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    components_list = _array(document.get("components", []), "SonarQube components")
    components: dict[str, str] = {}
    for comp in components_list:
        c = _object(comp, "SonarQube component")
        key = str(c.get("key") or "").strip()
        path = str(c.get("path") or c.get("longName") or "").strip()
        if key:
            components[key] = path
    severities = {
        "BLOCKER": "critical",
        "CRITICAL": "high",
        "MAJOR": "medium",
        "MINOR": "low",
        "INFO": "info",
    }
    statuses = {
        "OPEN": "open",
        "CONFIRMED": "open",
        "REOPENED": "open",
        "RESOLVED": "fixed",
        "CLOSED": "fixed",
        "WONTFIX": "dismissed",
        "FALSE-POSITIVE": "dismissed",
    }
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        issue = _object(item, "SonarQube issue")
        issue_key = str(issue.get("key") or "").strip()
        component = str(issue.get("component") or "").strip()
        # The component key is "projectKey:path/to/file"; the root project key
        # is the part before the first colon.
        project_key = component.split(":")[0] if ":" in component else component
        asset_tail = asset.split("/")[-1]  # bare project name from repo path
        in_scope = (
            project_key.lower() == asset.lower()
            or project_key.lower() == asset_tail.lower()
            or asset.lower().endswith("/" + project_key.lower())
        )
        if not in_scope:
            continue
        matched_asset = True
        rule = str(issue.get("rule") or "").strip()
        message = str(issue.get("message") or rule).strip()
        severity_raw = str(issue.get("severity") or "").strip()
        severity = severities.get(severity_raw, "info")
        status_raw = str(issue.get("status") or "").strip()
        resolution_raw = str(issue.get("resolution") or "").strip()
        status = statuses.get(resolution_raw) or statuses.get(status_raw, "open")
        if not issue_key or len(issue_key) > 300 or not message or len(message) > 1000:
            raise ValueError("SonarQube issue lacks valid identity or message")
        text_range = _object(issue.get("textRange") or {}, "SonarQube textRange")
        line = text_range.get("startLine")
        file_path = components.get(component, component)
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, issue_key),
                category="sast",
                title=redact_text(message[:1000]),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=valid_cves(_CVE_IN_TEXT.findall(rule)),
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "rule": rule[:200],
                    "file": redact_text(file_path[:500]),
                    "line": line if isinstance(line, int) else None,
                    "project": project_key[:200],
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if not matched_asset:
        raise ValueError("SonarQube JSON has no issues for the selected asset")
    return alerts


def _defectdojo_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """DefectDojo Findings export (paginated JSON API format).

    DefectDojo's ``/api/v2/findings/`` endpoint returns ``{count, next, results: [...]}``.
    We require a complete (single-page or merged) export: ``next`` must be null. Each
    result maps to a canonical NormalizedExternalAlert so it flows through the same
    intake pipeline as every other provider.
    """
    if document.get("next"):
        raise ValueError("DefectDojo export is incomplete; include all pages")
    rows = _array(document.get("results"), "DefectDojo findings")
    if len(rows) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    severities = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "info",
        "Informational": "info",
    }
    statuses_map = {
        "Active": "open",
        "Verified": "open",
        "Duplicate": "dismissed",
        "False Positive": "dismissed",
        "Out of Scope": "dismissed",
        "Mitigated": "fixed",
        "Risk Accepted": "dismissed",
    }
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        finding = _object(item, "DefectDojo finding")
        finding_id = finding.get("id")
        title_raw = str(finding.get("title") or "").strip()
        severity_raw = str(finding.get("severity") or "").strip()
        severity = severities.get(severity_raw, "info")
        # DefectDojo uses boolean active/verified/duplicate/false_p/mitigated flags
        is_dup = finding.get("duplicate") is True
        is_fp = finding.get("false_p") is True
        is_mitigated = finding.get("mitigated") is not None or finding.get("is_mitigated") is True
        is_out_of_scope = finding.get("out_of_scope") is True
        is_risk_accepted = finding.get("risk_accepted") is True
        is_active = finding.get("active") is True
        if is_dup or is_fp or is_out_of_scope or is_risk_accepted:
            status = "dismissed"
        elif is_mitigated:
            status = "fixed"
        elif is_active:
            status = "open"
        else:
            status = statuses_map.get(finding.get("status") or "", "open")
        endpoint_str = ""
        endpoints = finding.get("endpoints") or []
        if isinstance(endpoints, list) and endpoints:
            ep = endpoints[0]
            if isinstance(ep, dict):
                endpoint_str = str(ep.get("host") or ep.get("url") or "").strip()
            elif isinstance(ep, str):
                endpoint_str = ep.strip()
        # Accept finding if its endpoint matches the selected asset
        if endpoint_str:
            try:
                ep_kind, ep_value = normalized_asset_identity("domain", endpoint_str) if "." in endpoint_str else normalized_asset_identity("ip", endpoint_str)
                in_scope = (ep_kind, ep_value) == (kind, asset)
            except ValueError:
                in_scope = asset.lower() in endpoint_str.lower()
        else:
            # No endpoint information; include finding without asset filter
            in_scope = True
        if not in_scope:
            continue
        matched_asset = True
        if not isinstance(finding_id, int) or not title_raw or len(title_raw) > 1000:
            raise ValueError("DefectDojo finding lacks valid identity or title")
        cve_ids_raw = finding.get("cve") or finding.get("cve_list") or []
        if isinstance(cve_ids_raw, str):
            cve_ids_raw = [cve_ids_raw]
        cve_ids_raw = _array(cve_ids_raw, "DefectDojo CVE list") if not isinstance(cve_ids_raw, list) else cve_ids_raw
        cve_ids = valid_cves([str(c) for c in cve_ids_raw if c])
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, str(finding_id)),
                category="sast" if finding.get("scanner_confidence") or finding.get("sast_source_file_path") else "network",
                title=redact_text(title_raw),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=cve_ids,
                evidence={
                    "asset_type": kind,
                    "asset_value": asset,
                    "defectdojo_id": finding_id,
                    "file": redact_text(str(finding.get("sast_source_file_path") or "")[:500]),
                    "line": finding.get("line") if isinstance(finding.get("line"), int) else None,
                },
                raw_payload={},
            )
        )
        if len(alerts) > MAX_IMPORT_FINDINGS:
            raise ValueError("scanner export has too many findings")
    if rows and not matched_asset:
        raise ValueError("DefectDojo JSON has no findings for the selected asset")
    return alerts


def _bugcrowd_json(
    document: dict[str, Any],
    *,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    links = document.get("links") or {}
    if not isinstance(links, dict):
        raise ValueError("Bugcrowd links must be an object")
    if links.get("next"):
        raise ValueError("Bugcrowd export is incomplete; include all pages")
    data = document.get("data")
    rows = [data] if isinstance(data, dict) else _array(data, "Bugcrowd submissions")
    included = _array(document.get("included"), "Bugcrowd included targets")
    if len(rows) > MAX_IMPORT_FINDINGS or len(included) > MAX_IMPORT_FINDINGS:
        raise ValueError("scanner export has too many findings")
    targets: dict[str, str] = {}
    for item in included:
        target = _object(item, "Bugcrowd included resource")
        if target.get("type") != "target":
            continue
        target_id = target.get("id")
        name = _object(target.get("attributes"), "Bugcrowd target attributes").get("name")
        if isinstance(target_id, str) and isinstance(name, str):
            if target_id in targets and targets[target_id] != name:
                raise ValueError("Bugcrowd target identity is inconsistent")
            targets[target_id] = name
    statuses = {
        "new": "open",
        "triaged": "open",
        "unresolved": "open",
        "resolved": "fixed",
        "informational": "dismissed",
        "not-applicable": "dismissed",
        "not-reproducible": "dismissed",
        "out-of-scope": "dismissed",
    }
    severities = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
    alerts: list[NormalizedExternalAlert] = []
    matched_asset = False
    for item in rows:
        submission = _object(item, "Bugcrowd submission")
        if submission.get("type") != "submission":
            raise ValueError("Bugcrowd export contains a non-submission object")
        relationships = _object(submission.get("relationships"), "Bugcrowd relationships")
        target_ref = _object(
            _object(relationships.get("target"), "Bugcrowd target").get("data"),
            "Bugcrowd target reference",
        )
        name = targets.get(target_ref.get("id")) if target_ref.get("type") == "target" else None
        if name is None:
            continue
        try:
            target_kind, target_asset = normalized_asset_identity(kind, name)
        except ValueError:
            continue
        if (target_kind, target_asset) != (kind, asset):
            continue
        matched_asset = True
        attributes = _object(submission.get("attributes"), "Bugcrowd attributes")
        submission_id = submission.get("id")
        title = attributes.get("title")
        status = statuses.get(attributes.get("state"))
        raw_severity = attributes.get("severity")
        if isinstance(raw_severity, str) and raw_severity.isdecimal():
            raw_severity = int(raw_severity)
        severity = severities.get(raw_severity) if not isinstance(raw_severity, bool) else None
        if (
            not isinstance(submission_id, str)
            or not submission_id
            or len(submission_id) > 300
            or not isinstance(title, str)
            or not title.strip()
            or len(title) > 1000
            or status is None
            or severity is None
        ):
            raise ValueError("Bugcrowd submission lacks valid identity, state, or severity")
        if attributes.get("duplicate") is True:
            status = "dismissed"
        alerts.append(
            NormalizedExternalAlert(
                external_id=_stable_id(provider, submission_id),
                category="bug_bounty",
                title=redact_text(title.strip()),
                severity=severity,
                status=status,
                resource=asset,
                source_url=None,
                cve_ids=[],
                evidence={"asset_type": kind, "asset_value": asset},
                raw_payload={},
            )
        )
    if not matched_asset:
        raise ValueError("Bugcrowd export has no results for the selected asset")
    return alerts


def parse_scan_export(
    data: bytes,
    *,
    format_name: str,
    provider: str,
    asset_type: str,
    asset_value: str,
    field_mapping: Mapping[str, str] | None = None,
) -> list[NormalizedExternalAlert]:
    """Parse a bounded export without retaining arbitrary source payloads or secrets."""
    if not data or len(data) > MAX_IMPORT_BYTES:
        raise ValueError("scanner export is empty or exceeds the size limit")
    if not _PROVIDER.fullmatch(provider):
        raise ValueError("invalid scanner provider")
    if len(asset_value) > 900 or any(ord(char) < 32 for char in asset_value):
        raise ValueError("invalid asset identity")
    kind, asset = normalized_asset_identity(asset_type, asset_value)
    if format_name == "generic_csv":
        try:
            reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
            return _generic(
                reader,
                provider=provider,
                kind=kind,
                asset=asset,
                field_mapping=field_mapping,
            )
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ValueError("generic CSV must be valid UTF-8") from exc
    if format_name == "rapid7_csv":
        try:
            reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")), strict=True)
            return _rapid7_csv(reader, provider=provider, kind=kind, asset=asset)
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ValueError("Rapid7 export must be valid CSV and UTF-8") from exc
    if format_name == "aws_inspector_csv":
        try:
            reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")), strict=True)
            return _aws_inspector_csv(reader, provider=provider, kind=kind, asset=asset)
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ValueError("AWS Inspector export must be valid CSV and UTF-8") from exc
    if format_name == "nuclei_jsonl":
        return _nuclei_jsonl(data, provider=provider, kind=kind, asset=asset)
    if format_name == "nessus_xml":
        return _nessus_xml(data, provider=provider, kind=kind, asset=asset)
    if format_name == "burp_xml":
        return _burp_xml(data, provider=provider, kind=kind, asset=asset)
    if format_name == "qualys_host_detection_xml":
        return _qualys_host_detection_xml(data, provider=provider, kind=kind, asset=asset)
    if format_name in {"checkmarx_xml", "fortify_fvdl", "fortify_fpr"}:
        return _checkmarx_and_fortify_binary_dispatch(
            data, format_name=format_name, provider=provider, kind=kind, asset=asset
        )
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("scanner export must be valid UTF-8 JSON") from exc
    if format_name == "gitleaks":
        return _gitleaks(
            _array(parsed, "Gitleaks findings"),
            provider=provider,
            kind=kind,
            asset=asset,
        )
    if format_name == "generic_json":
        rows = (
            parsed
            if isinstance(parsed, list)
            else _object(parsed, "generic export").get("findings")
        )
        return _generic(
            _array(rows, "generic findings"),
            provider=provider,
            kind=kind,
            asset=asset,
            field_mapping=field_mapping,
        )
    if format_name == "prowler_ocsf":
        return _prowler_ocsf(
            _array(parsed, "Prowler OCSF findings"),
            provider=provider,
            kind=kind,
            asset=asset,
        )
    document = _object(parsed, "scanner export")
    if format_name == "sarif":
        return _sarif(document, provider=provider, kind=kind, asset=asset)
    if format_name == "trivy":
        return _trivy(document, provider=provider, kind=kind, asset=asset)
    if format_name == "cyclonedx":
        return _cyclonedx(document, provider=provider, kind=kind, asset=asset)
    if format_name == "spdx":
        return _spdx(document, provider=provider, kind=kind, asset=asset)
    if format_name == "gcp_scc_json":
        return _gcp_scc_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "azure_defender_json":
        return _azure_defender_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "hackerone_json":
        return _hackerone_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "bugcrowd_json":
        return _bugcrowd_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "wiz_json":
        return _wiz_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "prisma_cloud_json":
        return _prisma_cloud_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "sonarqube_json":
        return _sonarqube_json(document, provider=provider, kind=kind, asset=asset)
    if format_name == "defectdojo_json":
        return _defectdojo_json(document, provider=provider, kind=kind, asset=asset)
    raise ValueError("unsupported scanner export format")


def _checkmarx_and_fortify_binary_dispatch(
    data: bytes,
    *,
    format_name: str,
    provider: str,
    kind: str,
    asset: str,
) -> list[NormalizedExternalAlert]:
    """Separate dispatch path for binary/XML formats that cannot be JSON-parsed first."""
    if format_name == "checkmarx_xml":
        return _checkmarx_xml(data, provider=provider, kind=kind, asset=asset)
    if format_name in {"fortify_fvdl", "fortify_fpr"}:
        return _fortify_fvdl(data, provider=provider, kind=kind, asset=asset)
    raise ValueError("unsupported binary scanner format")


async def stage_scan_export(
    session: AsyncSession,
    principal: Principal,
    data: bytes,
    *,
    format_name: str,
    provider: str,
    asset_type: str,
    asset_value: str,
    field_mapping: Mapping[str, str] | None = None,
    assessment_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
) -> int:
    """Stage a scanner export into the tenant's existing alert and canonical models."""
    principal.require(Permission.ASSESSMENT_CREATE)
    if (assessment_id is None) != (job_id is None):
        raise InvalidConfigurationError("Assessment and scanner job must be linked together.")
    try:
        alerts = parse_scan_export(
            data,
            format_name=format_name,
            provider=provider,
            asset_type=asset_type,
            asset_value=asset_value,
            field_mapping=field_mapping,
        )
    except ValueError as exc:
        raise InvalidConfigurationError(
            "invalid scanner export",
            user_message=str(exc)[:200],
        ) from exc
    if format_name == "prowler_ocsf":
        fixed_ids = [alert.external_id for alert in alerts if alert.status == "fixed"]
        if fixed_ids:
            previously_seen = set(
                (
                    await session.execute(
                        select(ExternalSecurityAlert.external_id).where(
                            ExternalSecurityAlert.organization_id == principal.organization_id,
                            ExternalSecurityAlert.provider == provider,
                            pg_any(ExternalSecurityAlert.external_id, fixed_ids),
                        )
                    )
                )
                .scalars()
                .all()
            )
            alerts = [
                alert
                for alert in alerts
                if alert.status != "fixed" or alert.external_id in previously_seen
            ]
    # The staging service batches SQL internally, then projects the entire
    # upload once. Splitting here produces intermediate lifecycle transitions
    # when observations for one canonical finding straddle batch boundaries.
    staged = await external_alert._stage_normalized_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=None,
        provider=provider,
        alerts=alerts,
    )
    if assessment_id is not None and job_id is not None:
        await link_scan_observations(
            session,
            organization_id=principal.organization_id,
            assessment_id=assessment_id,
            job_id=job_id,
            provider=provider,
            external_ids=[alert.external_id for alert in alerts],
        )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.FINDING_IMPORT,
        principal=principal,
        resource_type="scan_export",
        organization_id=principal.organization_id,
        detail={"provider": provider, "format": format_name, "staged": staged},
    )
    return staged


async def import_prowler_artifact(
    session: AsyncSession,
    principal: Principal,
    job: ScannerJob,
    storage: ObjectStorage,
) -> int:
    """Import a completed sanitized cloud report through the canonical intake path."""
    principal.require(Permission.ASSESSMENT_CREATE)
    if job.organization_id != principal.organization_id:
        raise PermissionDeniedError("Cloud scan job belongs to another organization.")
    if job.imported_at is not None:
        return 0
    cloud_targets = {
        ScannerName.PROWLER_AWS.value: r"aws:\d{12}",
        ScannerName.PROWLER_AZURE.value: r"azure:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
        ScannerName.PROWLER_GCP.value: r"gcp:[a-z][a-z0-9-]{4,28}[a-z0-9]",
    }
    if (
        job.scanner not in cloud_targets
        or job.status != JobStatus.COMPLETED.value
        or len(job.targets) != 1
        or re.fullmatch(cloud_targets[job.scanner], job.targets[0]) is None
    ):
        raise InvalidConfigurationError("Cloud scan job is not safely importable.")
    artifacts = [
        artifact
        for artifact in job.artifacts
        if artifact.kind == ArtifactKind.RAW_OUTPUT.value
        and artifact.filename == "prowler.safe.json"
        and 0 < artifact.size_bytes <= MAX_IMPORT_BYTES
    ]
    if len(artifacts) != 1:
        raise InvalidConfigurationError("Cloud scan has no sanitized report.")
    data = await storage.get_bytes(
        artifacts[0].storage_key,
        organization_id=principal.organization_id,
    )
    count = await stage_scan_export(
        session,
        principal,
        data,
        format_name="prowler_ocsf",
        provider="prowler",
        asset_type="cloud_account",
        asset_value=job.targets[0],
        assessment_id=job.assessment_id,
        job_id=job.id,
    )
    job.imported_at = utcnow()
    return count
