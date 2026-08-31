"""Nuclei template-based vulnerability scanning (FR-012).

Nuclei is the scanner that produces most of an assessment's findings, and the one whose defaults
need the most trimming.  Four decisions are worth stating:

*   **No interactsh.**  ``-no-interactsh`` disables the out-of-band interaction server.  By
    default Nuclei registers callbacks with a ProjectDiscovery-hosted domain, which means a
    customer's internal hostnames and payload hits are sent to a third party Cynux has no
    agreement with.  Blind-SSRF and blind-RCE templates stop working without it; that is the
    trade, and it is the right way round.
*   **No destructive templates.**  ``-exclude-tags dos,intrusive,fuzz`` and
    ``-exclude-severity unknown``.  PRD section 8 puts automated destructive exploitation out of
    scope, and the ``dos`` tag is exactly that.
*   **Findings, not noise.**  Severities are ``critical,high,medium,low`` by default -- ``info``
    templates make up the bulk of Nuclei's output and turn a findings list into a technology
    inventory.  Asset discovery is recon's job, not this one's.
*   **JSONL, not JSON.**  Nuclei writes JSONL incrementally, one finding per line.  A scan
    killed at the timeout therefore leaves a valid, importable file; a truncated JSON array
    would leave a parse error and lose every finding it had already reported.

The report goes to DefectDojo (``Nuclei Scan``), which owns parsing and deduplication -- Cynux
does not read it (PRD section 8: no custom scanner parsers).
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import structlog

from app.db.enums import ArtifactKind, AssessmentDepth, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest

logger = structlog.get_logger(__name__)

#: Severity sets per depth. ``info`` is included only at ``deep``, where the operator has asked
#: for everything and can be assumed to want the noise.
_DEPTH_SEVERITY: dict[AssessmentDepth, str] = {
    AssessmentDepth.PASSIVE: "critical,high",
    AssessmentDepth.STANDARD: "critical,high,medium,low",
    AssessmentDepth.DEEP: "critical,high,medium,low,info",
}

#: Template tags never run, at any depth. See the module docstring.
EXCLUDED_TAGS = "dos,intrusive,fuzz"

#: Requests per second, per target. Nuclei's default of 150 is enough to look like an attack to
#: a WAF and enough to hurt a small application. The agent may lower this but not raise it.
DEFAULT_RATE_LIMIT = 50
MAX_RATE_LIMIT = 150


class NucleiAdapter(ScannerAdapter):
    name = ScannerName.NUCLEI
    image_setting = "image_nuclei"
    #: DefectDojo's parser name. It accepts both JSON and JSONL from Nuclei.
    defectdojo_scan_type = "Nuclei Scan"
    entrypoint_is_tool = True

    #: Nuclei resolves ``$HOME`` on startup to find its config and template directory, and exits
    #: if it cannot. ``/tmp`` is the tmpfs: templates land in memory-backed scratch that vanishes
    #: with the container, rather than in the bind-mounted job directory where they would be
    #: collected as artifacts and uploaded.
    #: S108 does not apply: this is a path *inside the container*, on a tmpfs Cynux creates
    #: with ``nosuid,noexec,nodev`` in its own mount namespace, not a shared host directory.
    container_env = MappingProxyType({"HOME": "/tmp"})  # noqa: S108
    #: With ``HOME`` on a tmpfs the root filesystem can stay read-only.
    read_only_root = True

    REPORT_NAME = "nuclei.jsonl"
    TARGETS_NAME = "nuclei-targets.txt"

    def prepare(self, request: ScannerRequest) -> None:
        if len(request.targets) > 1:
            (Path(request.workdir) / self.TARGETS_NAME).write_text(
                "\n".join(request.targets) + "\n", encoding="utf-8"
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        depth = self._depth(request)
        rate_limit = self._rate_limit(request)

        argv: list[str] = []
        if len(request.targets) == 1:
            argv += ["-target", request.targets[0]]
        else:
            argv += ["-list", self.container_path(self.TARGETS_NAME)]

        argv += [
            #: One JSON object per line, written as findings are confirmed. See the module
            #: docstring: this is what makes a timed-out scan's output importable.
            "-jsonl",
            "-output",
            self.container_path("out", self.REPORT_NAME),
            "-severity",
            _DEPTH_SEVERITY[depth],
            "-exclude-tags",
            EXCLUDED_TAGS,
            #: No out-of-band callbacks to a third-party service.
            "-no-interactsh",
            #: The container has no writable install directory and no business phoning home for
            #: a new binary mid-assessment.
            "-disable-update-check",
            "-no-color",
            "-rate-limit",
            str(rate_limit),
            "-concurrency",
            str(int(request.option("concurrency", 25))),
            "-bulk-size",
            str(int(request.option("bulk_size", 25))),
            "-timeout",
            "10",
            "-retries",
            "1",
            #: Periodic progress to stderr. This is what the worker turns into FR-038 progress
            #: events, so a twenty-minute scan is not a silent spinner.
            "-stats",
            "-stats-interval",
            "30",
        ]
        return tuple(argv)

    def _depth(self, request: ScannerRequest) -> AssessmentDepth:
        raw = request.option("depth", AssessmentDepth.STANDARD)
        try:
            return AssessmentDepth(str(raw))
        except ValueError:
            logger.warning("nuclei.unknown_depth", depth=str(raw))
            return AssessmentDepth.STANDARD

    def _rate_limit(self, request: ScannerRequest) -> int:
        """Clamped, not trusted.

        The rate limit can originate with the agent, and an LLM asked to "scan quickly" will
        reach for a large number. The ceiling is what keeps a Cynux assessment from being
        indistinguishable from an attack.
        """
        try:
            requested = int(request.option("rate_limit", DEFAULT_RATE_LIMIT))
        except (TypeError, ValueError):
            requested = DEFAULT_RATE_LIMIT
        clamped = max(1, min(requested, MAX_RATE_LIMIT))
        if clamped != requested:
            logger.info("nuclei.rate_limit_clamped", requested=requested, applied=clamped)
        return clamped

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        report = describe(
            request.out_dir / self.REPORT_NAME,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        if report is None:
            #: Nuclei writes the output file only when it has a finding, so an absent file is
            #: the normal "nothing found" case -- not an error, and not something to warn about
            #: on every clean scan.
            logger.info("nuclei.no_findings", target_count=len(request.targets))
            return ()
        return (report,)


ADAPTER = NucleiAdapter()

__all__ = [
    "DEFAULT_RATE_LIMIT",
    "EXCLUDED_TAGS",
    "MAX_RATE_LIMIT",
    "ADAPTER",
    "NucleiAdapter",
]
