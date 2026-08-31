"""Nmap service and port discovery (FR-012).

Runs **connect scans only**.  ``-sT`` rather than ``-sS``, and ``--unprivileged`` to stop Nmap
attempting a raw socket at all, because the sandbox drops every Linux capability including
``NET_RAW`` (see :mod:`app.scanners.sandbox`).  A SYN scan would be faster and stealthier; a
scanner container that can forge packets is worth more to an attacker than either, so the
capability stays dropped and Nmap uses the kernel's TCP stack like any other client.

Two things this adapter refuses to do:

*   **No NSE.**  ``--script`` is never emitted and :meth:`NmapAdapter.build_argv` asserts it is
    absent.  NSE scripts are arbitrary Lua with network and filesystem access, and the script
    categories include ``exploit`` and ``dos`` -- PRD section 8 puts automated destructive
    exploitation out of scope, and "the agent picked a script name" is not a control.
*   **No host discovery.**  ``-Pn`` skips the ping sweep.  Targets reaching this adapter have
    already been validated (FR-006) and approved (FR-011); re-deciding whether to scan them
    based on an ICMP reply would silently drop hosts behind a firewall that the human
    explicitly approved.

Output is XML because that is what DefectDojo's ``Nmap Scan`` parser reads.  Nmap's XML also
carries the service-version evidence the asset inventory needs, which the ``-oN`` text output
does not.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import structlog

from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ArtifactKind, AssessmentDepth, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest

logger = structlog.get_logger(__name__)

#: Flags that would either need a capability the sandbox drops, or run code Cynux does not
#: control. Asserted against the built argv rather than merely avoided.
FORBIDDEN_FLAGS = frozenset(
    {
        "-sS",  # SYN scan: needs NET_RAW
        "-sA",
        "-sF",
        "-sN",
        "-sX",
        "-sW",
        "-sM",
        "-sO",
        "-sY",
        "-sZ",
        "-O",  # OS detection: needs raw packets
        "-A",  # implies -O and --script=default
        "--script",
        "--script-args",
        "--script-args-file",
        "--script-help",
        "--script-updatedb",
        "--script-trace",
        "-sU",  # UDP scan: needs NET_RAW
        "--send-eth",
        "--spoof-mac",
        "-S",  # source address spoofing
        "-D",  # decoys
        "-f",  # fragmentation
        "--traceroute",
        "-iR",  # random targets: would scan hosts nobody approved
    }
)

#: Beyond this many hosts on the command line, targets go in a file. Nmap has no argv limit of
#: its own, but the kernel's ``ARG_MAX`` does, and a 4000-subdomain scan would hit it.
INLINE_TARGET_LIMIT = 40

#: How many ports each depth scans. ``deep`` is every port, which on a slow host is hours --
#: the runner's timeout is what bounds it, and partial XML is still imported.
_DEPTH_PORTS: dict[AssessmentDepth, tuple[str, ...]] = {
    AssessmentDepth.PASSIVE: ("--top-ports", "100"),
    AssessmentDepth.STANDARD: ("--top-ports", "1000"),
    AssessmentDepth.DEEP: ("-p-",),
}


def target_host(target: str) -> str:
    """Reduce a canonical target to the bare host Nmap wants.

    Targets arrive from :func:`app.core.targets.validate_target`, which canonicalises web
    targets as URLs. Nmap takes hosts, CIDRs and ranges -- handing it ``https://x/path?q=1``
    scans nothing and reports no error, which is the failure mode this function exists to
    prevent.
    """
    value = target.strip()
    if "://" in value:
        parsed = urlsplit(value)
        return (parsed.hostname or "").strip("[]") or value
    #: A bare ``host:port`` -- but not an IPv6 literal, where colons are the address.
    if value.count(":") == 1 and not value.startswith("["):
        head, _, tail = value.partition(":")
        if tail.isdigit():
            return head
    return value.strip("[]")


class NmapAdapter(ScannerAdapter):
    name = ScannerName.NMAP
    image_setting = "image_nmap"
    #: DefectDojo's parser name for Nmap XML.
    defectdojo_scan_type = "Nmap Scan"
    #: ``instrumentisto/nmap`` has ``nmap`` as its entrypoint, so the argv starts at the flags.
    entrypoint_is_tool = True

    REPORT_NAME = "nmap.xml"
    TARGETS_NAME = "nmap-targets.txt"

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        hosts = self._hosts(request)
        if not hosts:
            raise UnsafeScannerInvocationError(
                "No scannable host could be derived from the Nmap targets.",
                context={"target_count": len(request.targets)},
            )

    def prepare(self, request: ScannerRequest) -> None:
        hosts = self._hosts(request)
        if len(hosts) > INLINE_TARGET_LIMIT:
            (Path(request.workdir) / self.TARGETS_NAME).write_text(
                "\n".join(hosts) + "\n", encoding="utf-8"
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        hosts = self._hosts(request)
        depth = self._depth(request)

        argv: list[str] = [
            #: TCP connect scan. See the module docstring: the sandbox has no NET_RAW.
            "-sT",
            #: Tell Nmap not to try raw sockets, so it fails loudly at argument parsing rather
            #: than silently degrading mid-scan.
            "--unprivileged",
            #: No ping sweep -- the target list is already validated and approved.
            "-Pn",
            #: Service and version detection. This is the value Nmap adds over a port sweep,
            #: and what the enrichment step needs to match a CPE to a CVE.
            "-sV",
            "--version-intensity",
            "5",
            #: Aggressive-but-not-reckless timing. T5 drops results on lossy links, which for a
            #: security assessment means a missed open port reported as closed.
            "-T4",
            #: A single unresponsive host must not consume the whole job's budget.
            "--host-timeout",
            f"{max(60, min(request.timeout_seconds, 3600))}s",
            "--max-retries",
            "2",
            #: Bounded scan rate, so a Cynux scan is not itself a denial of service.
            "--max-rate",
            str(int(request.option("max_rate", 500))),
            "-oX",
            self.container_path("out", self.REPORT_NAME),
        ]
        argv.extend(_DEPTH_PORTS[depth])

        if len(hosts) > INLINE_TARGET_LIMIT:
            argv += ["-iL", self.container_path(self.TARGETS_NAME)]
        else:
            argv.extend(hosts)

        self._assert_no_raw_or_script(argv)
        return tuple(argv)

    def _assert_no_raw_or_script(self, argv: list[str]) -> None:
        """Final gate. See the two refusals in the module docstring."""
        offending = sorted(
            element
            for element in argv
            #: Prefix match catches ``--script=vuln`` as well as a bare ``--script``.
            if element in FORBIDDEN_FLAGS or element.split("=", 1)[0] in FORBIDDEN_FLAGS
        )
        if offending:
            logger.critical("nmap.forbidden_flag_blocked", flags=offending)
            raise UnsafeScannerInvocationError(
                "Nmap was about to be run with a flag Cynux forbids.",
                user_message=(
                    "Cynux blocked a port scan that requested capabilities or scripts it is "
                    "not permitted to use."
                ),
                context={"flags": offending},
            )

    def _hosts(self, request: ScannerRequest) -> tuple[str, ...]:
        """De-duplicated bare hosts, order preserved so the argv is reproducible."""
        seen: dict[str, None] = {}
        for target in request.targets:
            host = target_host(target)
            if host:
                seen.setdefault(host, None)
        return tuple(seen)

    def _depth(self, request: ScannerRequest) -> AssessmentDepth:
        raw = request.option("depth", AssessmentDepth.STANDARD)
        try:
            return AssessmentDepth(str(raw))
        except ValueError:
            #: An unrecognised depth becomes STANDARD rather than DEEP. Guessing upward would
            #: turn a typo into an all-ports scan of a production network.
            logger.warning("nmap.unknown_depth", depth=str(raw))
            return AssessmentDepth.STANDARD

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        report = describe(
            request.out_dir / self.REPORT_NAME,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        if report is None:
            #: Nmap writes the XML header before scanning and the closing tag at the end, so a
            #: missing file means it never started -- usually a bad flag. The stderr artifact
            #: has the reason.
            logger.warning("nmap.no_report", expected=str(request.out_dir / self.REPORT_NAME))
            return ()
        return (report,)


ADAPTER = NmapAdapter()

__all__ = [
    "FORBIDDEN_FLAGS",
    "INLINE_TARGET_LIMIT",
    "ADAPTER",
    "NmapAdapter",
    "target_host",
]
