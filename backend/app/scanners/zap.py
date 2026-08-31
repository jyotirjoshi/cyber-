"""OWASP ZAP baseline web scanning (FR-012).

``zap-baseline.py``, not a full active scan.  The baseline script spiders the target and reports
what ZAP's **passive** scanners observe while crawling -- missing security headers, cookie flags,
information disclosure, mixed content.  It does not send attack payloads.  For an MVP whose
active surface is already covered by Nuclei, passive ZAP adds the whole class of findings Nuclei
templates do not model, at no risk to the target.

Three implementation details that are not obvious and each caused a wrong first attempt:

*   **The mount is ``/zap/wrk``, not ``/work``.**  ``zap-baseline.py`` builds report paths by
    concatenating a hard-coded ``/zap/wrk/`` onto the ``-J`` filename, so an absolute path
    produces ``/zap/wrk//work/out/zap.json`` and the report never reaches the host. The
    workdir is therefore mounted where ZAP already looks, which
    :data:`~app.scanners.sandbox.ALLOWED_WORK_MOUNTS` permits explicitly, and ``-J`` gets a
    bare filename. The report lands in the workdir root rather than ``out/``.
*   **The image has no entrypoint.**  Unlike the Nmap and Nuclei images, ``zaproxy/zap-stable``
    starts a shell, so the argv must name the script.
*   **uid 1000, not 65534.**  The image pre-creates ``/home/zap`` owned by its ``zap`` user, and
    ZAP writes its session database there. As ``nobody`` it cannot, and fails on startup with a
    Java stack trace about a missing home directory. uid 1000 is still unprivileged, still has
    no capabilities, and still cannot reach anything on the network but the target.

Exit codes are informational: baseline returns 1 when it reported warnings and 2 on a
configuration failure. ``-I`` keeps warnings from being treated as failure, and
:attr:`ZapAdapter.success_exit_codes` records the rest, so a scan that found something is not
filed as a broken job.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import structlog

from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ArtifactKind, AssessmentDepth, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest

logger = structlog.get_logger(__name__)

#: Spider time per target, in minutes. The baseline script's own default is 1, which on a large
#: application crawls almost nothing.
_DEPTH_SPIDER_MINUTES: dict[AssessmentDepth, int] = {
    AssessmentDepth.PASSIVE: 2,
    AssessmentDepth.STANDARD: 5,
    AssessmentDepth.DEEP: 10,
}


def web_url(target: str) -> str | None:
    """Coerce a canonical target into an ``http(s)`` origin, or ``None`` if it is not web.

    ZAP needs a URL. Nmap-style targets -- bare hosts, IPs, CIDRs -- reach this adapter when an
    assessment selected a host that also serves HTTP, so a hostname is promoted to ``https://``.
    A CIDR is not a web target and returns ``None`` rather than being scanned as a hostname,
    which would resolve to nothing and waste the whole spider budget.
    """
    value = target.strip()
    if not value:
        return None
    if "/" in value and "://" not in value:
        #: A CIDR or a bare path fragment. Neither is an origin.
        return None
    if "://" not in value:
        return f"https://{value}"
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    #: Keep the path and query -- a single-page app may only respond usefully below a prefix --
    #: but drop the fragment, which is not sent to a server.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


class ZapAdapter(ScannerAdapter):
    name = ScannerName.ZAP
    image_setting = "image_zap"
    defectdojo_scan_type = "ZAP Scan"
    #: The image's CMD is a shell; the argv names the script. See the module docstring.
    entrypoint_is_tool = False

    work_mount = "/zap/wrk"
    #: ZAP writes its session database, add-on state and Java preferences under its home
    #: directory, none of which fit on a tmpfs sized for scratch.
    read_only_root = False
    run_as_user = "1000:1000"

    #: 1 = warnings were reported, which is the normal outcome of a scan that found something.
    #: 2 = ZAP failed to start or the target was unreachable; still not a Cynux fault, and the
    #: job records it with the stderr artifact attached.
    success_exit_codes = frozenset({0, 1, 2})

    SCRIPT = "zap-baseline.py"
    REPORT_NAME = "zap.json"

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if not self._urls(request):
            raise UnsafeScannerInvocationError(
                "No web target could be derived for ZAP.",
                context={"target_count": len(request.targets)},
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        urls = self._urls(request)
        depth = self._depth(request)

        #: One target per container. The baseline script takes a single ``-t``, and running a
        #: container per web target is what makes per-target timeouts and cancellation work.
        #: The job service fans out; :meth:`validate` guarantees there is at least one.
        target = urls[0]
        if len(urls) > 1:
            logger.info("zap.extra_targets_ignored", count=len(urls) - 1, scanned=target)

        return (
            self.SCRIPT,
            "-t",
            target,
            #: Bare filename: ZAP resolves it against the mount. See the module docstring.
            "-J",
            self.REPORT_NAME,
            #: Do not fail the run on warnings -- reported findings are the point.
            "-I",
            #: Spider budget in minutes. This is also what bounds the run: baseline reports
            #: whatever the passive scanners saw when the spider's time is up.
            "-m",
            str(_DEPTH_SPIDER_MINUTES[depth]),
        )

    def _urls(self, request: ScannerRequest) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for target in request.targets:
            url = web_url(target)
            if url:
                seen.setdefault(url, None)
        return tuple(seen)

    def _depth(self, request: ScannerRequest) -> AssessmentDepth:
        raw = request.option("depth", AssessmentDepth.STANDARD)
        try:
            return AssessmentDepth(str(raw))
        except ValueError:
            logger.warning("zap.unknown_depth", depth=str(raw))
            return AssessmentDepth.STANDARD

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        #: The workdir root, not ``out/`` -- ZAP resolves the report name against the mount.
        report = describe(
            Path(request.workdir) / self.REPORT_NAME,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        if report is None:
            logger.warning("zap.no_report", expected=str(Path(request.workdir) / self.REPORT_NAME))
            return ()
        return (report,)


ADAPTER = ZapAdapter()

__all__ = ["ADAPTER", "ZapAdapter", "web_url"]
