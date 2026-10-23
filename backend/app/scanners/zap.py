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
    :data:`~app.scanners.sandbox.ALLOWED_WORK_MOUNTS` permits explicitly, and ``-x`` gets a
    bare filename. The XML report lands in the workdir root rather than ``out/`` and matches
    DefectDojo's ``ZAP Scan`` parser contract.
*   **The image has no entrypoint.**  Unlike the Nmap and Nuclei images, ``zaproxy/zap-stable``
    starts a shell, so the argv must name the script.
*   **uid 1000, not 65534.**  The image pre-creates ``/home/zap`` owned by its ``zap`` user, and
    ZAP writes its session database there. As ``nobody`` it cannot, and fails on startup with a
    Java stack trace about a missing home directory. uid 1000 is still unprivileged, still has
    no capabilities, and still cannot reach anything on the network but the target.

Exit codes are significant: baseline returns 1 for alerts configured as FAIL, 2 for
WARN-only alerts, and 3 for a scan failure. A scan is complete only when it also produced
its XML report.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import structlog

from app.core.crypto import Secret
from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ArtifactKind, AssessmentDepth, ScannerName
from app.scanners.artifacts import describe
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest
from app.scanners.openapi_scope import SPEC_FILENAME, prepare_openapi_spec

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
    credential_environment_names = frozenset({"CYNUX_ZAP_API_TOKEN"})

    #: 1 = FAIL-level alerts; 2 = WARN-only alerts; 3 = scan or configuration failure.
    success_exit_codes = frozenset({0, 1, 2})
    requires_output = True

    SCRIPT = "zap-baseline.py"
    REPORT_NAME = "zap.xml"
    AUTH_HOOK_NAME = "zap-auth-hook.py"
    AUTH_SENDER_NAME = "zap-auth-sender.js"

    def prepare(self, request: ScannerRequest) -> None:
        api_mode = prepare_openapi_spec(request)
        token = request.option("api_auth_token")
        if token is None:
            return
        if not api_mode or not isinstance(token, Secret) or len(request.targets) != 1:
            raise UnsafeScannerInvocationError("ZAP API credential is not target-scoped")
        target = request.targets[0]
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise UnsafeScannerInvocationError("ZAP API credential target is invalid")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        prefix = parsed.path.rstrip("/") or "/"
        sender = f"""function sendingRequest(msg, initiator, helper) {{
  var uri = msg.getRequestHeader().getURI();
  var scheme = String(uri.getScheme()).toLowerCase();
  var host = String(uri.getHost()).toLowerCase();
  var port = uri.getPort();
  if (port < 0) port = scheme === 'https' ? 443 : 80;
  var path = String(uri.getPath() || '/');
  var prefix = {json.dumps(prefix)};
  if (scheme !== {json.dumps(parsed.scheme)} || host !== {json.dumps(parsed.hostname.lower())}
      || port !== {port} || path.indexOf('..') >= 0 || path.indexOf('%') >= 0
      || !(prefix === '/' || path === prefix || path.indexOf(prefix + '/') === 0)) return;
  var token = Java.type('java.lang.System').getenv('CYNUX_ZAP_API_TOKEN');
  if (token) msg.getRequestHeader().setHeader('Authorization', 'Bearer ' + token);
}}
function responseReceived(msg, initiator, helper) {{}}
"""
        hook = """def zap_started(zap, target):
    engines = [entry.split(' : ')[-1] for entry in zap.script.list_engines]
    engine = next((name for name in ('Graal.js', 'Oracle Nashorn') if name in engines), None)
    if engine is None:
        raise RuntimeError('ZAP JavaScript engine is unavailable for authenticated scan')
    loaded = zap.script.load('cynux-auth-sender', 'httpsender', engine,
                             '/zap/wrk/zap-auth-sender.js')
    if loaded != 'OK':
        raise RuntimeError('ZAP could not load the scoped authentication sender')
    enabled = zap.script.enable('cynux-auth-sender')
    if enabled != 'OK':
        raise RuntimeError('ZAP could not enable the scoped authentication sender')
    return zap, target
"""
        (Path(request.workdir) / self.AUTH_SENDER_NAME).write_text(sender, encoding="utf-8")
        (Path(request.workdir) / self.AUTH_HOOK_NAME).write_text(hook, encoding="utf-8")

    def verify_credential_scope(
        self, request: ScannerRequest, credentials: dict[str, str]
    ) -> None:
        token = request.option("api_auth_token")
        if token is None and not credentials:
            return
        if (
            not isinstance(token, Secret)
            or len(request.targets) != 1
            or request.option("api_spec") is None
            or set(credentials) != {"CYNUX_ZAP_API_TOKEN"}
            or credentials["CYNUX_ZAP_API_TOKEN"] != token.reveal()
        ):
            raise UnsafeScannerInvocationError("ZAP credential does not match the scoped API job")

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if not self._urls(request):
            raise UnsafeScannerInvocationError(
                "No web target could be derived for ZAP.",
                context={"target_count": len(request.targets)},
            )

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        if request.option("api_spec") is not None:
            argv = (
                "zap-api-scan.py", "-t", self.container_path(SPEC_FILENAME),
                "-f", "openapi", "-x", self.REPORT_NAME, "-I",
            )
            if request.option("api_auth_token") is not None:
                return (*argv, f"--hook={self.container_path(self.AUTH_HOOK_NAME)}")
            return argv
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
            "-x",
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
        report_path = Path(request.workdir) / self.REPORT_NAME
        token = request.option("api_auth_token")
        if report_path.is_file() and isinstance(token, Secret):
            if report_path.stat().st_size > 64 * 1024 * 1024:
                raise UnsafeScannerInvocationError("Authenticated ZAP report exceeds safe redaction limit")
            raw = report_path.read_bytes()
            plaintext = token.reveal()
            for variant in {plaintext, json.dumps(plaintext)[1:-1]}:
                raw = raw.replace(variant.encode("utf-8"), b"[REDACTED]")
            report_path.write_bytes(raw)
        report = describe(
            report_path,
            kind=ArtifactKind.RAW_OUTPUT,
            defectdojo_scan_type=self.defectdojo_scan_type,
        )
        if report is None:
            logger.warning("zap.no_report", expected=str(Path(request.workdir) / self.REPORT_NAME))
            return ()
        return (report,)


ADAPTER = ZapAdapter()

__all__ = ["ADAPTER", "ZapAdapter", "web_url"]
