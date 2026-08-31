"""ReconFTW passive discovery (FR-007, FR-008).

**FR-008 is a hard constraint and this module is where it is enforced.**  ReconFTW is an
orchestrator: left to its defaults it will start Nmap, run Nuclei, brute-force subdomains,
fuzz directories and fire injection payloads.  Every one of those is an *active* action against
a target, and in Cynux active actions happen only after a human approves them at the FR-011
interrupt -- reconnaissance runs **before** that approval, to produce the asset list the human
is approving a scan of.  A recon stage that attacked would mean Cynux attacked a system nobody
had yet agreed to attack.

Three independent mechanisms hold the line, because one would not:

1.  **Passive mode.**  ``-p`` (``--passive``), not ``-r``.  ReconFTW's recon mode includes port
    scanning and web probing; passive mode restricts it to sources that never touch the target
    -- certificate transparency, passive DNS, archives, search engines.
2.  **A config override.**  ``-f /work/reconftw.cfg`` is sourced *after* ReconFTW's own config,
    so :func:`hardening_config` gets the last word and explicitly disables every attack and
    scanning stage by name.  Unknown variables in a sourced shell config are harmless, so the
    list is deliberately a superset that covers ReconFTW's naming across versions.
3.  **A flag assertion.**  :meth:`ReconFTWAdapter.validate` refuses to run if any active-mode
    flag reached the argv, whatever built it.  This is the check that survives someone adding
    a "pass extra flags" option later.

The fourth mechanism is not in this file: the sandbox gives the container no credentials and an
egress-only network, so even a ReconFTW that ignored all three could not reach Cynux's own
infrastructure (SEC-004).

**Deployment note.**  The upstream ``six2dez/reconftw`` image is built to run as root, with its
tool tree under ``/root``.  Cynux refuses to run any scanner as root
(:func:`app.scanners.sandbox._assert_unprivileged`), so the deployment must supply an image whose
tools are readable by an unprivileged user -- see ``docker/scanners/README.md``.  Loosening the
uid instead is not an option: the workdir is a bind mount, so root in the container is root on
the host's files.

Recon output is **assets, not findings**.  :attr:`ReconFTWAdapter.defectdojo_scan_type` is
``None``: there is nothing here for DefectDojo to import.  :mod:`app.scanners.recon_assets`
turns the output into asset rows.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import structlog

from app.core.errors import UnsafeScannerInvocationError
from app.db.enums import ArtifactKind, ScannerName
from app.scanners.artifacts import collect_dir
from app.scanners.base import ArtifactFile, ScannerAdapter, ScannerRequest

logger = structlog.get_logger(__name__)

#: Flags that select an active ReconFTW mode or enable attack modules. Presence of any of these
#: in a built argv is a guardrail trip, not a configuration choice.
FORBIDDEN_FLAGS = frozenset(
    {
        "-a",
        "--all",
        "-w",
        "--web",
        "-n",
        "--osint",
        "-c",
        "--custom",
        "-v",
        "--vps",
        "-r",
        "--recon",
        "-s",
        "--subdomains",
        "-z",
        "--zen",
        "-y",
        "--ai",
        "--deep",
        "--force",
    }
)

#: The config ReconFTW sources last, via ``-f``. Every switch that could produce traffic to the
#: target -- or to a third party on the target's behalf -- is off.
_HARDENING: dict[str, str] = {
    # -- mode-level -------------------------------------------------------
    "DEEP": "false",
    "DIFF": "false",
    "AXIOM": "false",
    "REMOVETMP": "true",
    "REMOVELOG": "false",
    "PROXY": "false",
    "SENDZIPNOTIFY": "false",
    "NOTIFICATION": "false",
    # -- host discovery / port scanning (FR-008: Nmap is a separate, approved job)
    "PORTSCANNER": "false",
    "PORTSCAN_PASSIVE": "false",
    "PORTSCAN_ACTIVE": "false",
    "GEO_INFO": "false",
    "CDN_IP": "false",
    # -- subdomain stages: passive sources only ---------------------------
    "SUBBRUTE": "false",
    "SUBSCRAPING": "false",
    "SUBPERMUTE": "false",
    "SUBREGEXPERMUTE": "false",
    "SUB_RECURSIVE_BRUTE": "false",
    "SUB_RECURSIVE_PASSIVE": "false",
    "SUBANALYTICS": "false",
    "ZONETRANSFER": "false",
    "S3BUCKETS": "false",
    "SUBTAKEOVER": "false",
    # -- web probing and crawling -----------------------------------------
    "WEBPROBESIMPLE": "false",
    "WEBPROBEFULL": "false",
    "WEBSCREENSHOT": "false",
    "VIRTUALHOSTS": "false",
    "URL_CHECK": "false",
    "URL_GF": "false",
    "URL_EXT": "false",
    "JSCHECKS": "false",
    "FUZZ": "false",
    "CMS_SCANNER": "false",
    "WAF_DETECTION": "false",
    "NUCLEICHECK": "false",
    "PARAMS": "false",
    "BROKENLINKS": "false",
    "SPRAY": "false",
    "FAVICON": "false",
    "CACHE_CHECK": "false",
    # -- vulnerability modules: all of them --------------------------------
    "VULNS_GENERAL": "false",
    "XSS": "false",
    "CORS": "false",
    "TEST_SSL": "false",
    "OPEN_REDIRECT": "false",
    "SSRF_CHECKS": "false",
    "CRLF_CHECKS": "false",
    "LFI": "false",
    "SSTI": "false",
    "SQLI": "false",
    "COMM_INJ": "false",
    "PROTO_POLLUTION": "false",
    "SMUGGLING": "false",
    "WEBCACHE": "false",
    "BYPASSER4XX": "false",
    "FUZZPARAMS": "false",
}


def hardening_config() -> str:
    """The ``reconftw.cfg`` override written into the workdir.

    Sourced by ReconFTW after its own configuration, so these assignments win. See the module
    docstring for why the list is a superset of what any one ReconFTW version defines.
    """
    lines = [
        "# Generated by Cynux. FR-008: passive discovery only.",
        "# Sourced after reconftw.cfg, so these assignments are final.",
        "# Any active stage enabled here would attack a target before human approval.",
        "",
    ]
    lines.extend(f"{name}={value}" for name, value in sorted(_HARDENING.items()))
    lines.append("")
    return "\n".join(lines)


class ReconFTWAdapter(ScannerAdapter):
    name = ScannerName.RECONFTW
    image_setting = "image_reconftw"
    #: Recon produces assets, not findings. Nothing here is a DefectDojo import.
    defectdojo_scan_type = None

    #: ReconFTW writes tool caches and resolver lists into its own install directory, which a
    #: read-only root forbids. Every other sandbox restriction still applies -- no capabilities,
    #: no host environment, unprivileged user, egress-only network -- and the writable layer
    #: dies with the container.
    read_only_root = False

    #: ReconFTW's helper tools resolve ``$HOME`` for their config and API-key files. Pointing it
    #: at the tmpfs keeps that scratch out of the bind-mounted job directory, where it would be
    #: uploaded as an artifact.
    #: S108 does not apply: a container-internal path on Cynux's own tmpfs, not a host
    #: directory shared with anything. See :mod:`app.scanners.sandbox`.
    container_env = MappingProxyType({"HOME": "/tmp"})  # noqa: S108

    CONFIG_NAME = "reconftw.cfg"
    TARGETS_NAME = "targets.txt"

    def validate(self, request: ScannerRequest) -> None:
        super().validate(request)
        if len(request.targets) > 50:
            raise UnsafeScannerInvocationError(
                "Too many recon targets for one job.",
                context={"count": len(request.targets)},
            )

    def prepare(self, request: ScannerRequest) -> None:
        workdir = Path(request.workdir)
        (workdir / self.CONFIG_NAME).write_text(hardening_config(), encoding="utf-8")
        if len(request.targets) > 1:
            (workdir / self.TARGETS_NAME).write_text(
                "\n".join(request.targets) + "\n", encoding="utf-8"
            )
        request.out_dir.mkdir(parents=True, exist_ok=True)

    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]:
        argv: list[str] = []
        if len(request.targets) == 1:
            argv += ["-d", request.targets[0]]
        else:
            argv += ["-l", self.container_path(self.TARGETS_NAME)]

        argv += [
            #: Passive mode. Not ``-r``: recon mode port-scans and probes, which is active
            #: traffic against a target nobody has approved scanning yet (FR-008).
            "-p",
            "-f",
            self.container_path(self.CONFIG_NAME),
            "-o",
            self.container_path("out"),
        ]

        self._assert_passive(argv)
        return tuple(argv)

    def _assert_passive(self, argv: list[str]) -> None:
        """Final gate. See mechanism 3 in the module docstring."""
        offending = sorted(FORBIDDEN_FLAGS.intersection(argv))
        if offending:
            logger.critical("reconftw.active_flag_blocked", flags=offending)
            raise UnsafeScannerInvocationError(
                "ReconFTW was about to be run with an active-mode flag, which FR-008 forbids.",
                user_message=(
                    "Cynux blocked a reconnaissance run that would have performed active "
                    "scanning before approval."
                ),
                context={"flags": offending},
            )
        if "-p" not in argv:
            raise UnsafeScannerInvocationError(
                "ReconFTW argv did not select passive mode.",
                context={"scanner": str(self.name)},
            )

    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]:
        """ReconFTW writes a directory tree, not one report file.

        Only text and JSON outputs are kept: the tree also contains screenshots and tool caches
        that are megabytes each and are not evidence anyone reads.
        """
        artifacts = collect_dir(
            request.out_dir,
            kind=ArtifactKind.RAW_OUTPUT,
            patterns=("*.txt", "*.json", "*.jsonl", "*.csv"),
            recursive=True,
            limit=120,
        )
        if not artifacts:
            logger.warning("reconftw.no_output", out_dir=str(request.out_dir))
        return artifacts


ADAPTER = ReconFTWAdapter()

__all__ = ["FORBIDDEN_FLAGS", "ADAPTER", "ReconFTWAdapter", "hardening_config"]
