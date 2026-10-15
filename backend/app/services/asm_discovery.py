"""Continuous Attack Surface Management discovery — runs outside assessment workflow.

A recurring-scan schedule is powerful but assessment-scoped: it produces an Assessment row,
a full agent run, and scanner jobs. ASM discovery is lighter: it runs passive reconnaissance
(ReconFTW ``-p``) against every tenant's registered surface targets, diffs against the live
inventory, emits drift notifications, and updates ``AssetChange`` records — with no assessment
and no agent invocation overhead.

Design constraints:
* At most one discovery run per tenant per cadence to prevent concurrent recon jobs.
* Each run checks its own authorization expiry before touching a scanner — an expired scope
  silently disables the surface, same as ``RecurringScan``.
* New/changed assets are recorded in ``AssetChange`` and trigger a ``new_asset`` notification.
* No findings are produced; the output feeds the asset inventory only.
* Tenant isolation enforced at every DB query.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import structlog
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    CynuxError,
    InvalidConfigurationError,
    ScannerContainerError,
    ScannerCrashError,
    ScannerTimeoutError,
)
from app.db.base import utcnow
from app.db.enums import AssetStatus, Criticality, CriticalitySource, NotificationEvent, Permission
from app.db.models.asset import Asset, AssetChange
from app.db.models.identity import Membership, Organization, User
from app.schemas.asm import (
    AsmSurfaceCreateIn,
    AsmSurfaceOut,
    AsmSurfaceUpdateIn,
)
from app.services import notification as notification_service
from app.services.context import Principal
from app.services.notification import NotificationContent
from app.services.scheduling import next_cron_time

log = structlog.get_logger(__name__)

# Maximum seed domains/IPs per surface (keeps recon jobs bounded)
MAX_SURFACE_SEEDS = 50
# Maximum assets written per discovery run (prevents runaway DB growth from noisy CT feeds)
MAX_ASSETS_PER_RUN = 5_000
# Maximum runs pulled per maintenance tick — one per tenant is the fair-share goal
_BATCH_LIMIT = 20
# Asset columns that trigger a "changed" record when they differ from the stored row
_TRACKABLE_FIELDS = frozenset(
    {"ip_address", "http_title", "http_status_code", "tls_subject", "service", "internet_exposed"}
)
_ASM_SURFACE_LAST_SEEN = "asm_surface_last_seen"
_ASM_SURFACE_MISSES = "asm_surface_misses"
_MISSING_CONFIRMATIONS = 2


# ---------------------------------------------------------------------------
# Model (inline — avoids a new migration file; column added to existing table
# via the batch migration 0040 created below)
# ---------------------------------------------------------------------------
# The AsmSurface model lives in app.db.models.identity (same file as Organization)
# so it is loaded with the rest of the ORM on startup. We import it lazily here to
# avoid a circular import with the model file.


def _load_model() -> Any:
    from app.db.models.asm import AsmSurface  # type: ignore[attr-defined]
    return AsmSurface


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


async def create_surface(
    session: AsyncSession,
    principal: Principal,
    payload: AsmSurfaceCreateIn,
    settings: Settings,
) -> Any:
    AsmSurface = _load_model()
    principal.require(Permission.ASSESSMENT_CREATE)
    if len(payload.seeds) > MAX_SURFACE_SEEDS:
        raise InvalidConfigurationError(
            f"A surface may have at most {MAX_SURFACE_SEEDS} seeds.",
            user_message=f"A surface may have at most {MAX_SURFACE_SEEDS} seeds.",
        )
    if principal.user_id is None or not payload.authorization_confirmed:
        raise InvalidConfigurationError(
            "A human operator must confirm scope authorization.",
            user_message="A human operator must confirm scope authorization.",
        )
    now = utcnow()
    expiry = payload.authorization_expires_at
    if expiry.tzinfo is None or expiry <= now or expiry > now + dt.timedelta(days=365):
        raise InvalidConfigurationError(
            "Authorization expiry must be timezone-aware, in the future, and within one year.",
            user_message="Authorization expiry must be in the future and within one year.",
        )
    try:
        first_run = next_cron_time(payload.cron_expression, payload.timezone, now)
    except ValueError as exc:
        raise InvalidConfigurationError(str(exc), user_message=str(exc)) from exc
    surface = AsmSurface(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        seeds=list(payload.seeds),
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        authorization_text=payload.authorization_text,
        authorization_expires_at=expiry,
        enabled=True,
        next_run_at=first_run,
        last_run_at=None,
        last_asset_count=0,
        last_new_count=0,
        last_error_code=None,
    )
    session.add(surface)
    await session.flush()
    return surface


async def list_surfaces(session: AsyncSession, principal: Principal) -> list[Any]:
    AsmSurface = _load_model()
    principal.require(Permission.ASSET_READ)
    rows = (
        await session.execute(
            select(AsmSurface)
            .where(AsmSurface.organization_id == principal.organization_id)
            .order_by(AsmSurface.name)
        )
    ).scalars().all()
    return [s for s in rows if s.organization_id == principal.organization_id]


async def get_surface(session: AsyncSession, principal: Principal, surface_id: uuid.UUID) -> Any:
    from app.core.errors import ResourceNotFoundError
    AsmSurface = _load_model()
    principal.require(Permission.ASSET_READ)
    row = (
        await session.execute(
            select(AsmSurface).where(
                AsmSurface.id == surface_id,
                AsmSurface.organization_id == principal.organization_id,
            )
        )
    ).scalar_one_or_none()
    if row is None or row.organization_id != principal.organization_id:
        raise ResourceNotFoundError("ASM surface not found")
    return row


async def update_surface(
    session: AsyncSession,
    principal: Principal,
    surface_id: uuid.UUID,
    payload: AsmSurfaceUpdateIn,
    settings: Settings,
) -> Any:
    AsmSurface = _load_model()
    principal.require(Permission.ASSESSMENT_CREATE)
    surface = await get_surface(session, principal, surface_id)
    now = utcnow()
    if payload.name is not None:
        surface.name = payload.name
    if payload.seeds is not None:
        if len(payload.seeds) > MAX_SURFACE_SEEDS:
            raise InvalidConfigurationError(
                f"A surface may have at most {MAX_SURFACE_SEEDS} seeds.",
                user_message=f"A surface may have at most {MAX_SURFACE_SEEDS} seeds.",
            )
        surface.seeds = list(payload.seeds)
    if payload.cron_expression is not None:
        try:
            surface.next_run_at = next_cron_time(
                payload.cron_expression, surface.timezone, now
            )
            surface.cron_expression = payload.cron_expression
        except ValueError as exc:
            raise InvalidConfigurationError(str(exc), user_message=str(exc)) from exc
    if payload.authorization_text is not None:
        surface.authorization_text = payload.authorization_text
    if payload.authorization_expires_at is not None:
        expiry = payload.authorization_expires_at
        if expiry.tzinfo is None or expiry <= now or expiry > now + dt.timedelta(days=365):
            raise InvalidConfigurationError(
                "Authorization expiry must be timezone-aware, in the future, and within one year.",
                user_message="Authorization expiry must be in the future and within one year.",
            )
        surface.authorization_expires_at = expiry
    if payload.enabled is not None:
        if payload.enabled:
            if surface.authorization_expires_at <= now:
                raise InvalidConfigurationError(
                    "ASM surface authorization has expired.",
                    user_message="Renew the authorization before resuming this surface.",
                )
            try:
                next_run = next_cron_time(surface.cron_expression, surface.timezone, now)
            except ValueError as exc:
                raise InvalidConfigurationError(
                    str(exc), user_message="The stored discovery schedule is invalid."
                ) from exc
            if next_run >= surface.authorization_expires_at:
                raise InvalidConfigurationError(
                    "Authorization expires before the next scheduled discovery.",
                    user_message="Renew the authorization before resuming this surface.",
                )
            surface.next_run_at = next_run
            surface.last_error_code = None
        surface.enabled = payload.enabled
    await session.flush()
    return surface


async def delete_surface(
    session: AsyncSession, principal: Principal, surface_id: uuid.UUID
) -> None:
    from app.core.errors import ResourceNotFoundError
    principal.require(Permission.ASSESSMENT_CREATE)
    surface = await get_surface(session, principal, surface_id)
    await session.delete(surface)


# ---------------------------------------------------------------------------
# Discovery execution
# ---------------------------------------------------------------------------


async def _upsert_assets_from_recon(
    session: AsyncSession,
    organization_id: uuid.UUID,
    surface_id: uuid.UUID,
    discovered: list[Any],
) -> tuple[int, int]:
    """Upsert discovered assets; return (total_upserted, new_count)."""
    from app.db.models.asset import Asset, AssetChange
    from app.scanners.recon_assets import DiscoveredAsset

    if not discovered:
        return 0, 0

    # Load existing assets for this tenant matching any discovered name
    names = {da.name for da in discovered}
    existing_rows = (
        await session.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.name.in_(names),
            )
        )
    ).scalars().all()
    # Tenant-isolation guard: discard any row that snuck past the WHERE clause
    existing: dict[tuple[str, int | None, str | None], Asset] = {
        (row.name, row.port, row.protocol): row
        for row in existing_rows
        if row.organization_id == organization_id
    }

    now = utcnow()
    upserted = 0
    new_count = 0

    surface_key = str(surface_id)
    for da in discovered[:MAX_ASSETS_PER_RUN]:
        asset_key = (da.name, da.port, da.protocol)
        existing_asset = existing.get(asset_key)
        if existing_asset is None:
            # Create new asset
            asset = Asset(
                id=uuid.uuid4(),
                organization_id=organization_id,
                name=da.name,
                asset_type=da.asset_type,
                ip_address=da.ip_address,
                port=da.port,
                protocol=da.protocol,
                service=da.service,
                technology=list(da.technology),
                http_title=da.http_title,
                http_status_code=da.http_status_code,
                tls_subject=da.tls_subject,
                internet_exposed=da.internet_exposed,
                status=AssetStatus.ACTIVE.value,
                criticality=Criticality.UNKNOWN.value,
                criticality_source=CriticalitySource.DEFAULT.value,
                risk_score=0.0,
                evidence={
                    **dict(da.evidence),
                    _ASM_SURFACE_LAST_SEEN: {surface_key: now.isoformat()},
                    _ASM_SURFACE_MISSES: {},
                },
                first_seen_at=now,
                last_seen_at=now,
                seen_in_assessments=[],
                groups=[],
                custom_fields={},
            )
            session.add(asset)
            await session.flush()  # get the id
            session.add(
                AssetChange(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    asset_id=asset.id,
                    assessment_id=None,
                    change_type="discovered",
                    changes={"source": "asm_discovery", "surface_id": str(surface_id)},
                )
            )
            existing[asset_key] = asset
            upserted += 1
            new_count += 1
        else:
            asset = existing_asset
            if asset.organization_id != organization_id:
                continue  # safety belt
            # Compute delta for trackable fields
            changes: dict[str, Any] = {}
            if asset.status != AssetStatus.ACTIVE.value:
                changes["status"] = {"old": asset.status, "new": AssetStatus.ACTIVE.value}
                asset.status = AssetStatus.ACTIVE.value
            for field in _TRACKABLE_FIELDS:
                new_val = getattr(da, field, None)
                old_val = getattr(asset, field, None)
                if new_val is not None and new_val != old_val:
                    changes[field] = {"old": old_val, "new": new_val}
                    setattr(asset, field, new_val)
            asset.last_seen_at = now
            evidence = dict(asset.evidence or {})
            per_surface_seen = dict(evidence.get(_ASM_SURFACE_LAST_SEEN) or {})
            per_surface_seen[surface_key] = now.isoformat()
            misses = dict(evidence.get(_ASM_SURFACE_MISSES) or {})
            misses.pop(surface_key, None)
            evidence[_ASM_SURFACE_LAST_SEEN] = per_surface_seen
            evidence[_ASM_SURFACE_MISSES] = misses
            asset.evidence = evidence
            if da.technology:
                asset.technology = list(da.technology)
            if changes:
                session.add(
                    AssetChange(
                        id=uuid.uuid4(),
                        organization_id=organization_id,
                        asset_id=asset.id,
                        assessment_id=None,
                        change_type="changed",
                        changes={"source": "asm_discovery", "surface_id": str(surface_id), "fields": changes},
                    )
                )
            upserted += 1

    return upserted, new_count


async def _reconcile_missing_surface_assets(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    surface_id: uuid.UUID,
    discovered: list[Any],
    now: dt.datetime,
) -> int:
    """Mark an ASM-owned asset unreachable only after two completed misses.

    Recon output can be incomplete, so a single missing observation is preserved as
    provenance rather than treated as evidence that an asset was removed.  We only call
    this after a successful, non-empty discovery run and only for assets previously
    observed by this same surface.
    """
    if not discovered:
        return 0
    surface_key = str(surface_id)
    seen_keys = {(item.name, item.port, item.protocol) for item in discovered}
    candidates = (
        await session.execute(
            select(Asset)
            .where(
                Asset.organization_id == organization_id,
                Asset.status == AssetStatus.ACTIVE.value,
            )
            .order_by(Asset.last_seen_at.desc().nullslast(), Asset.id)
            .limit(MAX_ASSETS_PER_RUN)
            .with_for_update()
        )
    ).scalars().all()
    surface_candidates = [
        asset
        for asset in candidates
        if isinstance((asset.evidence or {}).get(_ASM_SURFACE_LAST_SEEN), dict)
        and surface_key in (asset.evidence or {}).get(_ASM_SURFACE_LAST_SEEN, {})
    ]
    # A successful ReconFTW container can still complete only a subset of its passive
    # sources. Do not turn a partial inventory into mass "unreachable" drift: require
    # at least half of the surface's known active assets to be represented first.
    if surface_candidates and len(seen_keys) * 2 < len(surface_candidates):
        log.warning(
            "asm.drift_reconciliation_skipped_low_coverage",
            surface_id=surface_key,
            known=len(surface_candidates),
            observed=len(seen_keys),
        )
        return 0
    marked = 0
    for asset in surface_candidates:
        evidence = dict(asset.evidence or {})
        per_surface_seen = evidence.get(_ASM_SURFACE_LAST_SEEN)
        assert isinstance(per_surface_seen, dict)
        if (asset.name, asset.port, asset.protocol) in seen_keys:
            continue
        misses = dict(evidence.get(_ASM_SURFACE_MISSES) or {})
        prior = misses.get(surface_key, 0)
        count = prior + 1 if isinstance(prior, int) else 1
        misses[surface_key] = count
        evidence[_ASM_SURFACE_MISSES] = misses
        asset.evidence = evidence
        if count < _MISSING_CONFIRMATIONS:
            continue
        asset.status = AssetStatus.UNREACHABLE.value
        session.add(
            AssetChange(
                id=uuid.uuid4(),
                organization_id=organization_id,
                asset_id=asset.id,
                assessment_id=None,
                change_type="unreachable",
                changes={
                    "source": "asm_discovery",
                    "surface_id": surface_key,
                    "consecutive_misses": count,
                    "last_seen_from_surface": per_surface_seen[surface_key],
                    "observed_at": now.isoformat(),
                },
            )
        )
        marked += 1
    return marked


async def run_due_surfaces(
    session: AsyncSession,
    settings: Settings,
    *,
    now: dt.datetime | None = None,
    limit: int = _BATCH_LIMIT,
) -> int:
    """Run discovery for all surfaces whose next_run_at has passed.

    One surface per tenant per tick (fair scheduling). Uses ``SKIP LOCKED`` so
    multiple workers never double-run the same surface.
    """
    from app.db.enums import Role
    from app.db.models.asm import AsmSurface  # type: ignore[attr-defined]

    now = now or dt.datetime.now(dt.UTC)

    # Fair-schedule: one surface per tenant, ordered by next_run_at
    ranked = (
        select(
            AsmSurface.id.label("surface_id"),
            func.row_number()
            .over(
                partition_by=AsmSurface.organization_id,
                order_by=(AsmSurface.next_run_at, AsmSurface.id),
            )
            .label("tenant_rank"),
        )
        .where(
            AsmSurface.enabled.is_(True),
            AsmSurface.next_run_at <= now,
        )
        .subquery()
    )
    rows = (
        await session.execute(
            select(AsmSurface)
            .join(ranked, and_(ranked.c.surface_id == AsmSurface.id, ranked.c.tenant_rank == 1))
            .order_by(AsmSurface.next_run_at, AsmSurface.id)
            .limit(max(1, min(limit, 100)))
            .with_for_update(of=AsmSurface, skip_locked=True)
        )
    ).scalars().all()

    ran = 0
    for surface in rows:
        if surface.organization_id is None:
            continue  # defensive
        # Re-check authorization expiry at execution time (security requirement)
        if surface.authorization_expires_at <= now:
            surface.enabled = False
            surface.last_error_code = "authorization_expired"
            log.info("asm.surface_disabled_expired", surface_id=str(surface.id))
            continue

        # Load the creating operator to build a principal for capability checks
        role_raw = None
        if surface.created_by_id is not None:
            role_raw = (
                await session.execute(
                    select(Membership.role)
                    .join(User, User.id == Membership.user_id)
                    .join(Organization, Organization.id == Membership.organization_id)
                    .where(
                        Membership.organization_id == surface.organization_id,
                        Membership.user_id == surface.created_by_id,
                        Membership.accepted_at.is_not(None),
                        User.is_active.is_(True),
                        Organization.is_active.is_(True),
                    )
                )
            ).scalar_one_or_none()
        try:
            role = Role(role_raw) if role_raw is not None else None
        except ValueError:
            role = None
        if role is None:
            surface.enabled = False
            surface.last_error_code = "operator_inactive"
            log.info("asm.surface_disabled_no_operator", surface_id=str(surface.id))
            continue

        principal = Principal.for_worker(
            organization_id=surface.organization_id,
            user_id=surface.created_by_id,
            role=role,
        )

        # Schedule next run before attempting so a failure still advances the clock
        try:
            surface.next_run_at = next_cron_time(surface.cron_expression, surface.timezone, now)
        except ValueError:
            surface.enabled = False
            surface.last_error_code = "invalid_cron"
            continue

        try:
            upserted, new_count = await _run_surface_discovery(
                session, principal, surface, settings, now=now
            )
            surface.last_run_at = now
            surface.last_asset_count = upserted
            surface.last_new_count = new_count
            surface.last_error_code = None
            ran += 1
            log.info(
                "asm.surface_completed",
                surface_id=str(surface.id),
                upserted=upserted,
                new=new_count,
            )
        except CynuxError as exc:
            surface.last_error_code = exc.code
            log.warning("asm.surface_error", surface_id=str(surface.id), code=exc.code)
        except Exception as exc:
            surface.last_error_code = "internal_error"
            log.error(
                "asm.surface_exception",
                surface_id=str(surface.id),
                exc_type=type(exc).__name__,
            )

    return ran


async def _run_surface_discovery(
    session: AsyncSession,
    principal: Principal,
    surface: Any,
    settings: Settings,
    *,
    now: dt.datetime,
) -> tuple[int, int]:
    """Execute passive recon for one surface and merge results into the asset inventory.

    This runs ReconFTW in passive mode via the existing DockerRunner/sandbox path, then
    parses its output directory with :func:`app.scanners.recon_assets.parse_recon_output`
    and upserts the results into the asset table.

    A runner or container failure is surfaced to the schedule as a classified error. It
    must not be represented as an empty successful discovery, because that hides an
    operational outage and can corrupt drift interpretation.
    """
    import os
    import pathlib
    import tempfile

    from app.scanners.recon_assets import parse_recon_output
    from app.scanners.reconftw import ADAPTER as reconftw_adapter
    from app.scanners.base import ScannerRequest
    from app.scanners.sandbox import build_sandbox
    from app.db.enums import ScannerName

    seeds: list[str] = list(surface.seeds or [])
    if not seeds:
        return 0, 0

    with tempfile.TemporaryDirectory(prefix="asm-", dir=None) as tmp:
        work = pathlib.Path(tmp)
        out_dir = work / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        request = ScannerRequest(
            scanner=ScannerName.RECONFTW,
            targets=tuple(seeds),
            workdir=work,
            timeout_seconds=min(settings.scanner.timeout_recon, 3600),
            options={},
        )
        # Prepare config file before execution
        reconftw_adapter.prepare(request)
        try:
            from app.scanners.runner import DockerRunner
            sandbox = build_sandbox(reconftw_adapter, request, settings.scanner)
            runner = DockerRunner(settings.scanner)
            result = await runner.run(reconftw_adapter, request, sandbox)
        except Exception as exc:
            log.warning(
                "asm.recon_run_failed",
                surface_id=str(surface.id),
                exc_type=type(exc).__name__,
            )
            raise ScannerContainerError(
                "ASM passive discovery runner failed.",
                retryable=True,
            ) from None
        if not result.succeeded:
            log.warning(
                "asm.recon_run_incomplete",
                surface_id=str(surface.id),
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                cancelled=result.cancelled,
            )
            if result.timed_out:
                raise ScannerTimeoutError("ASM passive discovery timed out.")
            raise ScannerCrashError(
                "ASM passive discovery did not complete.",
                retryable=not result.cancelled,
            )

        discovered = parse_recon_output(out_dir, root_domain=seeds[0] if seeds else None)

    upserted, new_count = await _upsert_assets_from_recon(
        session,
        organization_id=surface.organization_id,
        surface_id=surface.id,
        discovered=discovered,
    )
    unreachable_count = await _reconcile_missing_surface_assets(
        session,
        organization_id=surface.organization_id,
        surface_id=surface.id,
        discovered=discovered,
        now=now,
    )
    if unreachable_count:
        log.info(
            "asm.assets_marked_unreachable",
            surface_id=str(surface.id),
            count=unreachable_count,
        )

    # Emit new-asset notification only when new assets were found
    if new_count > 0:
        seed_names = set(seeds)
        new_names = []
        # Fetch the most recently created assets for this surface from the change log
        recent = (
            await session.execute(
                select(Asset.name)
                .join(
                    AssetChange,
                    and_(
                        AssetChange.asset_id == Asset.id,
                        AssetChange.organization_id == Asset.organization_id,
                    ),
                )
                .where(
                    AssetChange.organization_id == surface.organization_id,
                    Asset.organization_id == surface.organization_id,
                    AssetChange.change_type == "discovered",
                    AssetChange.changes["surface_id"].astext == str(surface.id),
                    AssetChange.created_at >= now - dt.timedelta(minutes=5),
                )
                .order_by(Asset.name)
                .limit(20)
            )
        ).scalars().all()
        new_names = [n for n in recent if n not in seed_names]
        preview = ", ".join(new_names[:5]) or "new inventory records"
        suffix = ", and more" if new_count > 5 else ""
        try:
            await notification_service.dispatch(
                session,
                principal,
                event=NotificationEvent.NEW_ASSET,
                content=NotificationContent(
                    subject=f"{new_count} new asset{'s' if new_count != 1 else ''} discovered by ASM",
                    body=(
                        f"Continuous ASM discovered {new_count} new asset"
                        f"{'s' if new_count != 1 else ''} for surface '{surface.name}': "
                        f"{preview}{suffix}."
                    ),
                    link=f"{settings.public_base_url.rstrip('/')}/assets",
                ),
                settings=settings,
                resource_type="asm_surface",
                resource_id=str(surface.id),
            )
        except Exception as exc:
            log.warning(
                "asm.notification_failed",
                surface_id=str(surface.id),
                exc_type=type(exc).__name__,
            )

    return upserted, new_count


__all__ = [
    "create_surface",
    "delete_surface",
    "get_surface",
    "list_surfaces",
    "run_due_surfaces",
    "update_surface",
]
