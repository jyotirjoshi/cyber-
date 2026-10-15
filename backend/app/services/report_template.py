"""Safe, versioned, block-based enterprise report templates."""

from __future__ import annotations

from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.report import ReportTemplate
from app.db.repository import tenant_select
from app.schemas.report import ReportTemplateCreateIn
from app.services.context import Principal

ALLOWED_BLOCKS = frozenset(
    {"title", "narrative", "metric", "trend", "table", "chart", "compliance", "page_break", "branding"}
)
ALLOWED_QUERIES = frozenset(
    {
        "risk_summary",
        "severity_summary",
        "risk_trend",
        "mttr_summary",
        "sla_summary",
        "top_findings",
        "asset_risk",
        "compliance_summary",
        "assessment_coverage",
        "client_portfolio",
    }
)
_TEXT_FIELDS = frozenset({"text", "label", "heading", "caption", "footer"})


def validate_template(document: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document).difference({"blocks", "theme"}):
        raise ValueError("template must contain only blocks and an optional theme")
    blocks = document.get("blocks")
    if not isinstance(blocks, list) or not 1 <= len(blocks) <= 100:
        raise ValueError("template requires between 1 and 100 blocks")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(blocks):
        if not isinstance(raw, dict):
            raise ValueError(f"template block {index} must be an object")
        kind = raw.get("type")
        if kind not in ALLOWED_BLOCKS:
            raise ValueError(f"unsupported report block: {kind}")
        allowed = {"type", "query", "limit", "style", "logo_url", *_TEXT_FIELDS}
        if set(raw).difference(allowed):
            raise ValueError(f"report block {index} contains unsupported fields")
        query = raw.get("query")
        if query is not None and query not in ALLOWED_QUERIES:
            raise ValueError(f"unsupported saved report query: {query}")
        if kind in {"metric", "trend", "table", "chart", "compliance"} and query is None:
            raise ValueError(f"{kind} block requires a saved query")
        item: dict[str, Any] = {"type": kind}
        for field in _TEXT_FIELDS:
            value = raw.get(field)
            if value is not None:
                if not isinstance(value, str) or len(value) > 20_000:
                    raise ValueError(f"block {field} must be bounded text")
                item[field] = value
        if query is not None:
            item["query"] = query
        if "limit" in raw:
            limit = raw["limit"]
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
                raise ValueError("block limit must be between 1 and 500")
            item["limit"] = limit
        if "style" in raw:
            if raw["style"] not in {"default", "compact", "emphasis", "muted"}:
                raise ValueError("unsupported block style")
            item["style"] = raw["style"]
        if "logo_url" in raw:
            logo = raw["logo_url"]
            parsed = urlparse(logo) if isinstance(logo, str) else None
            if parsed is None or parsed.scheme != "https" or not parsed.hostname or len(logo) > 2048:
                raise ValueError("branding logo must be a bounded HTTPS URL")
            item["logo_url"] = logo
        normalized.append(item)
    theme = document.get("theme", {})
    if not isinstance(theme, dict) or set(theme).difference({"primary_color", "accent_color", "company_name"}):
        raise ValueError("unsupported report theme")
    for color in (theme.get("primary_color"), theme.get("accent_color")):
        if color is not None and (
            not isinstance(color, str)
            or len(color) != 7
            or not color.startswith("#")
            or any(char not in "0123456789abcdefABCDEF" for char in color[1:])
        ):
            raise ValueError("theme colors must be six-digit hex values")
    company_name = theme.get("company_name")
    if company_name is not None and (not isinstance(company_name, str) or len(company_name) > 255):
        raise ValueError("company name is too long")
    return {"blocks": normalized, "theme": deepcopy(theme)}


def resolve_template_blocks(
    definition: dict[str, Any], context: dict[str, Any]
) -> list[dict[str, Any]]:
    """Resolve only named, bounded context projections; never evaluate expressions."""
    validated = validate_template(definition)
    summary = context.get("summary") or {}
    operational = context.get("operational_metrics") or {}
    query_values: dict[str, Any] = {
        "risk_summary": {
            "exposure_score": operational.get("exposure_score"),
            "open_findings": summary.get("total"),
            "known_exploited": summary.get("in_kev"),
        },
        "severity_summary": summary.get("by_severity") or {},
        "risk_trend": {
            "current": operational.get("exposure_score"),
            "previous": operational.get("previous_exposure_score"),
            "delta": operational.get("exposure_delta"),
        },
        "mttr_summary": {"days": operational.get("mean_time_to_remediate_days")},
        "sla_summary": operational.get("sla") or {},
        "top_findings": list(context.get("findings") or []),
        "asset_risk": list(context.get("assets") or []),
        "compliance_summary": context.get("compliance") or {},
        "assessment_coverage": {
            "degradations": list(context.get("degradations") or []),
            "asset_count": context.get("asset_count"),
        },
        "client_portfolio": list(context.get("client_portfolio") or []),
    }
    resolved: list[dict[str, Any]] = []
    for block in validated["blocks"]:
        item = dict(block)
        query = item.get("query")
        if query:
            value = query_values[query]
            if isinstance(value, list):
                value = value[: int(item.get("limit", 50))]
            item["value"] = value
        resolved.append(item)
    return resolved


async def create_template(
    session: AsyncSession, principal: Principal, payload: ReportTemplateCreateIn
) -> ReportTemplate:
    principal.require(Permission.REPORT_GENERATE)
    name = payload.name.strip()
    current = await session.scalar(
        select(func.max(ReportTemplate.version)).where(
            ReportTemplate.organization_id == principal.organization_id,
            ReportTemplate.name == name,
        )
    )
    previous = list(
        (
            await session.scalars(
                tenant_select(ReportTemplate, principal.organization_id).where(
                    ReportTemplate.name == name,
                    ReportTemplate.is_active.is_(True),
                )
            )
        ).all()
    )
    for row in previous:
        row.is_active = False
    row = ReportTemplate(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=name,
        version=int(current or 0) + 1,
        description=payload.description.strip() if payload.description else None,
        definition=validate_template(payload.definition),
        is_active=True,
    )
    session.add(row)
    await session.flush()
    return row


async def get_template(
    session: AsyncSession, principal: Principal, template_id
) -> ReportTemplate:
    row = await session.scalar(
        tenant_select(ReportTemplate, principal.organization_id).where(
            ReportTemplate.id == template_id
        )
    )
    if row is None:
        raise ResourceNotFoundError("Report template not found")
    return row


async def list_templates(
    session: AsyncSession, principal: Principal
) -> list[ReportTemplate]:
    principal.require(Permission.REPORT_READ)
    rows = await session.scalars(
        tenant_select(ReportTemplate, principal.organization_id).order_by(
            ReportTemplate.name, ReportTemplate.version.desc()
        )
    )
    return list(rows.all())


__all__ = ["ALLOWED_BLOCKS", "ALLOWED_QUERIES", "create_template", "get_template", "list_templates", "resolve_template_blocks", "validate_template"]
