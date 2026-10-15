from __future__ import annotations

import pytest

from app.services.report_template import resolve_template_blocks, validate_template


def test_template_rejects_arbitrary_html_or_unknown_query() -> None:
    with pytest.raises(ValueError):
        validate_template({"blocks": [{"type": "html", "value": "<script>alert(1)</script>"}]})
    with pytest.raises(ValueError):
        validate_template({"blocks": [{"type": "table", "query": "raw_sql"}]})


def test_template_normalizes_only_allowlisted_blocks_and_queries() -> None:
    template = validate_template(
        {
            "blocks": [
                {"type": "title", "text": "Quarterly posture"},
                {"type": "metric", "query": "risk_summary", "label": "Open risk"},
                {"type": "page_break"},
            ]
        }
    )
    assert [block["type"] for block in template["blocks"]] == [
        "title",
        "metric",
        "page_break",
    ]


def test_template_rejects_javascript_urls_and_oversized_text() -> None:
    with pytest.raises(ValueError):
        validate_template({"blocks": [{"type": "branding", "logo_url": "javascript:alert(1)"}]})
    with pytest.raises(ValueError):
        validate_template({"blocks": [{"type": "narrative", "text": "x" * 20001}]})


def test_named_queries_resolve_without_expression_evaluation() -> None:
    blocks = resolve_template_blocks(
        {"blocks": [{"type": "metric", "query": "risk_summary"}]},
        {
            "summary": {"total": 14, "in_kev": 2},
            "operational_metrics": {"exposure_score": 61.5},
        },
    )
    assert blocks[0]["value"] == {
        "exposure_score": 61.5,
        "open_findings": 14,
        "known_exploited": 2,
    }
