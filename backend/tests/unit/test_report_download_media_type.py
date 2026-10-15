"""Report downloads must preserve the selected machine-readable media type."""

from __future__ import annotations


def test_json_report_download_uses_application_json() -> None:
    from types import SimpleNamespace

    from app.api.v1.reports import _media_type
    from app.db.enums import ReportFormat

    assert _media_type(SimpleNamespace(format_enum=ReportFormat.JSON)) == "application/json"

