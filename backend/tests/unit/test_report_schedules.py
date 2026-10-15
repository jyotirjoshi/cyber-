"""Durable tenant-owned report schedule contracts."""

from __future__ import annotations


def test_report_schedule_owns_its_persisted_configuration_fields() -> None:
    """A schedule must match its migration instead of leaking fields to share grants."""
    from app.db.models.report import ReportSchedule, ReportShareLink

    schedule_columns = ReportSchedule.__table__.c
    share_columns = ReportShareLink.__table__.c
    assert {"name", "cron_expression", "recipients", "next_run_at"} <= {
        column.name for column in schedule_columns
    }
    assert "name" not in share_columns


def test_report_schedule_has_tenant_cron_and_delivery_metadata() -> None:
    from app.db.models.report import ReportSchedule

    columns = ReportSchedule.__table__.c
    assert {"organization_id", "assessment_id", "cron_expression", "timezone", "next_run_at"} <= {
        column.name for column in columns
    }


def test_report_schedule_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/report-schedules" in {route.path for route in api_router.routes}


def test_report_schedule_can_be_paused_without_deletion() -> None:
    from app.api.v1.reports import router

    assert "/report-schedules/{schedule_id}/pause" in {route.path for route in router.routes}


def test_report_schedule_can_be_resumed() -> None:
    from app.api.v1.reports import router

    assert "/report-schedules/{schedule_id}/resume" in {route.path for route in router.routes}


def test_report_schedule_lifecycle_has_audit_actions() -> None:
    from app.services.audit import AuditAction

    assert AuditAction.REPORT_SCHEDULE_CREATE == "report_schedule.create"
    assert AuditAction.REPORT_SCHEDULE_PAUSE == "report_schedule.pause"
    assert AuditAction.REPORT_SCHEDULE_RESUME == "report_schedule.resume"


def test_worker_report_schedule_runner_is_available() -> None:
    from app.services.report import run_due_report_schedules

    assert callable(run_due_report_schedules)


def test_report_schedule_delivery_link_uses_audited_api_path() -> None:
    import uuid

    from app.services.report import report_schedule_download_url

    assert report_schedule_download_url("https://cynux.example", uuid.UUID(int=1)) == (
        "https://cynux.example/api/v1/reports/00000000-0000-0000-0000-000000000001/download"
    )

