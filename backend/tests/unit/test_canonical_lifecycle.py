"""Canonical lifecycle decisions must not mistake partial syncs for remediation."""

from app.services.canonical_lifecycle import next_status


def test_first_observation_is_new() -> None:
    assert next_status(None, ["open"], complete=True, consecutive_absences=0) == "new"


def test_open_observation_reopens_closed_finding() -> None:
    assert next_status("closed", ["open"], complete=True, consecutive_absences=0) == "reopened"


def test_fixed_source_is_mitigated_until_retest() -> None:
    assert next_status("open", ["fixed"], complete=True, consecutive_absences=0) == "mitigated"


def test_partial_or_first_missing_scan_cannot_close() -> None:
    assert next_status("open", [], complete=False, consecutive_absences=3) == "open"
    assert next_status("open", [], complete=True, consecutive_absences=1) == "open"


def test_second_complete_missing_scan_closes() -> None:
    assert next_status("open", [], complete=True, consecutive_absences=2) == "closed"
    assert next_status("open", ["absent"], complete=True, consecutive_absences=2) == "closed"


def test_analyst_disposition_is_not_overwritten_by_sync() -> None:
    assert next_status("accepted_risk", ["open"], complete=True, consecutive_absences=0) == "accepted_risk"
    assert next_status("false_positive", [], complete=True, consecutive_absences=2) == "false_positive"
