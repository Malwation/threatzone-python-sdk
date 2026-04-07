"""Recipe 07 — handle ``ReportUnavailableError``.

Mirrors `docs/RECIPES.md#7-handle-the-reportunavailableerror-exception`.
"""

from __future__ import annotations

import pytest

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios


def test_static_only_submission_raises_on_dynamic_endpoint(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Dynamic-gated endpoints 409 on a static-only submission."""
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_processes(created.uuid)
    assert exc_info.value.code == "DYNAMIC_REPORT_UNAVAILABLE"


def test_error_carries_required_and_available_reports(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """The typed exception exposes ``required_report`` and ``available_reports``."""
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_processes(created.uuid)

    err = exc_info.value
    assert err.required_report == "dynamic"
    assert "static" in err.available_reports
    assert err.submission_uuid == created.uuid


def test_cdr_report_unavailable_on_plain_sandbox(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A sandbox submission has no CDR report and surfaces a 409."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_cdr_results(created.uuid)
    assert exc_info.value.code == "CDR_REPORT_UNAVAILABLE"


def test_static_report_unavailable_on_url_submission(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """URL submissions have no static report."""
    scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission("https://phishing.example.com")

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_static_scan_results(created.uuid)
    assert exc_info.value.code == "STATIC_REPORT_UNAVAILABLE"


def test_report_unavailable_is_status_code_409(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """``ReportUnavailableError`` is always HTTP 409."""
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_network_summary(created.uuid)
    assert exc_info.value.status_code == 409
