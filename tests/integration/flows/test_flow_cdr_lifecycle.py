"""Flow — CDR submission lifecycle."""

from __future__ import annotations

import pytest

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import CdrResponse, Submission


def test_cdr_submission_completes(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_cdr_document(fake_api)
    created = sync_client.create_cdr_submission(b"DOCX")
    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)


def test_cdr_report_returned(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_cdr_document(fake_api)
    created = sync_client.create_cdr_submission(b"DOCX")
    report = sync_client.get_cdr_results(created.uuid)
    assert isinstance(report, CdrResponse)


def test_cdr_result_downloadable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_cdr_document(fake_api)
    created = sync_client.create_cdr_submission(b"DOCX")
    with sync_client.download_cdr_result(created.uuid) as dl:
        payload = dl.read()
    assert len(payload) > 0


def test_dynamic_endpoints_unavailable_on_cdr(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_cdr_document(fake_api)
    created = sync_client.create_cdr_submission(b"DOCX")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_processes(created.uuid)
