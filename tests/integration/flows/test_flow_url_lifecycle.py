"""Flow — full URL submission lifecycle."""

from __future__ import annotations

import pytest

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Submission, UrlAnalysisResponse


def test_url_submission_roundtrip(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)
    assert final.type == "url"


def test_url_analysis_report_general_info(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    report = sync_client.get_url_analysis(created.uuid)
    assert isinstance(report, UrlAnalysisResponse)
    assert report.general_info.url == target


def test_url_screenshot_download(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    screenshot = sync_client.get_screenshot(created.uuid)
    assert isinstance(screenshot, bytes)
    assert len(screenshot) > 0


def test_url_media_list(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    media = sync_client.list_media_files(created.uuid)
    assert isinstance(media, list)
    assert len(media) >= 1


def test_dynamic_endpoints_unavailable_on_url(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_processes(created.uuid)
