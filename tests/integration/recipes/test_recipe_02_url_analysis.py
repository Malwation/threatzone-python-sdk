"""Recipe 02 — submit a URL and pull the URL analysis report.

Mirrors `docs/RECIPES.md#2-submit-a-url-and-get-the-url-analysis-report`.
"""

from __future__ import annotations

import pytest

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Submission, UrlAnalysisResponse


def test_submit_url_and_fetch_analysis(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Happy path: create URL submission, wait, and fetch the URL analysis."""
    target = scenarios.seed_phishing_url(fake_api)

    created = sync_client.create_url_submission(target)
    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)

    report = sync_client.get_url_analysis(final.uuid)
    assert isinstance(report, UrlAnalysisResponse)
    assert report.general_info.url == target


def test_url_submission_is_typed_url(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """A URL submission has ``type='url'`` and a populated ``url`` field."""
    target = "https://malicious-link.test/login"
    fake_api.register_url_analysis(url=target, verdict="malicious")

    created = sync_client.create_url_submission(target)
    detail = sync_client.get_submission(created.uuid)
    assert detail.type == "url"
    assert detail.url == target
    assert detail.file is None


def test_url_analysis_contains_phishing_verdict(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A seeded malicious URL has a non-benign verdict in the analysis report."""
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)

    report = sync_client.get_url_analysis(created.uuid)
    assert report.level in {"suspicious", "malicious"}


def test_url_analysis_on_file_submission_raises_409(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Calling ``get_url_analysis`` on a file submission yields a 409."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE-bytes")

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_url_analysis(created.uuid)
    assert exc_info.value.code == "URL_ANALYSIS_REPORT_UNAVAILABLE"
