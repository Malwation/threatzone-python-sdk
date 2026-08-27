"""Flow — full URL submission lifecycle."""

from __future__ import annotations

import pytest

from threatzone import BadRequestError, ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    DevicePresetOption,
    Message,
    Submission,
    UrlAnalysisResponse,
    UrlAnalysisSession,
)


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


def test_url_analysis_report_carries_the_scoring_fields(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    report = sync_client.get_url_analysis(created.uuid)
    assert report.threat_score is not None
    assert report.risk_level == "Critical"
    assert report.verdict_provenance is not None
    assert report.verdict_provenance.raw_verdict == "malicious"
    assert report.impersonation_target is not None
    assert report.completeness is not None
    assert report.intel_detections[0].source == "urlhaus"
    assert report.scored_at is not None


def test_url_submission_records_the_session_options(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(
        target,
        safe_browsing=True,
        metafields={"timeout": 240, "device_preset": "68b0000000000000000000a1"},
        configurations={"networkConfig": "68b0000000000000000000bb"},
    )
    session = sync_client.get_url_analysis_session(created.uuid)
    assert isinstance(session, UrlAnalysisSession)
    assert session.state == "running"
    assert session.vnc_available is True
    assert session.link is not None
    assert session.session_config is not None
    assert session.session_config.device_preset_name == "iPhone 15 Pro"
    assert session.session_config.session_duration_seconds == 240
    assert session.session_config.network_config_id == "68b0000000000000000000bb"

    report = sync_client.get_url_analysis(created.uuid)
    assert report.metafields == {"timeout": 240, "device_preset": "68b0000000000000000000a1"}


def test_url_session_is_unavailable_before_it_starts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    session = sync_client.get_url_analysis_session(created.uuid)
    assert session.state == "unavailable"
    assert session.vnc_available is False
    assert session.link is None
    assert session.expired is True


def test_start_and_restart_the_url_session(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)

    started = sync_client.start_url_analysis_session(created.uuid)
    assert isinstance(started, Message)
    assert sync_client.get_url_analysis_session(created.uuid).state == "running"

    restarted = sync_client.restart_url_analysis_session(created.uuid)
    assert isinstance(restarted, Message)
    assert sync_client.get_url_analysis_session(created.uuid).vnc_available is True


def test_seeded_interactive_session_is_running(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_interactive_url_session(fake_api)
    created = sync_client.create_url_submission(target, safe_browsing=True)
    session = sync_client.get_url_analysis_session(created.uuid)
    assert session.state == "running"
    assert session.session_config is not None
    assert session.session_config.device_preset_name == "iPhone 15 Pro"


def test_session_endpoints_reject_a_file_submission(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    sha256 = scenarios.seed_malicious_pe(fake_api)
    submissions = sync_client.search_by_sha256(sha256)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_url_analysis_session(submissions[0].uuid)


def test_restart_url_analysis_report(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    result = sync_client.restart_url_analysis(created.uuid)
    assert "restart" in result.message


def test_url_media_list_with_the_source_filter(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    media = sync_client.list_media_files(created.uuid, source="url_analysis")
    assert len(media) >= 1
    assert media[0].kind == "screenshot"


def test_url_media_list_rejects_a_bad_source(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    with pytest.raises(BadRequestError):
        sync_client.list_media_files(created.uuid, source="static")


def test_device_preset_catalog(sync_client: ThreatZone) -> None:
    presets = sync_client.get_device_presets()
    assert all(isinstance(p, DevicePresetOption) for p in presets)
    assert any(p.default for p in presets)
    assert {p.category for p in presets} == {"desktop", "mobile"}
