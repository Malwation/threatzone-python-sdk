"""Flow — static-only submission lifecycle."""

from __future__ import annotations

import pytest

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import SignatureCheckResponse, StaticScanResponse, Submission


def test_static_submission_completes(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)
    assert final.is_complete()


def test_static_scan_report_reachable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    report = sync_client.get_static_scan_results(created.uuid)
    assert isinstance(report, StaticScanResponse)


def test_signature_check_reachable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    report = sync_client.get_signature_check_results(created.uuid)
    assert isinstance(report, SignatureCheckResponse)


def test_dynamic_gated_endpoints_409(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_processes(created.uuid)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_network_summary(created.uuid)


def test_cdr_gated_endpoint_409(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_cdr_results(created.uuid)


def test_yara_rules_visible_on_static(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    rules = sync_client.get_yara_rules(created.uuid)
    assert rules.total >= 0
