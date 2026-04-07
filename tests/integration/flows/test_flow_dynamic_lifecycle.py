"""Flow — the full dynamic analysis lifecycle end to end."""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    ArtifactsResponse,
    IndicatorsResponse,
    IoCsResponse,
    NetworkSummary,
    OverviewSummary,
    ProcessesResponse,
    ProcessTreeResponse,
    YaraRulesResponse,
)


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_overview_summary_reachable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    summary = sync_client.get_overview_summary(uuid)
    assert isinstance(summary, OverviewSummary)


def test_processes_and_tree(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    procs = sync_client.get_processes(uuid)
    tree = sync_client.get_process_tree(uuid)
    assert isinstance(procs, ProcessesResponse)
    assert isinstance(tree, ProcessTreeResponse)


def test_indicators_iocs_yara_artifacts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    assert isinstance(sync_client.get_indicators(uuid), IndicatorsResponse)
    assert isinstance(sync_client.get_iocs(uuid), IoCsResponse)
    assert isinstance(sync_client.get_yara_rules(uuid), YaraRulesResponse)
    assert isinstance(sync_client.get_artifacts(uuid), ArtifactsResponse)


def test_network_endpoints_on_dynamic(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    summary = sync_client.get_network_summary(uuid)
    assert isinstance(summary, NetworkSummary)
    assert sync_client.get_network_threats(uuid)


def test_download_sample_and_pcap(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    with sync_client.download_sample(uuid) as dl:
        assert len(dl.read()) > 0
    with sync_client.download_pcap(uuid) as dl:
        assert len(dl.read()) > 0


def test_poll_count_records_polling(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    assert fake_api.poll_count(uuid) >= 1


def test_request_log_captures_post_and_get(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    _submit(fake_api, sync_client)
    methods = [r.method for r in fake_api.request_log]
    assert "POST" in methods
    assert "GET" in methods
