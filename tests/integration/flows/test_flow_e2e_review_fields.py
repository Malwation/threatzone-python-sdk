"""Flow — the fake API returns the fields of the current Public API contract."""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_network_rows_carry_outcomes(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    assert {row.connect_outcome for row in sync_client.get_tcp_connections(uuid)} == {"established"}
    assert all(row.answered for row in sync_client.get_dns_queries(uuid))


def test_mitre_carries_the_catalog_version(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    mitre = sync_client.get_mitre_techniques(uuid)
    assert (mitre.attack_version, mitre.domain) == ("20.0", "enterprise")
    assert mitre.items and all(item.attempted is False for item in mitre.items)


def test_indicator_rows_carry_the_engine(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    assert {row.source for row in sync_client.get_indicators(uuid).items} == {"dynamic_scan"}


def test_url_list_item_has_url_and_no_file_fields(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_phishing_url(fake_api, url="https://phishing.example.com/login")
    created = sync_client.create_url_submission("https://phishing.example.com/login")
    item = next(i for i in sync_client.list_submissions().items if i.uuid == created.uuid)
    assert (item.url, item.filename, item.sha256) == (
        "https://phishing.example.com/login",
        None,
        None,
    )


def test_me_carries_machine_readable_plan_fields(sync_client: ThreatZone) -> None:
    me = sync_client.get_user_info()
    assert me.plan.starts_at is not None
    assert me.plan.file_limits.file_size_bytes == 104857600
    assert me.modules[0].ends_at is not None
