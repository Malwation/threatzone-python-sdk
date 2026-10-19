"""Flow — network list totals, packets, endpoints, host flows and the HTTPS capture."""

from __future__ import annotations

import pytest

from threatzone import (
    AsyncThreatZone,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    ThreatZone,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_list_pages_carry_the_total(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    first = sync_client.get_tcp_connections(uuid, limit=2)
    second = sync_client.get_tcp_connections(uuid, limit=2, skip=2)
    assert first.total_count == second.total_count == 3
    assert len(first) + len(second) == 3
    assert sync_client.get_network_summary(uuid).tcp_count == first.total_count
    assert sync_client.get_network_threats(uuid).total_count == 2


def test_rows_carry_the_sensor_fields(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    c2 = sync_client.get_tcp_connections(uuid)[0]
    assert c2.ptr_domain == "server-10.hosting.example.net"
    assert c2.source_ip is not None
    assert c2.packets_omitted == 0
    threat = sync_client.get_network_threats(uuid)[0]
    assert threat.severity_level == 1
    summary = sync_client.get_network_summary(uuid)
    assert summary.https_pcap_available is True
    assert summary.attribution_counts is not None
    assert summary.attribution_counts.tcp.sample == summary.tcp_count


def test_packets_return_the_payload_bytes(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    http_row = sync_client.get_http_requests(uuid)[0]
    [pair] = sync_client.get_http_request_packets(uuid, http_row.id).items
    assert pair.body is not None
    assert pair.body.data == b"bot=fake&token=FAKE-TOKEN-FOR-TESTS"
    tcp_row = sync_client.get_tcp_connections(uuid)[0]
    flow = sync_client.get_tcp_connection_packets(uuid, tcp_row.id)
    assert flow.destination_ip == tcp_row.destination_ip
    assert flow.items[0].data is not None
    assert flow.items[0].data.data == b"\x16\x03\x01\x00\x01"
    with pytest.raises(NotFoundError) as excinfo:
        sync_client.get_udp_connection_packets(uuid, tcp_row.id)
    assert excinfo.value.body is not None
    assert excinfo.value.body["code"] == "NETWORK_ROW_NOT_FOUND"


def test_endpoint_flows_page_with_the_cursor(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    endpoints = sync_client.get_network_endpoints(uuid, attribution=["sample"])
    assert endpoints.total == len(endpoints.items)
    c2 = endpoints.items[0]
    assert c2.alert_count == 2
    first = sync_client.get_network_host_flows(uuid, c2.key, attribution=["sample"], first=2)
    assert first.page_info.has_next_page is True
    assert sum(alert.count for alert in first.alerts) == c2.alert_count
    second = sync_client.get_network_host_flows(
        uuid, c2.key, attribution=["sample"], first=2, after=first.page_info.end_cursor
    )
    assert second.page_info.has_next_page is False
    flows = [*first.flows, *second.flows]
    assert {flow.protocol for flow in flows} == {"DNS", "HTTP", "TCP"}
    assert first.totals == second.totals
    assert sync_client.get_network_endpoints(uuid, limit=1).truncated is True
    with pytest.raises(BadRequestError):
        sync_client.get_network_host_flows(uuid, c2.key, after="not-a-cursor")


def test_unknown_host_returns_an_empty_page(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    page = sync_client.get_network_host_flows(uuid, "fe80::1%eth0")
    assert page.flows == []
    assert page.page_info.end_cursor is None


def test_https_pcap_download_follows_the_permission(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    with sync_client.download_https_pcap(uuid) as download:
        assert download.read() == b"FAKE-HTTPS-PCAP-BYTES"
    fake_api.mark_https_pcap_missing(uuid)
    with pytest.raises(NotFoundError):
        sync_client.download_https_pcap(uuid)
    fake_api.deny_download_report(uuid)
    with pytest.raises(PermissionDeniedError):
        sync_client.download_https_pcap(uuid)


async def test_async_network_routes(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    dns = await async_client.get_dns_queries(uuid, limit=1)
    assert len(dns) == 1
    assert dns.total_count == 2
    endpoints = await async_client.get_network_endpoints(uuid)
    page = await async_client.get_network_host_flows(uuid, endpoints.items[0].key)
    assert page.totals.tcp_flows == 1
    udp_row = (await async_client.get_udp_connections(uuid))[0]
    flow = await async_client.get_udp_connection_packets(uuid, udp_row.id)
    assert flow.protocol == "udp"
    download = await async_client.download_https_pcap(uuid)
    async with download:
        assert await download.read() == b"FAKE-HTTPS-PCAP-BYTES"
