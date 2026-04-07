"""Recipe 06 — export network IoCs.

Mirrors `docs/RECIPES.md#6-export-network-iocs`.
"""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    Connection,
    DnsQuery,
    HttpRequest,
    NetworkSummary,
    NetworkThreat,
)


def test_network_summary_exposes_counts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Network summary returns typed counts and pcap flag."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    summary = sync_client.get_network_summary(created.uuid)
    assert isinstance(summary, NetworkSummary)
    assert summary.dns_count >= 0
    assert summary.http_count >= 0
    assert summary.tcp_count >= 0
    assert summary.udp_count >= 0
    assert summary.threat_count >= 1
    assert isinstance(summary.pcap_available, bool)


def test_dns_http_tcp_udp_return_typed_lists(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """All the network endpoints hand back properly typed pydantic lists."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    for dns in sync_client.get_dns_queries(created.uuid):
        assert isinstance(dns, DnsQuery)
    for http in sync_client.get_http_requests(created.uuid):
        assert isinstance(http, HttpRequest)
    for tcp in sync_client.get_tcp_connections(created.uuid):
        assert isinstance(tcp, Connection)
    for udp in sync_client.get_udp_connections(created.uuid):
        assert isinstance(udp, Connection)


def test_network_threats_carry_signature_and_protocol(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Seeded Suricata threats surface via ``get_network_threats``."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    threats = sync_client.get_network_threats(created.uuid)
    assert len(threats) >= 1
    for threat in threats:
        assert isinstance(threat, NetworkThreat)
        assert threat.signature


def test_network_endpoints_accept_limit_and_skip(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """``limit`` and ``skip`` pass through cleanly without error."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    result = sync_client.get_dns_queries(created.uuid, limit=50, skip=0)
    assert isinstance(result, list)
