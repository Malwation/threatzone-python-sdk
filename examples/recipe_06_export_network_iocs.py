"""Recipe 6: Export network IoCs (domains, IPs, URLs) for a submission.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_06_export_network_iocs.py <submission_uuid>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ThreatZone


def main(client: ThreatZone, submission_uuid: str) -> dict[str, list[str]]:
    """Collect domains, IPs and URLs observed by the sandbox."""
    summary = client.get_network_summary(submission_uuid)
    print(
        f"DNS={summary.dns_count} HTTP={summary.http_count} "
        f"TCP={summary.tcp_count} UDP={summary.udp_count} "
        f"threats={summary.threat_count} pcap={summary.pcap_available}"
    )

    domains: list[str] = []
    ips: list[str] = []
    urls: list[str] = []

    for dns in client.get_dns_queries(submission_uuid):
        if dns.host and dns.host not in domains:
            domains.append(dns.host)

    for http in client.get_http_requests(submission_uuid):
        if http.host and http.host not in domains:
            domains.append(http.host)
        if http.ip and http.ip not in ips:
            ips.append(http.ip)
        urls.append(f"http://{http.host}:{http.port}")

    for conn in client.get_tcp_connections(submission_uuid):
        if conn.destination_ip and conn.destination_ip not in ips:
            ips.append(conn.destination_ip)

    result: dict[str, list[str]] = {"domains": domains, "ips": ips, "urls": urls}
    print(f"Collected {len(domains)} domains, {len(ips)} IPs, {len(urls)} URLs")
    return result


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python examples/recipe_06_export_network_iocs.py <submission_uuid>"
        )

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
