"""Recipe 11: Build a flat counts dict from a submission's overview summary.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_11_daily_summary.py <submission_uuid>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ThreatZone


def main(client: ThreatZone, submission_uuid: str) -> dict[str, int]:
    """Return all the counts from get_overview_summary as a flat dict."""
    summary = client.get_overview_summary(submission_uuid)

    counts: dict[str, int] = {
        "indicators_total": summary.indicators.total,
        "indicators_malicious": summary.indicators.levels.malicious,
        "indicators_suspicious": summary.indicators.levels.suspicious,
        "indicators_benign": summary.indicators.levels.benign,
        "behavior_event_count": summary.behavior_event_count,
        "syscall_count": summary.syscall_count,
        "ioc_count": summary.ioc_count,
        "yara_rule_count": summary.yara_rule_count,
        "config_count": summary.config_count,
        "artifact_count": summary.artifact_count,
        "mitre_technique_count": summary.mitre_technique_count,
    }
    if summary.network is not None:
        counts["network_dns_count"] = summary.network.dns_count
        counts["network_http_count"] = summary.network.http_count
        counts["network_tcp_count"] = summary.network.tcp_count
        counts["network_udp_count"] = summary.network.udp_count
        counts["network_threat_count"] = summary.network.threat_count

    print(f"Submission {submission_uuid} summary:")
    for key, value in counts.items():
        print(f"  {key:<24} {value}")
    return counts


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python examples/recipe_11_daily_summary.py <submission_uuid>")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
