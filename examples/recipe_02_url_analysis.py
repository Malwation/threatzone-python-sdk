"""Recipe 2: Submit a URL, wait, print phishing findings.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_02_url_analysis.py <url>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.types import UrlAnalysisResponse


def main(client: ThreatZone, url: str) -> UrlAnalysisResponse:
    """Submit URL, wait, fetch URL analysis, print phishing-relevant fields."""
    created = client.create_url_submission(url, private=True)
    print(f"Created URL submission {created.uuid}")

    final = client.wait_for_completion(created.uuid, timeout=300)

    try:
        report = client.get_url_analysis(final.uuid)
    except ReportUnavailableError as exc:
        print(f"URL analysis not ready: {exc.current_status}")
        raise

    print(f"URL:     {report.general_info.url}")
    print(f"Domain:  {report.general_info.domain}")
    print(f"Verdict: {report.level}")
    if report.ip_info is not None:
        print(f"IP:      {report.ip_info.ip} ({report.ip_info.country})")
    if report.threat_analysis is not None and report.threat_analysis.blacklist:
        print("URL appears on at least one blacklist.")
    return report


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python examples/recipe_02_url_analysis.py <url>")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
