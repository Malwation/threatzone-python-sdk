"""Recipe 2: Submit a URL with an interactive session, wait, print the score.

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
import time

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.types import UrlAnalysisResponse

SESSION_POLL_ATTEMPTS = 30
SESSION_POLL_INTERVAL = 2.0


def wait_for_session_link(
    client: ThreatZone,
    uuid: str,
    *,
    attempts: int = SESSION_POLL_ATTEMPTS,
    interval: float = SESSION_POLL_INTERVAL,
) -> str | None:
    """Poll the interactive session until it runs. Return the viewer link."""
    for _ in range(attempts):
        session = client.get_url_analysis_session(uuid)
        if session.state == "running" and session.link is not None:
            return session.link
        if session.state in {"error", "finished"}:
            print(f"Session ended early: {session.state} ({session.failure_code})")
            return None
        if session.state == "queued":
            print(f"Session queued at position {session.queue_position}")
        if interval > 0:
            time.sleep(interval)
    return None


def main(client: ThreatZone, url: str) -> UrlAnalysisResponse:
    """Submit a URL, open a session, wait, then print the scored report."""
    presets = client.get_device_presets()
    mobile = next((p for p in presets if p.category == "mobile"), None)

    metafields: dict[str, object] = {"timeout": 240}
    if mobile is not None:
        metafields["device_preset"] = mobile.id
        print(f"Using device preset {mobile.name}")

    created = client.create_url_submission(
        url,
        private=True,
        safe_browsing=True,
        metafields=metafields,
    )
    print(f"Created URL submission {created.uuid}")

    link = wait_for_session_link(client, created.uuid, interval=0.0)
    if link is not None:
        print(f"Viewer:  {link}")

    final = client.wait_for_completion(created.uuid, timeout=300)

    try:
        report = client.get_url_analysis(final.uuid)
    except ReportUnavailableError as exc:
        print(f"URL analysis not ready: {exc.current_status}")
        raise

    print(f"URL:     {report.general_info.url}")
    print(f"Domain:  {report.general_info.domain}")
    print(f"Verdict: {report.level}")
    print(f"Score:   {report.threat_score} ({report.risk_level})")
    if report.impersonation_target is not None:
        target = report.impersonation_target
        print(f"Brand:   impersonates {target.brand_name} ({target.confidence} confidence)")
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
