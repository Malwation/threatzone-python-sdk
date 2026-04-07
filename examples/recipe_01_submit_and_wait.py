"""Recipe 1: Submit a file, wait for analysis, print verdict.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_01_submit_and_wait.py <path/to/sample>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from threatzone import AnalysisTimeoutError, ThreatZone
from threatzone.types import Submission


def main(client: ThreatZone, sample_path: Path) -> Submission:
    """Submit a sample, poll until complete, print verdict, return final submission."""
    created = client.create_sandbox_submission(
        sample_path,
        environment="w10_x64",
        private=True,
    )
    print(f"Created submission {created.uuid}")

    try:
        final = client.wait_for_completion(created.uuid, timeout=900, poll_interval=5)
    except AnalysisTimeoutError as exc:
        print(f"Still running after {exc.elapsed:.0f}s. UUID={exc.uuid}")
        raise

    print(f"Verdict: {final.level}")
    for report in final.reports:
        print(f"  {report.type:<12} -> {report.status} (level={report.level})")
    return final


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python examples/recipe_01_submit_and_wait.py <sample_path>")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, Path(sys.argv[1]))
    finally:
        client.close()
