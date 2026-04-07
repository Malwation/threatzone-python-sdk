"""Recipe 7: Gracefully handle ReportUnavailableError when calling a dynamic endpoint.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_07_handle_report_unavailable.py <submission_uuid>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.types import ProcessesResponse


def main(client: ThreatZone, submission_uuid: str) -> ProcessesResponse | None:
    """Try to fetch processes; return None if dynamic report is unavailable."""
    try:
        processes = client.get_processes(submission_uuid)
    except ReportUnavailableError as exc:
        print(
            f"Dynamic report not available (code={exc.code}, "
            f"current_status={exc.current_status}, "
            f"available_reports={exc.available_reports})"
        )
        return None

    print(f"Got {processes.total} processes.")
    return processes


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python examples/recipe_07_handle_report_unavailable.py <submission_uuid>"
        )

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
