"""Recipe 5: Find prior submissions by SHA-256.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_05_search_by_sha256.py <sha256>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ThreatZone
from threatzone.types import Submission


def main(client: ThreatZone, sha256: str) -> list[Submission]:
    """Search workspace submissions by SHA-256, print each, return the list."""
    matches = client.search_by_sha256(sha256)
    if not matches:
        print(f"No submissions found for {sha256}.")
        return matches

    for submission in matches:
        print(
            f"{submission.uuid}  level={submission.level}  type={submission.type}  "
            f"created={submission.created_at.isoformat()}"
        )
    return matches


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python examples/recipe_05_search_by_sha256.py <sha256>")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
