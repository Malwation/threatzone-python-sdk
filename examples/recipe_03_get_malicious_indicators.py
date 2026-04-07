"""Recipe 3: Get all malicious indicators for a submission.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_03_get_malicious_indicators.py <submission_uuid>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ThreatZone
from threatzone.types import Indicator

PAGE_LIMIT = 100


def main(client: ThreatZone, submission_uuid: str) -> list[Indicator]:
    """Walk every malicious indicator page and return them as a flat list."""
    collected: list[Indicator] = []
    page = 1
    while True:
        response = client.get_indicators(
            submission_uuid,
            level="malicious",
            page=page,
            limit=PAGE_LIMIT,
        )
        if not response.items:
            break
        collected.extend(response.items)
        for indicator in response.items:
            attack = ", ".join(indicator.attack_codes) or "-"
            print(f"[{indicator.score:>3}] {indicator.name} ({indicator.category}) attack={attack}")
        if len(response.items) < PAGE_LIMIT:
            break
        page += 1

    print(f"Total malicious indicators: {len(collected)}")
    return collected


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python examples/recipe_03_get_malicious_indicators.py <submission_uuid>"
        )

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
