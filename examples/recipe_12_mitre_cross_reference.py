"""Recipe 12: Cross-reference MITRE techniques against indicator attack codes.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_12_mitre_cross_reference.py <submission_uuid>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ThreatZone

PAGE_LIMIT = 100


def main(client: ThreatZone, submission_uuid: str) -> dict[str, list[str]]:
    """Return MITRE techniques, indicator attack codes, and their intersection."""
    mitre = client.get_mitre_techniques(submission_uuid)
    mitre_techniques: list[str] = list(mitre.techniques)

    indicator_attack_codes: list[str] = []
    page = 1
    while True:
        response = client.get_indicators(submission_uuid, page=page, limit=PAGE_LIMIT)
        if not response.items:
            break
        for indicator in response.items:
            for code in indicator.attack_codes:
                if code not in indicator_attack_codes:
                    indicator_attack_codes.append(code)
        if len(response.items) < PAGE_LIMIT:
            break
        page += 1

    intersection = sorted(set(mitre_techniques) & set(indicator_attack_codes))

    print(f"MITRE techniques:        {len(mitre_techniques)}")
    print(f"Indicator attack codes:  {len(indicator_attack_codes)}")
    print(f"Intersection:            {len(intersection)}")
    for code in intersection:
        print(f"  {code}")

    return {
        "indicator_attack_codes": indicator_attack_codes,
        "mitre_techniques": mitre_techniques,
        "intersection": intersection,
    }


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python examples/recipe_12_mitre_cross_reference.py <submission_uuid>"
        )

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
