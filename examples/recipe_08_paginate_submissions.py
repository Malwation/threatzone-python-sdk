"""Recipe 8: Paginate through the submissions list.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_08_paginate_submissions.py [page] [limit]

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import ThreatZone
from threatzone.types import PaginatedSubmissions


def main(client: ThreatZone, page: int, limit: int) -> PaginatedSubmissions:
    """Fetch one page of submissions, print each item, return the envelope."""
    response = client.list_submissions(page=page, limit=limit)
    print(
        f"Page {page}/{response.total_pages}  "
        f"showing {len(response.items)} of {response.total} total"
    )
    for item in response.items:
        print(
            f"  {item.uuid}  {item.level:<10}  {item.filename or '-'}"
        )
    return response


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")
    page_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    limit_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, page_arg, limit_arg)
    finally:
        client.close()
