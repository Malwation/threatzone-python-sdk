"""Recipe 10: Use the AsyncThreatZone client.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_10_async_client.py <path/to/sample>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from threatzone import AnalysisTimeoutError, AsyncThreatZone
from threatzone.types import Submission


async def main(client: AsyncThreatZone, sample_path: Path) -> Submission:
    """Async version of recipe 1: submit, wait, return final submission."""
    created = await client.create_sandbox_submission(
        sample_path,
        environment="w10_x64",
        private=True,
    )
    print(f"Created submission {created.uuid}")

    try:
        final = await client.wait_for_completion(created.uuid, timeout=900, poll_interval=5)
    except AnalysisTimeoutError as exc:
        print(f"Timed out after {exc.elapsed:.0f}s")
        raise

    print(f"Verdict: {final.level}")
    return final


async def _run(api_key: str, base_url: str, sample_path: Path) -> None:
    client = AsyncThreatZone(api_key=api_key, base_url=base_url)
    try:
        await main(client, sample_path)
    finally:
        await client.close()


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python examples/recipe_10_async_client.py <sample_path>")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")
    asyncio.run(_run(api_key, base_url, Path(sys.argv[1])))
