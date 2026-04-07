"""Recipe 4: Download every artifact from a submission to disk.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_04_download_all_artifacts.py <submission_uuid> <out_dir>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from threatzone import ThreatZone


def main(client: ThreatZone, submission_uuid: str, out_dir: Path) -> int:
    """Download every artifact for the submission. Return the count saved."""
    out_dir.mkdir(parents=True, exist_ok=True)

    response = client.get_artifacts(submission_uuid)
    print(f"Found {response.total} artifacts.")

    saved = 0
    for artifact in response.items:
        target = out_dir / f"{artifact.hashes.sha256}_{artifact.filename}"
        with client.download_artifact(submission_uuid, artifact.id) as download:
            download.save(target)
        print(f"  [{artifact.type:<18}] {artifact.filename} -> {target}")
        saved += 1
    return saved


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 3:
        raise SystemExit(
            "Usage: python examples/recipe_04_download_all_artifacts.py <submission_uuid> <out_dir>"
        )

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1], Path(sys.argv[2]))
    finally:
        client.close()
