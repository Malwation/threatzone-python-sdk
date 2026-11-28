"""Recipe 17: Wait for the live sandbox view of a file submission.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_17_live_sandbox_view.py <submission_uuid>

2. Imported by tests/integration/test_examples.py, which runs main() against
   FakeThreatZoneAPI.

The link is a credential: anyone who has it can open the VM while the run is in
progress. This script prints only whether you got it, not the link itself.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone

from threatzone import ThreatZone
from threatzone.types import DynamicSession


def main(
    client: ThreatZone,
    submission_uuid: str,
    *,
    poll_interval: float = 5.0,
    timeout: float = 300.0,
) -> DynamicSession:
    """Poll the live view until the VM runs or the timeout passes; return the last state."""
    deadline = time.monotonic() + timeout
    session = client.get_dynamic_session(submission_uuid)
    while session.state != "running" and time.monotonic() < deadline:
        time.sleep(poll_interval)
        session = client.get_dynamic_session(submission_uuid)

    if session.state != "running":
        print(f"Live view not available (state={session.state}).")
        return session

    if session.expires_at is not None:
        ends = datetime.fromtimestamp(session.expires_at / 1000, tz=timezone.utc)
        print(f"Live view is up until {ends.isoformat()}.")
    if session.link is None:
        print("Only the submitter and the workspace admins get the link.")
    else:
        print("Got the live view link (session.link). Keep it secret.")
    return session


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python examples/recipe_17_live_sandbox_view.py <submission_uuid>")

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        main(client, sys.argv[1])
    finally:
        client.close()
