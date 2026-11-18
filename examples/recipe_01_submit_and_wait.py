"""Recipe 1: Submit a file, wait for the final verdict, print what the analysis found.

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
import time
from pathlib import Path

from threatzone import AnalysisTimeoutError, ReportUnavailableError, ThreatZone
from threatzone.types import Submission


def wait_for_final(
    client: ThreatZone, uuid: str, *, timeout: float = 900, poll_interval: float = 5
) -> Submission:
    """Wait until every report is done and the platform stamps the final score.

    ``finalized`` is ``None`` on older servers and can stay ``False`` on a submission last
    updated more than 24 hours ago, so the timeout always ends the wait.
    """
    deadline = time.monotonic() + timeout
    submission = client.wait_for_completion(uuid, timeout=timeout, poll_interval=poll_interval)
    while submission.finalized is False and time.monotonic() < deadline:
        time.sleep(poll_interval)
        submission = client.get_submission(uuid)
    return submission


def print_findings(client: ThreatZone, uuid: str) -> None:
    """Print the behaviour verdict, the run notes, the key detections and the IoCs."""
    try:
        verdict = client.get_verdict(uuid)
        run = client.get_run(uuid)
    except ReportUnavailableError:
        print("No dynamic report for this submission.")
    else:
        print(f"Behaviour verdict: {verdict.tier} ({verdict.score}/100)")
        if verdict.summary:
            print(verdict.summary)
        for note in run.run_notes:
            print(f"Run note: {note.text}")

    rows = client.get_indicators(uuid, limit=100).items
    key_rows = [row for row in rows if row.in_verdict_chain] or sorted(
        rows, key=lambda row: row.score, reverse=True
    )[:5]
    for row in key_rows:
        print(f"[{row.level} {row.score:g}] {row.name} {', '.join(row.attack_codes)}")
        print(f"  {row.summary or row.description}")

    for ioc in client.get_iocs(uuid, tier="ioc", limit=100).items:
        print(f"IoC {ioc.type}: {ioc.value}")


def main(client: ThreatZone, sample_path: Path) -> Submission:
    """Submit a sample, wait for the final verdict, print the findings, return the submission."""
    created = client.create_sandbox_submission(
        sample_path,
        environment="w10_x64",
        private=True,
    )
    print(f"Created submission {created.uuid}")

    # --- Variant: let the server auto-select the environment ---
    # When automating across heterogeneous samples (.exe, .elf, .apk, ...), set
    # auto_select_environment=True and omit the `environment` kwarg. The server
    # routes the sample based on its detected extension.
    auto = client.create_sandbox_submission(
        sample_path,
        auto_select_environment=True,
        private=True,
    )
    print(f"Submission (auto-env): {auto.uuid}")

    try:
        final = wait_for_final(client, created.uuid)
    except AnalysisTimeoutError as exc:
        print(f"Still running after {exc.elapsed:.0f}s. UUID={exc.uuid}")
        raise

    print(f"Verdict: {final.level} ({final.score}/100)")
    for report in final.reports:
        print(f"  {report.type:<12} -> {report.status} (level={report.level})")
    print_findings(client, created.uuid)
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
