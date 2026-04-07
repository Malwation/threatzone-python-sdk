# Threat.Zone Python SDK Recipes

Self-contained, copy-pasteable examples. All recipes assume the following boilerplate:

```python
from threatzone import ThreatZone

client = ThreatZone(api_key="<your-api-key>")
```

## Table of contents

1. [Submit a file and wait for completion](#1-submit-a-file-and-wait-for-completion)
2. [Submit a URL and get the URL analysis report](#2-submit-a-url-and-get-the-url-analysis-report)
3. [Get all malicious indicators for a submission](#3-get-all-malicious-indicators)
4. [Download all artifacts from a submission](#4-download-all-artifacts)
5. [Search submissions by SHA256](#5-search-by-sha256)
6. [Export network IoCs for a submission](#6-export-network-iocs)
7. [Handle the ReportUnavailableError exception](#7-handle-the-reportunavailableerror-exception)
8. [Paginate through a large list](#8-paginate-through-a-large-list)
9. [Discriminate errors by their `code` field](#9-discriminate-errors-by-their-code-field)
10. [Use the async client](#10-use-the-async-client)
11. [Build a daily report summary](#11-build-a-daily-report-summary)
12. [Cross-reference MITRE techniques with indicators](#12-cross-reference-mitre-techniques-with-indicators)

---

### 1. Submit a file and wait for completion

**Goal.** Upload a binary for sandbox analysis, poll until every report reaches a terminal
state, and print the verdict.

```python
from pathlib import Path

from threatzone import AnalysisTimeoutError, ThreatZone

def submit_and_wait(sample: Path) -> None:
    with ThreatZone() as client:
        created = client.create_sandbox_submission(
            sample,
            environment="w10_x64",
            private=True,
        )
        print(f"Created submission {created.uuid}")

        try:
            final = client.wait_for_completion(
                created.uuid,
                timeout=900,
                poll_interval=10,
            )
        except AnalysisTimeoutError as exc:
            print(f"Still running after {exc.elapsed:.0f}s. UUID={exc.uuid}")
            return

        print(f"Verdict: {final.level}")
        for report in final.reports:
            print(f"  {report.type:<12} -> {report.status} (level={report.level})")

submit_and_wait(Path("./sample.exe"))
```

**Notes.**

- `wait_for_completion()` polls `GET /submissions/:uuid` and checks
  `submission.is_complete()`, which returns `True` only when **every** report has reached
  `completed` or `error`. If you only need dynamic analysis, branch on
  `submission.reports` yourself.
- Use `create_static_submission()` for static-only analysis, `create_cdr_submission()` for
  CDR sanitization, and `create_open_in_browser_submission(url=...)` for
  URL + browser dynamic analysis.
- The `environment` key comes from `client.get_environments()`.

---

### 2. Submit a URL and get the URL analysis report

**Goal.** Analyse a suspicious URL and pull the full URL analysis report
(general info, IP geo, DNS records, WHOIS, TLS cert, threat intelligence).

```python
from threatzone import ReportUnavailableError, ThreatZone

def analyse_url(url: str) -> None:
    with ThreatZone() as client:
        created = client.create_url_submission(url, private=True)
        final = client.wait_for_completion(created.uuid, timeout=300)

        try:
            report = client.get_url_analysis(final.uuid)
        except ReportUnavailableError as exc:
            print(f"URL analysis not ready: {exc.current_status}")
            return

        print(f"URL:       {report.general_info.url}")
        print(f"Domain:    {report.general_info.domain}")
        print(f"Title:     {report.general_info.website_title}")
        print(f"Verdict:   {report.level}")

        if report.ip_info is not None:
            print(f"IP:        {report.ip_info.ip} ({report.ip_info.country})")
            print(f"ISP:       {report.ip_info.isp}")
            print(f"Verdict:   {report.ip_info.threat_status.verdict}")

        if report.ssl_certificate is not None:
            print(f"TLS issuer: {report.ssl_certificate.issuer}")
            print(f"TLS valid until: {report.ssl_certificate.expires_at}")

        for dns in report.dns_records:
            print(f"DNS {dns.type}: {', '.join(dns.records)}")

        if report.threat_analysis is not None and report.threat_analysis.blacklist:
            print("URL appears on at least one blacklist.")

analyse_url("https://example-phish.test/login")
```

**Notes.**

- `screenshot.available` is `True` when a page screenshot is available. Fetch the bytes
  via `client.get_screenshot(uuid)`.
- `whois` and `ssl_certificate` are both `Optional` &mdash; always null-check.
- Use `create_open_in_browser_submission(url, environment="w10_x64")` instead if you
  need the full dynamic + browser capture on top of the URL analysis.

---

### 3. Get all malicious indicators

**Goal.** Stream every indicator with severity `malicious` and print the MITRE technique
IDs it maps to.

```python
from threatzone import ThreatZone

def dump_malicious_indicators(submission_uuid: str) -> None:
    with ThreatZone() as client:
        page = 1
        while True:
            response = client.get_indicators(
                submission_uuid,
                level="malicious",
                page=page,
                limit=100,
            )
            if not response.items:
                break

            for indicator in response.items:
                attack = ", ".join(indicator.attack_codes) or "-"
                pids = ", ".join(str(pid) for pid in indicator.pids) or "-"
                print(f"[{indicator.score:>3}] {indicator.name}")
                print(f"    category: {indicator.category}")
                print(f"    attack:   {attack}")
                print(f"    pids:     {pids}")

            if len(response.items) < 100:
                break
            page += 1

        print(f"Rollup: {response.levels.malicious} malicious, "
              f"{response.levels.suspicious} suspicious, "
              f"{response.levels.benign} benign")

dump_malicious_indicators("00000000-0000-0000-0000-000000000000")
```

**Notes.**

- Filter by MITRE technique with `attack_code="T1055"`, or by process id with `pid=1508`.
- `levels` reflects **filtered** counts, not the unfiltered totals. Call without `level`
  if you need the total rollup.
- Endpoint is dynamic-gated &mdash; wrap the call in
  [recipe 7](#7-handle-the-reportunavailableerror-exception) to handle static-only submissions.

---

### 4. Download all artifacts

**Goal.** Enumerate every artifact on a completed submission and save each to disk, keyed
by its SHA-256.

```python
from pathlib import Path

from threatzone import ThreatZone

def download_artifacts(submission_uuid: str, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)

    with ThreatZone() as client:
        response = client.get_artifacts(submission_uuid)
        print(f"Found {response.total} artifacts.")

        for artifact in response.items:
            out = target_dir / f"{artifact.hashes.sha256}_{artifact.filename}"
            with client.download_artifact(submission_uuid, artifact.id) as download:
                download.save(out)
            print(f"  [{artifact.type:<18}] {artifact.filename} -> {out}")

download_artifacts(
    "00000000-0000-0000-0000-000000000000",
    Path("./artifacts"),
)
```

**Notes.**

- `artifact.hashes.sha256` is the canonical SHA-256 &mdash; the legacy flat
  `artifact.sha256` field is gone.
- `DownloadResponse` is a context manager; always use `with` so the underlying HTTP stream
  is closed on every path, including exceptions.
- Very large artifacts stream in 64KB chunks (no buffering in memory). Use
  `download.iter_bytes()` if you need manual chunk-by-chunk processing.

---

### 5. Search by SHA256

**Goal.** Given a hash you pulled from an IOC feed, find every submission in your
workspace that ever analysed that file.

```python
from threatzone import ThreatZone

def find_by_sha256(sha256: str) -> None:
    with ThreatZone() as client:
        matches = client.search_by_sha256(sha256)
        if not matches:
            print(f"No submissions found for {sha256}.")
            return

        for submission in matches:
            print(f"{submission.uuid}  level={submission.level}  "
                  f"type={submission.type}  created={submission.created_at.isoformat()}")

find_by_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
```

**Notes.**

- `search_by_sha256()` is a workspace-scoped search. Private submissions in other
  workspaces are not returned.
- If you want to search across a broader hash list, use `list_submissions(sha256=...)`
  instead &mdash; it shares the same workspace scoping but supports pagination.
- The legacy `search_by_hash()` method has been **removed**. Use `search_by_sha256()`.

---

### 6. Export network IoCs

**Goal.** Produce a flat, SIEM-friendly list of every network IoC the sandbox observed:
DNS queries, HTTP hosts, Suricata alerts.

```python
from dataclasses import dataclass
from typing import List

from threatzone import ThreatZone

@dataclass
class NetIoc:
    kind: str
    value: str
    context: str

def export_network_iocs(submission_uuid: str) -> List[NetIoc]:
    rows: List[NetIoc] = []
    with ThreatZone() as client:
        summary = client.get_network_summary(submission_uuid)
        print(f"PCAP available: {summary.pcap_available}")
        print(f"DNS: {summary.dns_count}, HTTP: {summary.http_count}, "
              f"TCP: {summary.tcp_count}, UDP: {summary.udp_count}, "
              f"Threats: {summary.threat_count}")

        for dns in client.get_dns_queries(submission_uuid):
            rows.append(NetIoc("dns", dns.host, f"{dns.type}/{dns.status}"))

        for http in client.get_http_requests(submission_uuid):
            rows.append(NetIoc("http", f"{http.host}:{http.port}", http.ip))

        for conn in client.get_tcp_connections(submission_uuid):
            target = f"{conn.destination_ip}:{conn.destination_port}"
            rows.append(NetIoc("tcp", target, conn.country or "-"))

        for threat in client.get_network_threats(submission_uuid):
            target = f"{threat.destination_ip}:{threat.destination_port}"
            rows.append(NetIoc("threat", target, threat.signature))

    return rows

for row in export_network_iocs("00000000-0000-0000-0000-000000000000"):
    print(f"{row.kind:<7} {row.value:<48} {row.context}")
```

**Notes.**

- The HTTP endpoint no longer returns method, URL, or headers &mdash; only
  `host`, `ip`, `port`, `country`. If you need raw payloads, download the PCAP via
  `client.download_pcap(uuid)` and inspect it in Wireshark or Zeek.
- All network endpoints accept `limit` and `skip` kwargs for manual windowing.
- For Suricata TLS alerts, `threat.tls` carries the JA3 fingerprint block.

---

### 7. Handle the ReportUnavailableError exception

**Goal.** Call a dynamic-report-gated endpoint on a freshly submitted sample, gracefully
retry while the report is still cooking, and give up once the report is known to be in a
terminal error state.

```python
import time
from typing import Optional

from threatzone import ReportUnavailableError, ThreatZone
from threatzone.types import IndicatorsResponse

POLL_SLEEP_SECONDS = 10
TERMINAL_ERROR_STATUSES = {"error"}

def fetch_indicators_with_retry(
    client: ThreatZone,
    submission_uuid: str,
    max_attempts: int = 30,
) -> Optional[IndicatorsResponse]:
    for attempt in range(max_attempts):
        try:
            return client.get_indicators(submission_uuid)
        except ReportUnavailableError as exc:
            if exc.current_status in TERMINAL_ERROR_STATUSES:
                print(f"Dynamic report errored out: {exc.message}")
                return None

            print(
                f"Attempt {attempt + 1}: dynamic report "
                f"{exc.current_status or 'unscheduled'}; "
                f"available now: {exc.available_reports}"
            )
            time.sleep(POLL_SLEEP_SECONDS)

    return None

with ThreatZone() as client:
    response = fetch_indicators_with_retry(
        client,
        "00000000-0000-0000-0000-000000000000",
    )
    if response is not None:
        print(f"Got {response.total} indicators.")
```

**Notes.**

- `ReportUnavailableError.code` is one of `DYNAMIC_REPORT_UNAVAILABLE`,
  `STATIC_REPORT_UNAVAILABLE`, `CDR_REPORT_UNAVAILABLE`, or
  `URL_ANALYSIS_REPORT_UNAVAILABLE`. Branch on this if you're wrapping several endpoints.
- `.current_status` is `None` when the report has not even been scheduled yet (e.g.
  a static-only submission's dynamic report). Treat `None` as "never coming" and exit
  early.
- `.available_reports` tells you which report types you **can** successfully query for
  this submission right now &mdash; use it to offer graceful fallback UX.

---

### 8. Paginate through a large list

**Goal.** Iterate every submission in a workspace without ever holding more than one page
in memory.

```python
from typing import Iterator

from threatzone import ThreatZone
from threatzone.types import SubmissionListItem

PAGE_LIMIT = 100

def iter_submissions(client: ThreatZone) -> Iterator[SubmissionListItem]:
    page = 1
    while True:
        response = client.list_submissions(page=page, limit=PAGE_LIMIT)
        if not response.items:
            return

        yield from response.items

        if page >= response.total_pages:
            return
        page += 1

with ThreatZone() as client:
    for i, submission in enumerate(iter_submissions(client), start=1):
        print(f"{i:>5}  {submission.uuid}  {submission.level:<10}  {submission.filename}")
```

**Notes.**

- `list_submissions()` also accepts `level`, `type`, `sha256`, `filename`, `start_date`,
  `end_date`, `private`, and `tags` for server-side filtering.
- Each `SubmissionListItem` carries the full indicator rollup
  (`item.indicators.levels.malicious`) and the aggregated `item.overview.status`, so
  you rarely need to call `get_submission()` afterwards just to filter.
- The same pagination pattern applies to `get_indicators()`, `get_iocs()`,
  `get_yara_rules()`, `get_behaviours()`, and `get_syscalls()` &mdash; check each
  method's envelope for `items` and `total`.

---

### 9. Discriminate errors by their `code` field

**Goal.** Implement robust error handling that reacts differently to each failure mode
without string-matching on the human-readable `message`.

```python
from threatzone import (
    APIError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ReportUnavailableError,
    ThreatZone,
)

def fetch_indicators_safely(client: ThreatZone, submission_uuid: str) -> None:
    try:
        response = client.get_indicators(submission_uuid)
    except AuthenticationError:
        print("Invalid API key.")
    except PermissionDeniedError as exc:
        code = (exc.body or {}).get("code")
        if code == "SUBMISSION_PRIVATE":
            print("Submission belongs to a different workspace.")
        else:
            print(f"Access denied: {exc.message}")
    except NotFoundError:
        print("Submission does not exist.")
    except BadRequestError as exc:
        code = (exc.body or {}).get("code")
        if code == "INVALID_UUID":
            print("UUID is not a valid v4 UUID.")
        elif code == "INVALID_QUERY_PARAM":
            print(f"Query parameter validation failed: {exc.message}")
        else:
            print(f"Bad request: {exc.message}")
    except ReportUnavailableError as exc:
        if exc.code == "DYNAMIC_REPORT_UNAVAILABLE":
            print(f"Dynamic report state: {exc.current_status}")
    except RateLimitError as exc:
        wait = exc.retry_after or 60
        print(f"Rate limited; retry after {wait}s.")
    except APIError as exc:
        print(f"Unhandled API error {exc.status_code}: {exc.message}")
    else:
        print(f"Got {response.total} indicators.")

with ThreatZone() as client:
    fetch_indicators_safely(client, "00000000-0000-0000-0000-000000000000")
```

**Notes.**

- `APIError.body["code"]` is the machine-readable discriminator. It's one of the values
  in the `ApiErrorCode` literal union in `threatzone.types.errors`. Every code is stable
  across releases; the `message` is not.
- `ReportUnavailableError` already exposes `.code` as a typed attribute &mdash; no need
  to reach into `.body` for it.
- `RateLimitError.retry_after` is parsed from the `Retry-After` response header; it's
  `None` if the header was absent.

---

### 10. Use the async client

**Goal.** Submit a batch of files concurrently and wait for every submission to finish
in parallel.

```python
import asyncio
from pathlib import Path
from typing import List

from threatzone import AnalysisTimeoutError, AsyncThreatZone
from threatzone.types import Submission

async def analyse_batch(samples: List[Path]) -> List[Submission]:
    async with AsyncThreatZone() as client:
        created = await asyncio.gather(*[
            client.create_sandbox_submission(sample, environment="w10_x64")
            for sample in samples
        ])
        print(f"Queued {len(created)} submissions.")

        results = await asyncio.gather(
            *[client.wait_for_completion(sub.uuid, timeout=900) for sub in created],
            return_exceptions=True,
        )

        finished: List[Submission] = []
        for sample, result in zip(samples, results):
            if isinstance(result, AnalysisTimeoutError):
                print(f"  {sample.name}: TIMEOUT after {result.elapsed:.0f}s")
            elif isinstance(result, Exception):
                print(f"  {sample.name}: FAILED ({type(result).__name__})")
            else:
                print(f"  {sample.name}: {result.level}")
                finished.append(result)

        return finished

asyncio.run(analyse_batch([Path("a.exe"), Path("b.exe"), Path("c.exe")]))
```

**Notes.**

- `AsyncThreatZone` exposes every method `ThreatZone` does. Use `async with` for context
  management.
- `asyncio.gather(return_exceptions=True)` prevents a single failed submission from
  poisoning the whole batch.
- Watch your API quota &mdash; concurrent submissions also count against
  `limits_count.concurrent_submission_count`.

---

### 11. Build a daily report summary

**Goal.** Produce a plain-text digest of every submission created in the last 24 hours
along with its verdict rollup.

```python
from datetime import datetime, timedelta, timezone

from threatzone import ThreatZone

def daily_digest() -> None:
    since = datetime.now(timezone.utc) - timedelta(days=1)

    with ThreatZone() as client:
        account = client.get_user_info()
        response = client.list_submissions(
            page=1,
            limit=100,
            start_date=since,
        )

        print(f"Digest for {account.workspace_name}")
        print(f"Period: last 24h")
        print(f"Submissions: {response.total}")
        print("=" * 60)

        verdict_counts = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0}
        for item in response.items:
            verdict_counts[item.level] = verdict_counts.get(item.level, 0) + 1

        for level, count in verdict_counts.items():
            print(f"  {level:<10} {count:>4}")

        print("=" * 60)
        for item in response.items[:10]:
            mitre_count = item.indicators.levels.malicious
            print(
                f"  {item.created_at.strftime('%H:%M')} "
                f"{item.level:<10} {item.filename or item.uuid} "
                f"(mal={mitre_count})"
            )

daily_digest()
```

**Notes.**

- `list_submissions` accepts `datetime` for `start_date`/`end_date` and serializes to
  ISO-8601 automatically.
- `item.indicators.levels` carries `malicious/suspicious/benign` counts baked into the
  list item &mdash; no extra round-trip to `/summary` needed for a quick rollup.
- Iterate with [recipe 8](#8-paginate-through-a-large-list) if you have more than 100
  submissions per day.

---

### 12. Cross-reference MITRE techniques with indicators

**Goal.** Build a `technique_id -> [indicator_name, ...]` map so you can drive an ATT&CK
navigator layer from a single submission.

```python
from collections import defaultdict
from typing import Dict, List

from threatzone import ThreatZone

def mitre_attack_layer(submission_uuid: str) -> Dict[str, List[str]]:
    with ThreatZone() as client:
        mitre = client.get_mitre_techniques(submission_uuid)
        print(f"Submission matched {mitre.total} MITRE techniques.")

        by_technique: Dict[str, List[str]] = defaultdict(list)
        page = 1
        while True:
            response = client.get_indicators(submission_uuid, page=page, limit=100)
            if not response.items:
                break

            for indicator in response.items:
                for technique in indicator.attack_codes:
                    by_technique[technique].append(indicator.name)

            if len(response.items) < 100:
                break
            page += 1

        return dict(by_technique)

layer = mitre_attack_layer("00000000-0000-0000-0000-000000000000")
for technique_id in sorted(layer):
    print(f"{technique_id}:")
    for indicator_name in layer[technique_id]:
        print(f"  - {indicator_name}")
```

**Notes.**

- `get_mitre_techniques()` is the fast path for just the de-duplicated technique IDs.
  Use `get_indicators()` on top if you want the indicator-to-technique edges.
- `Indicator.attack_codes` uses the dotted MITRE sub-technique notation
  (e.g. `T1003.001`). You can filter the indicator list by a single technique with
  `get_indicators(uuid, attack_code="T1055")`.
- Both endpoints are `ReportStatusGuard('dynamic')`-gated &mdash; wrap them with the
  retry loop from [recipe 7](#7-handle-the-reportunavailableerror-exception) if the
  submission may still be in analysis.
