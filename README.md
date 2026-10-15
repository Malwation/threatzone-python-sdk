# Threat.Zone Python SDK

Official Python SDK for the [Threat.Zone](https://threat.zone) malware analysis platform.
Targets the Threat.Zone Public API, ships fully typed Pydantic v2
models for every endpoint, and exposes both synchronous (`ThreatZone`) and asynchronous
(`AsyncThreatZone`) clients with identical method surfaces. Requires **Python 3.10+**.

> [!WARNING]
> ## ⚠️ Version Compatibility Notice
>
> **This SDK requires Threat.Zone v3.2.0 or later.**
>
> This SDK targets the Public API shipped with **Threat.Zone v3.2.0**. It will **not** function correctly against earlier versions of the platform.
>
>
> Running an older Threat.Zone version? Pin to a pre-v3.2.0 release of this SDK, or coordinate with your admin to upgrade the platform first.

## Install

```bash
pip install threatzone
# or
uv add threatzone
```

## Configure

```python
from threatzone import ThreatZone

client = ThreatZone(api_key="<your-api-key>")
```

The client reads `THREATZONE_API_KEY` from the environment, so `ThreatZone()` is enough
if you export it. The default `base_url` is `https://app.threat.zone/public-api`.

For on-prem or local development, pass `base_url` explicitly:

```python
client = ThreatZone(
    api_key="<your-api-key>",
    base_url="https://threatzone.your-company.internal/public-api",
)
```

The `base_url` **must** include the `/public-api` suffix. For self-signed certs, leave
`verify_ssl=False` (the default).

## Quick usage

```python
from pathlib import Path

account = client.get_user_info()
print(f"Workspace: {account.workspace_name}")

submission = client.create_sandbox_submission(Path("./sample.exe"))
completed = client.wait_for_completion(submission.uuid, timeout=600)
print(f"Verdict: {completed.level}")
print(f"MITRE techniques: {completed.mitre_techniques}")
```

- Pass `auto_select_environment=True` to let the server route the sample to a Windows / Linux / macOS / Android environment based on its detected type. See [recipe 14](./docs/RECIPES.md#14-auto-select-sandbox-environment).

### Score explanation

`get_submission()` returns the live score that the web UI shows, and
`score_breakdown` explains it:

```python
detail = client.get_submission(submission.uuid)
print(detail.score)  # 78.5
if detail.score_breakdown is not None:
    print(detail.score_breakdown.deciding_layer)  # indicator_mean
    for contributor in detail.score_breakdown.contributors:
        print(contributor.points, contributor.indicator_id, contributor.title)
```

- A pure URL submission has `score=None` and `score_breakdown=None` until the final URL
  verdict.
- `contributors[].title` and `what_would_change` are display text. The text can change
  between releases. Match on `indicator_id`, not on the title.
- The detail response also carries `overview.duration`, `file.history` (other names of the
  same sample), `reports[].metafields` (the analysis options) and `tags[].author`.

### Filename canonicalisation (`dynamic_mimetype_check`)

By default the server appends the real (Magika-detected) extension to the
persisted filename when it disagrees with what the file was named. Opt out per
submission &mdash; sandbox / open-in-browser take it as a `metafields` key, static
/ CDR take it as a top-level kwarg:

```python
# sandbox / open-in-browser → inside metafields
client.create_sandbox_submission(
    "./malware.txt",
    environment="w10_x64",
    metafields={"dynamic_mimetype_check": False, "timeout": 120},
)

# static / CDR → top-level kwarg
client.create_static_submission("./malware.txt", dynamic_mimetype_check=False)
client.create_cdr_submission("./report.doc", dynamic_mimetype_check=False)
```

See [Recipe 13](docs/RECIPES.md#13-control-dynamic_mimetype_check) for the full
breakdown including reading back `FileInfo.is_mimetype_checked` after the
submission completes.

## URL analysis

Submit a URL, open an interactive browser session, then read the scored report.

```python
# Pick an emulated device. Omit the metafield to use the plan default.
presets = client.get_device_presets()
mobile = next(p for p in presets if p.category == "mobile")

created = client.create_url_submission(
    "https://suspicious-landing.example.com/update.php",
    private=True,
    safe_browsing=True,
    metafields={"timeout": 240, "device_preset": mobile.id},
    configurations={"networkConfig": "<network-config-id>"},
)

# Poll for the viewer link. A session over workspace capacity is queued, not rejected.
session = client.get_url_analysis_session(created.uuid)
if session.state == "queued":
    print(f"Queued at position {session.queue_position}")
if session.vnc_available:
    print(f"Viewer: {session.link}")

client.wait_for_completion(created.uuid, timeout=300)
report = client.get_url_analysis(created.uuid)

print(report.threat_score, report.risk_level)          # 88 Critical
print(report.privacy_score, report.privacy_risk_level)  # 35 Medium
if report.impersonation_target is not None:
    print(report.impersonation_target.brand_name)
for hit in report.intel_detections:
    print(hit.source, hit.severity)
```

Session control:

- `start_url_analysis_session(uuid)` opens a session on an existing submission.
- `restart_url_analysis_session(uuid)` ends the current session and starts a clean one
  with the same device and network choice.
- Neither call consumes daily submission quota.
- `restart_url_analysis(uuid)` re-runs the analysis itself. It counts against the
  concurrent-submission quota.

Scoring fields (`threat_score`, `risk_level`, `privacy_score`, `privacy_risk_level`,
`privacy_breakdown`, `verdict_provenance`, `impersonation_target`,
`completeness`, `intel_detections`, `metafields`, `scored_at`) are `None` or empty until
scoring finishes. Read them after the report reaches `completed`.

`report.job_id` identifies the analysis run. A restart starts a new run with a new
`job_id`. `session.session_config.network_config_source` (`"submit"` or
`"admin-default"`) and `network_config_name` tell where the network choice came from.

Score explanation, evidence and browser sections (all plans):

```python
explanation = client.get_url_analysis_indicators(created.uuid)
if explanation.snapshot is not None:
    for indicator in explanation.snapshot.indicators:
        print(indicator.rule_id, indicator.weighted_points, indicator.disposition)
        for ref in indicator.evidence_refs:
            if ref.available:
                evidence = client.get_url_analysis_indicator_evidence(
                    created.uuid,
                    indicator.id,
                    ref.id,
                    job_id=explanation.snapshot.job_id,
                    scored_at=explanation.snapshot.scored_at,
                )
                print(evidence.text)  # pretty-printed JSON, 8192 characters or fewer

tls = client.get_url_analysis_browser_section(created.uuid, "tls")
print(tls.revision, tls.data)
```

- `get_url_analysis_indicators(uuid)` returns `state` (`"available"`, `"pending"` or
  `"unavailable"`) and the `snapshot`. `unavailable_reason` is `"legacy"`, `"size_limit"`
  or `"scoring_error"`. Indicator `title` and `reason` are display text that can change;
  use `id` and `rule_id` in automation.
- `get_url_analysis_indicator_evidence(uuid, indicator_id, reference_id, *, job_id=None,
  scored_at=None)` returns one evidence item. When `job_id` or `scored_at` is `None`, the SDK
  reads the explanation first and uses the snapshot values. `state` is `"unavailable"` when
  the selector is not current: read the explanation again. An unknown indicator or reference
  raises `NotFoundError` (`URL_SCORE_EVIDENCE_NOT_FOUND`).
- `get_url_analysis_browser_section(uuid, section)` accepts `"overview"`, `"findings"`,
  `"tls"` or `"network-summary"` (redirects, hosts and IP addresses). Another name raises
  `NotFoundError` (`URL_BROWSER_SECTION_NOT_FOUND`). A run without browser data raises
  `NotFoundError` (`URL_BROWSER_SECTION_UNAVAILABLE`). The API never returns cookies, full
  network entries, or request and response bodies.

Media from the session:

```python
media = client.list_media_files(created.uuid, source="url_analysis")
for item in media:
    print(item.id, item.kind)  # kind: "video", "screenshot", or None

data = client.get_media_file(created.uuid, media[0].id, source="url_analysis")
```

`source` accepts `"dynamic"` or `"url_analysis"`. When omitted, the server picks
`dynamic` if the submission has a dynamic report, otherwise `url_analysis`. A submission
with neither report returns 409.

See [recipe 2](./docs/RECIPES.md#2-submit-a-url-and-get-the-url-analysis-report) for the
full flow.

## Indicators and artifacts

```python
uuid = completed.uuid

for row in client.get_indicators(uuid).items:
    # Windows V2 rows carry the analyst text, the acting process and the related events.
    # These fields are None on legacy rows.
    print(row.name, row.rule_source, row.what_happened)
    if row.actor is not None:
        print(row.actor.image, row.actor.pid, row.actor.pid_gen)
    for event in row.related or []:
        print(event.event_id, event.t_offset_s, event.text)
    # Overview rows have an empty id. finding_source names the job that produced them.
    if not row.id:
        print(row.finding_source, row.artifacts)

for ioc in client.get_iocs(uuid).items:
    print(ioc.type, ioc.raw_type, ioc.value)  # raw_type: the type text as stored

# Filter by the stored source value; an unknown value raises BadRequestError.
for artifact in client.get_artifacts(uuid, source="dynamic_report").items:
    print(artifact.filename, artifact.analysis_status, artifact.analysis_reason)
    # The engine jobs of the artifact, oldest first.
    for job in client.get_artifact_jobs(uuid, artifact.id):
        print(job.engine_type, job.status, job.error_code)  # error_code: JOB_FAILED, ...
```

`ArtifactJob.error_code` is a fixed code (`JOB_FAILED`, `JOB_DEAD_LETTERED`, `JOB_SKIPPED`).
The API never returns the platform error text. `Artifact.download_link` is the path of the
artifact download route; `download_artifact()` needs the `downloadSample` plan permission.

## Static scan, strings and CDR

```python
uuid = completed.uuid

report = client.get_static_scan_results(uuid)
if report.file_info is not None:
    # NSRL (National Software Reference Library) match; None when the engine has no value.
    print(report.file_info.real_filename, report.file_info.real_sha256)
for embedded in report.one_note_embedded_files or []:  # onenote reports only
    print(embedded.embedded_file_name, embedded.source_filepath, embedded.entropy)

# Observables and facts of the extracted strings. Values come in full; secret is a label.
facts = client.get_static_scan_string_facts(uuid)
for observable in facts.observables:
    if observable.secret:
        print(observable.kind, observable.value, observable.source)
for fact in facts.facts:
    print(fact.code, fact.capability, fact.matches)

# One window of the extracted strings: search first, then start/end (at most 1000 rows).
page = client.get_static_scan_strings_page(uuid, start=0, end=500, search="telegram")
print(page.items_count, [item.value for item in page.items])

# CDR details nest for inner files, for example archive members.
cdr = client.get_cdr_results(uuid)
for detail in (cdr.sanitized_file_info.details if cdr.sanitized_file_info else []):
    print(detail.name, detail.action, detail.count, detail.file_name)
    for nested in detail.details:
        print("  ", nested.name, nested.action, nested.sha256)
```

`get_static_scan_string_facts()` and `get_static_scan_strings_page()` are heavy routes. Each API
token can send 30 heavy-route requests each minute; above the limit the call raises
`RateLimitError`. The API and the SDK never mask, cut or hide secret values.

## Processes, behaviours and syscalls

```python
uuid = completed.uuid

# (pid, pid_gen) identifies one process when the OS reuses a pid. Each field is None on
# reports that do not record it.
for process in client.get_processes(uuid).items:
    print(process.pid, process.pid_gen, process.origin, process.image, process.exit_timestamp)

# Kill chain: process starts, dropped files and memory dumps, as in the web UI.
killchain = client.get_killchain(uuid)
for group in killchain.dropped_files:
    for dropped in group.files:
        if dropped.artifact_id is not None:  # None: no stored copy of this file
            client.download_artifact(uuid, dropped.artifact_id).save(f"{dropped.artifact_id}.bin")

# Index filters: the same server-side filters and counts as the web UI.
page = client.get_behaviours(
    uuid,
    pids=[1508],
    operations=["regsetvalue"],          # any of, case-insensitive
    fields={"key": ["run", "runonce"]},  # sent as field.key; text the detail contains
    sort="time",
)
print(page.total, page.sorted_by, [event.subject for event in page.items])

summary = client.get_behaviour_summary(uuid)  # totals, by type / operation / process, exits
facets = client.get_behaviour_facets(uuid, "operation", contains="reg", first=20)

# Search the raw syscall log page by page.
result = client.search_syscalls(uuid, query="NtCreateFile", failed_only=True)
while True:
    for hit in result.lines:
        print(hit.line, hit.raw)
    if result.next_from_line is None:
        break
    result = client.search_syscalls(
        uuid, query="NtCreateFile", failed_only=True, after_line=result.next_from_line
    )

# Raw files (the plan needs the downloadReport permission).
client.download_behaviour(uuid).save("behaviour.json")
client.download_syscalls(uuid).save("syscalls.txt")
```

The index parameters (`pids` to `sort`) and the summary and facet routes read the behaviour
index. The public API never builds the index; the index is built when the Behaviour view of
the report is opened. Without a current index these calls raise `BehaviourIndexingError`.
`get_behaviours()` without the index parameters (`event_ids` is allowed) reads the behaviour
file and does not need the index. `get_behaviour_summary()`, `get_behaviour_facets()` and
`search_syscalls()` and `get_killchain()` are heavy routes: each API token can send a limited
number of requests per minute, and `RateLimitError.retry_after` gives the seconds to wait.
`get_killchain()` returns `artifact_id` instead of a download link. `dump_collector_active` is
`False` when the memory dump collector did not run; then an empty `mem_dumps` does not tell that
no dump was possible.

## Network

```python
uuid = completed.uuid

# Every network list is a plain list with total_count (the X-Total-Count header).
page = client.get_tcp_connections(uuid, limit=100, skip=0)
print(f"{len(page)} of {page.total_count} TCP rows")
for row in page:
    print(row.destination_ip, row.domain, row.ptr_domain, row.app_proto, row.bytes_to_server)

# Packet payloads of one row, as bytes. The payloads are not masked.
http_row = client.get_http_requests(uuid)[0]
for pair in client.get_http_request_packets(uuid, http_row.id).items:
    print(pair.method, pair.url, pair.body.data if pair.body else None)
tcp_packets = client.get_tcp_connection_packets(uuid, page[0].id)  # also: UDP

# The network map: endpoints, then the flows and alerts of one host, page by page.
endpoints = client.get_network_endpoints(uuid, attribution=["sample", "sample_child"])
host = endpoints.items[0].key
flows = client.get_network_host_flows(uuid, host, attribution=["sample", "sample_child"])
while True:
    for flow in flows.flows:
        print(flow.protocol, flow.remote_ip, flow.remote_port, flow.count)
    if not flows.page_info.has_next_page:
        break
    flows = client.get_network_host_flows(
        uuid, host, attribution=["sample", "sample_child"], after=flows.page_info.end_cursor
    )
for alert in flows.alerts:
    print(alert.signature, alert.severity, alert.count)

# Decrypted HTTPS capture (the plan needs the downloadReport permission).
if client.get_network_summary(uuid).https_pcap_available:
    client.download_https_pcap(uuid).save("https.pcap")
```

`get_network_endpoints()` and `get_network_host_flows()` are heavy routes, with the same
per-token limit as the other heavy routes. Send the same `attribution` to both, so the flows
match the rows of the endpoint. An unknown host returns an empty page. A packet route raises
`NotFoundError` (`NETWORK_ROW_NOT_FOUND`) when the row ID does not belong to the submission.

## Reports and exports

```python
uuid = completed.uuid

# PDF: wait for the background render (bounded by `timeout`, default 600 s).
client.download_pdf_report(uuid).save("report.pdf")

# PDF without waiting: raises PdfReportPendingError while the render runs.
status = client.get_pdf_report_status(uuid)  # analysis_in_progress / queued / generating / ready

client.download_stix_report(uuid).save("bundle.json")  # STIX 2.1 bundle
client.download_html_report(uuid).save("report.html")

# IP, domain, URL and SHA-256 indicators as one file: csv, text, stix or misp.
# stix and misp need the stixReport plan permission; without it the call raises
# PermissionDeniedError. The values are not masked.
client.download_iocs(uuid, format="csv").save("iocs.csv")

# AI analyst report: AiReport (HTTP 200) or AiReportPending (HTTP 202).
from threatzone import AiReportPending

report = client.get_ai_report(uuid)
if isinstance(report, AiReportPending):
    print(f"AI report is {report.status}. Try again later.")
elif report.status == "failed" and report.error is not None:
    print(f"AI report failed: {report.error.code}")

# Queue a new AI report (submitter or workspace admin, final score, uses one quota unit).
# 409 raises ReportUnavailableError (AI_REPORT_NOT_FINALIZED / AI_REPORT_IN_PROGRESS);
# a used daily quota raises RateLimitError with retry_after.
queued = client.regenerate_ai_report(uuid)  # AiReportRegenerateResult, status == "queued"

# Plan permissions and the AI report quota.
account = client.get_user_info()
if account.plan_permissions is not None and not account.plan_permissions.download_report:
    print("The plan cannot download the network capture.")
print(f"AI reports used: {account.user_info.limits_count.ai_report_count}")
print(f"AI quota resets at: {account.ai_report_resets_at}")

# Chat bot and webhook requests from the decrypted HTTPS capture.
for entry in client.get_network_exfil_requests(uuid):
    print(entry.api, entry.api_method, entry.masked_target)

# The SHA-256 search returns one page (server default: 20 rows).
matches = client.search_by_sha256("<sha256>", page=2, limit=100)
# scope="public": only public submissions of all workspaces, also URL submissions whose
# downloaded payload has this SHA-256. The default scope is "workspace".
public_matches = client.search_by_sha256("<sha256>", scope="public")
```

The HTML and PDF reports show the items that analysts in your workspace pinned, and their
note, in a "Pinned evidence" section. Other workspaces do not see them.

## Verdict, run notes, annotations and run compare

```python
# The Windows V2 verdict with its narrative and story, as the web report shows it.
verdict = client.get_verdict(uuid)  # every field is None for a legacy report
if verdict.story is not None:
    for step in verdict.story.steps:
        print(step.t_offset_s, step.process.image, step.text)

# How the run went: Java console output (full stored text), cut-short facts and notes.
run = client.get_run(uuid)
if run.java_output is not None:
    print(run.java_output.text)
for note in run.run_notes:
    print(note.code, note.text)

# Evidence pins and the note of your workspace. Each write returns the full view.
annotations = client.pin_evidence(uuid, kind="technique", ref="technique:T1055", label="Injection")
client.set_note(uuid, "The sample drops a second stage.")
client.unpin_evidence(uuid, annotations.pins[0].id)
client.set_note(uuid, "")  # an empty text removes the note

# The previous run of the same sample, then the difference between the two runs.
previous = client.get_previous_run(uuid).previous_run_uuid
if previous is not None:
    diff = client.compare_runs(uuid, previous)
    print(diff.techniques.added, diff.iocs.removed_total)
```

`get_verdict()` and `get_run()` need a dynamic report; without it they raise
`ReportUnavailableError`. The framework writes the verdict, story and note text. The text can
change between releases: show it, do not parse it.

Pins and the note belong to the workspace of the API token. Your workspace can annotate every
submission that it can see, also a public submission of another workspace. The annotations
stay in your workspace: a caller never reads or changes the annotations of another workspace.
A private submission of another workspace raises `NotFoundError`. `pin_evidence()` raises
`BadRequestError` with code `ANNOTATION_PIN_LIMIT_REACHED` when your workspace has 200 pins on
the submission. `unpin_evidence()` raises `NotFoundError` with code `ANNOTATION_PIN_NOT_FOUND`
for an unknown pin ID. The web UI and the HTML and PDF reports of your workspace show the pins
and the note.

`compare_runs()` reads only runs that your workspace can open. `added` items are in `uuid`
only; `removed` items are in `other_uuid` only. Each list holds at most 200 items;
`added_total` and `removed_total` count the items before that cap.

## Core concepts

- **Submissions** — one analysis target (file or URL) with a stable `uuid`, a workspace
  owner, a `private` flag, and up to four reports.
- **Reports** — `dynamic`, `static`, `cdr`, `url_analysis`. Independent; poll each via
  `submission.is_complete()` / `submission.has_errors()`. Every report carries its own
  `status`, `level`, `score`.
- **Observation streams** — the dynamic report produces `indicators` (rule hits),
  `iocs` (concrete IOC values), `behaviours` (OS-level operations), and `syscalls`
  (raw log lines).
- **Artifacts** — files produced or extracted during analysis; keyed by `hashes.sha256`.
- **Access control** — public submissions are visible to every API key; private
  submissions are workspace-scoped. Cross-workspace reads of private submissions raise
  `PermissionDeniedError` (403).

## Async

`AsyncThreatZone` mirrors `ThreatZone` method-for-method:

```python
import asyncio
from threatzone import AsyncThreatZone

async def main() -> None:
    async with AsyncThreatZone(api_key="<your-api-key>") as client:
        account = await client.get_user_info()
        print(account.email)

asyncio.run(main())
```

Use `asyncio.gather()` for concurrent fan-out. See [recipe 10](./docs/RECIPES.md#10-use-the-async-client).

## Errors

Every error inherits from `ThreatZoneError`. HTTP errors additionally inherit from
`APIError` and carry the parsed error envelope on `.body`, with the structured code at
`.body["code"]`. Branch on `.code`, never on `.message`.

| Status | Exception | When |
|---|---|---|
| — | `ThreatZoneError` | Base class. Catch for a single safety net. |
| — | `APIError` | HTTP error base class. `.status_code`, `.body`, `.response`. |
| 400 | `BadRequestError` | `INVALID_UUID`, `INVALID_QUERY_PARAM`. |
| 401 | `AuthenticationError` | Missing/invalid API key. |
| 402 | `PaymentRequiredError` | Workspace subscription inactive. |
| 403 | `PermissionDeniedError` | Cross-workspace private read, or module not enabled. |
| 404 | `NotFoundError` | Submission, artifact, or media missing. |
| 409 | `ReportUnavailableError` | Required report not yet available. Carries `.code`, `.submission_uuid`, `.required_report`, `.current_status`, `.available_reports`. |
| 409 | `BehaviourIndexingError` | `BEHAVIOUR_INDEXING`: the behaviour index is not ready. Subclass of `ReportUnavailableError`. Has `.retry_after`. |
| 413 | `BehaviourTooLargeError` | `BEHAVIOUR_TOO_LARGE`: the behaviour file or the index scan is above the read limit. `.size_bytes`, `.max_bytes`, `.download_route`. |
| 429 | `RateLimitError` | API quota or heavy-route limit exceeded. Has `.retry_after`. |
| 502 | `BehaviourUnreadableError` | `BEHAVIOUR_UNREADABLE`: the stored behaviour file is not valid. Subclass of `InternalServerError`. |
| 5xx | `InternalServerError` | Server-side failure. |
| — | `TimeoutError` | HTTP request timed out. |
| — | `ConnectionError` | Network-level failure. |
| — | `AnalysisTimeoutError` | `wait_for_completion()` exceeded its timeout. `.uuid`, `.elapsed`. |
| 202 | `YaraRulePendingError` | YARA rule generation still in progress. `.retry_after`. |
| 202 | `PdfReportPendingError` | PDF report not ready (`download_pdf_report(wait=False)`, or the wait reached its timeout). `.retry_after`. |

```python
from threatzone import ReportUnavailableError, ThreatZone

try:
    indicators = client.get_indicators("00000000-0000-0000-0000-000000000000")
except ReportUnavailableError as exc:
    if exc.code == "DYNAMIC_REPORT_UNAVAILABLE":
        print(f"Dynamic report not ready (status: {exc.current_status}).")
```

See [recipe 9](./docs/RECIPES.md#9-discriminate-errors-by-their-code-field) for the full
discrimination pattern and [recipe 7](./docs/RECIPES.md#7-handle-the-reportunavailableerror-exception)
for the recommended retry loop.

## Documentation

| Document | Purpose |
|---|---|
| [Recipes](./docs/RECIPES.md) | Runnable examples covering common tasks. |
| [Type Reference](./docs/TYPES.md) | Pydantic model overview grouped by feature area. |

## Testing utilities

The SDK ships a stateful in-process fake Threat.Zone API for consumer-side tests:

```python
from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios

fake = FakeThreatZoneAPI()
scenarios.seed_malicious_pe(fake, sha256="a" * 64)

client = ThreatZone(
    api_key="test-key",
    base_url="https://fake.threat.zone/public-api",
    http_client=fake.as_httpx_client(),
)
```

Available scenarios: `seed_malicious_pe`, `seed_benign_document`, `seed_cdr_document`,
`seed_phishing_url`, `seed_static_only_submission`, `seed_private_cross_workspace`.

## Development

```bash
uv sync --all-extras --dev
uv run pytest tests/
uv run ruff check src/ tests/
uv run mypy src/threatzone
uv build
```

All tests run in-process against `FakeThreatZoneAPI` — no network, no API token. Live
smoke-testing uses the scripts in `examples/` with `PUBLIC_API_TOKEN` exported; see
`examples/README.md`.

GitHub Actions workflows can be exercised locally via `act` — see
[`.github/workflows/README.md`](./.github/workflows/README.md).

## Links

- [Threat.Zone platform](https://threat.zone)
- [Public API reference](https://app.threat.zone/public-api/docs)
- [PyPI package](https://pypi.org/project/threatzone/)
- [GitHub repository](https://github.com/Malwation/threatzone-python-sdk)

## License

MIT — see [LICENSE](LICENSE).
