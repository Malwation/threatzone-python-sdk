# Threat.Zone Python SDK Type Reference

Every SDK response is a fully typed Pydantic v2 model. This page is a scannable map of
the model hierarchy, grouped by feature area. For the full field list of any model, read
the source in [`src/threatzone/types/`](../src/threatzone/types/) &mdash; the Pydantic
models are the canonical schema.

All models:

- `populate_by_name=True` &mdash; they accept **either** the camelCase API field name
  **or** the snake_case Python attribute.
- Use `model.model_dump(by_alias=True)` to get JSON back in the API's camelCase shape.
- Are importable from `threatzone.types` (e.g. `from threatzone.types import Indicator`).

---

## Submissions

Top-level submission types. Returned by `create_*_submission()`, `list_submissions()`,
`get_submission()`, `search_by_sha256()`, and `wait_for_completion()`.

| Type | Purpose | Endpoints |
|------|---------|-----------|
| `SubmissionCreated` | Thin envelope for a freshly queued submission. | `POST /submissions/*` |
| `SubmissionListItem` | One row in a paginated list. Carries enrichment (indicators rollup, overview). `url` is the submitted URL of a URL submission; `filename` and `sha256` are `None` for a URL submission. | `GET /submissions` |
| `PaginatedSubmissions` | Full list envelope with `items`, `total`, `page`, `limit`, `total_pages`. | `GET /submissions` |
| `Submission` | Full submission detail including `file`, `mitre_techniques`, `overview`, `score_breakdown`. `score` is the live score that the web UI shows; it is `None` for a pure URL submission until the final URL verdict. `search_by_sha256()` returns one page of these (`page`, `limit`; the server default is 20 rows). | `GET /submissions/:uuid`, `GET /submissions/search/sha256/:sha256` |
| `SubmissionOverview` | Aggregated analysis status + job progress (`status`, optional `jobs`, `duration`). `duration` is the longest report run time in seconds; only `get_submission()` sends it. | Nested in `Submission` and `SubmissionListItem` |
| `SubmissionIndicatorsRollup` | Severity rollup attached to a submission (`levels`, `artifact_count`). | Nested in `Submission` and `SubmissionListItem` |
| `ReportStatus` | Per-report state (`type`, `status`, `level`, `score`, `duration`, `format`, `operating_system`, `metafields`). `score` is a `float` or `None`. `metafields` is a `dict[str, str]` of the analysis options as the web UI shows them (option name to selected value); only `get_submission()` sends it. `metafield_values` is the typed form keyed by the metafield key (`dict[str, MetafieldValue]`, for example `{"timeout": 120}`), and `execution_duration_seconds` is the `timeout` option of a dynamic report. Read these two in code. | Nested `reports[]` on `Submission` |
| `ScoreBreakdown` | Explanation of `Submission.score`: `deciding_layer`, `verdict`, `score`, `cap`, `contributors`, `what_would_change`. Only `get_submission()` sends it. `None` for a pure URL submission, before the overview exists, and when the stored score does not come from the current score rule. | `GET /submissions/:uuid` |
| `ScoreContributor` | One finding with a large effect on the score: `source`, `indicator_id`, `title`, `points`, `level`. At most ten, largest effect first. | Nested in `ScoreBreakdown.contributors` |

**Discriminative fields.**

- `Submission.level` is `ThreatLevel = Literal["unknown", "benign", "suspicious", "malicious"]`.
- `Submission.type` is `Literal["file", "url"]`.
- `search_by_sha256(..., scope=...)` takes `SubmissionSearchScope` (`workspace` or `public`).
  `workspace` (the server default) reads the file submissions of your workspace and the public
  file submissions of other workspaces. `public` reads only public submissions of all
  workspaces, also URL submissions whose downloaded payload has the SHA256.
- `Submission.reports[].status` is `Literal["error", "not_started", "accepted", "in_progress", "clean_up", "completed"]`.
- `Submission.reports[].type` is `Literal["dynamic", "static", "cdr", "url_analysis", "open_in_browser"]`.
- `Submission.is_complete()` returns `True` when every report is in `completed` or `error`.
- `ScoreBreakdown.deciding_layer` is `ScoreLayer` (`indicator_mean`, `dynamic_verdict`, `config_floor`, `url_analysis`, `submission_level`, `none`, or a new value). `cap` is set only for `indicator_mean`.
- `ScoreContributor.level` is a `ThreatLevel` or a new value. `ScoreBreakdown.verdict` is a display label such as `Malicious`.
- `ScoreContributor.title` and `ScoreBreakdown.what_would_change` are display text. The text can change between releases. Do not parse it; match on `indicator_id`.
- Every detail-only field (`score_breakdown`, `overview.duration`, `file.history`, `reports[].metafields`) is `None` on `search_by_sha256()` rows, on `list_submissions()` rows, and on older servers.

Related: `Tag`, `FileInfo`, `Hashes` (in `threatzone.types.common`).

---

## Indicators Surface

Everything under the "observation" streams produced by the analysis pipeline. Every type
in this group is envelope-wrapped (`items`, `total`) for server-side pagination.

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Indicator` | A single rule hit with cross-reference IDs. Fields: `id`, `source`, `name`, `description`, `summary`, `why_matched`, `in_verdict_chain`, `category`, `level`, `score`, `score_maximum`, `pids`, `pid_gens`, `attack_codes`, `attempted_attack_codes`, `event_ids`, `syscall_line_numbers`, `author`, `rule_source`, `what_happened`, `why_it_matters`, `why_this_tier`, `not_observed`, `outcome`, `score_note`, `score_factors`, `score_result`, `score_cap`, `related`, `actor`, `target`, `t_offset_s`, `span_s`, `occurrences`, `finding_source`, `artifacts`, `dynamic_indicator_id`. | `GET /submissions/:uuid/indicators` |
| `IndicatorRelated` | A behaviour event related to the row: `event_id`, `signal_id`, `text`, `t_offset_s`, `actor` (`IndicatorRelatedActor`: `image`, `pid`). | nested in `Indicator.related` |
| `IndicatorActor` | The process that did the behaviour: `image`, `pid`, `pid_gen`, `lineage`. | nested in `Indicator.actor` |
| `IndicatorTarget` | The object that the behaviour acted on: `kind`, `value`. | nested in `Indicator.target` |
| `IndicatorsResponse` | `{items, total, levels}` envelope. `levels` is a `{malicious, suspicious, benign}` severity rollup. | same |
| `IndicatorLevels` | Severity counts: `malicious`, `suspicious`, `benign`. | nested |
| `IoC` | `{type, value, artifacts, raw_type}`. `type` is the 11-value literal below. | `GET /submissions/:uuid/iocs` |
| `IoCsResponse` | Paginated IoC envelope. | same |
| `YaraRule` | `{rule, category, artifacts}`. `category` is `malicious`/`suspicious`/`benign`. | `GET /submissions/:uuid/yara-rules` |
| `YaraRulesResponse` | Paginated YARA rule envelope. | same |
| `ExtractedConfig` | `{family, config, c2s, artifacts}`. `config` is a free-form family-specific dict. | `GET /submissions/:uuid/extracted-configs` |
| `ExtractedConfigsResponse` | Paginated extracted config envelope. | same |
| `Artifact` | `{id, filename, size, type, source, hashes, tags, process_attribution, analysis_status, analysis_trigger, analysis_reason, download_link}`. SHA-256 is under `hashes.sha256`. | `GET /submissions/:uuid/artifacts` |
| `ArtifactHashes` | `{md5, sha1, sha256}`. | nested in `Artifact` |
| `ArtifactsResponse` | Artifact envelope (`items`, `total`). | same |
| `ArtifactJob` | One engine analysis job of an artifact: `engine_type`, `status`, `error_code`. `get_artifact_jobs()` returns a list, oldest first. | `GET /submissions/:uuid/artifacts/:artifactId/jobs` |
| `EmlAnalysis` | Parsed `.eml` artifact: `headers`, `other_headers`, `attachments`, `qr_results`, `artifact`. | `GET /submissions/:uuid/eml-analysis` |
| `MitreResponse` | `{techniques: List[str], total, attack_version, domain, items}`. `attack_version` is the ATT&CK catalog version (`"20.0"`); `domain` is `AttackDomain` (`enterprise` or `mobile` for an Android report), and `items` holds only the techniques of that domain. Sorted, de-duplicated MITRE IDs. `items` has one `MitreTechniqueUsage` for each matched technique that is in the ATT&CK catalog of the platform, sorted by `technique_id`. A code that is not in the catalog is in `techniques` but not in `items`, so `items` can be shorter than `techniques`. `items` is `None` when an older server omits it. | `GET /submissions/:uuid/mitre` |
| `MitreTechniqueUsage` | `{technique_id, name, tactic_ids, score, score_maximum, in_verdict_chain, attempted, indicator_ids}`. `tactic_ids` lists every tactic of the technique in matrix order. `attempted` is `True` when every carrying indicator marks the technique attempted (a request that the sandbox did not confirm). `score` is the highest score (0 to 100) of the indicators that carry the technique; `score_maximum` is always `100`. `indicator_ids` are `Indicator.id` values. | nested in `MitreResponse` |
| `StaticScanResponse` | Static report singleton, discriminated by `report_format`. Format-specific keys stay in `.model_extra`. | `GET /submissions/:uuid/static-scan` |
| `StaticScanFileInfo` | `{md5, sha1, sha256, ssdeep, mime_type, file_type, entropy, filesize, real_filename, real_sha256}`. | nested in `StaticScanResponse` |
| `StaticScanOneNoteEmbeddedFile` | One `oneNoteEmbeddedFiles[]` entry of an `onenote` report. Read it with `StaticScanResponse.one_note_embedded_files`. | same |
| `StringFacts` | `{observables, facts, total, truncated}`. | `GET /submissions/:uuid/static-scan/string-facts` |
| `StringObservable` | `{kind, value, count, display, host, detail, source, secret}`. | nested in `StringFacts` |
| `StringFact` | `{code, value, capability, matches, count, names}`. | nested in `StringFacts` |
| `StringsPage` | `{items, items_count, start, end, download_link}`. | `GET /submissions/:uuid/static-scan/strings/items` |
| `StringItem` | `{value, from_source, blacklist, hint}`. | nested in `StringsPage` |
| `CdrResponse` | CDR singleton: `sanitized`, `removed`, `sanitized_file_info`, `elapsed_time`. | `GET /submissions/:uuid/cdr` |
| `CdrSanitizedFileInfoDetail` | `{name, action, data, count, sha256, description, file_name, details}`. `details` nests the same model. | nested in `CdrSanitizedFileInfo` |
| `SignatureCheckResult` | Per-artifact code-signing verification result. | `GET /submissions/:uuid/signature-check` |
| `SignatureCheckResponse` | Envelope. | same |
| `OverviewSummary` | Aggregated counts for the whole submission: `indicators`, `behavior_event_count`, `syscall_count`, `ioc_count`, `yara_rule_count`, `config_count`, `artifact_count`, `mitre_technique_count`, optional `network`. | `GET /submissions/:uuid/summary` |

**Discriminative fields.**

- `Indicator.level` is `IndicatorLevel = Literal["malicious", "suspicious", "benign"] | str`. A new server value does not fail the parse.
- `Indicator.author` is `Literal["system", "user"]`.
- `Indicator.score` is `float`. The API can send a fractional score. An integer score keeps its value.
- `Indicator.score_maximum` is `int | None`: the scale of `score` (10 legacy, 100 Windows V2). `None` when the API does not send it. Divide `score` by `score_maximum` before comparing rows from different scales.
- `Indicator.summary` is `str | None`: a one-sentence plain-language summary, sent for Windows V2 schema 2.1 rows only. `None` on legacy rows and when the API does not send it. On rows with a summary, `description` holds the long analyst text.
- `Indicator.why_matched` is `str | None`: why the indicator matched, in one sentence (Windows V2 reports). `Indicator.in_verdict_chain` is `bool | None`: `True` when the indicator is part of the finding that set the verdict. Both are `None` on legacy rows and when an older server omits them.
- The Windows V2 fields of `Indicator` are `None` on legacy rows, on rows that do not carry them, and when an older server omits them:
  - `pid_gens` is `list[int] | None`: the PID generation of each entry in `pids`, in the same order. Use `pids[i]` and `pid_gens[i]` together to identify one process.
  - `rule_source` is `str | None`: the rule or signal that produced the row, for example `behavior:process_hollowing`.
  - `what_happened`, `why_it_matters`, `why_this_tier`, `outcome` are `str | None`, and `not_observed` is `list[str] | None` (schema 2.1 rows).
  - `score_note` is `str | None`: the score note as stored. The text can change between analysis versions. For machine use, read `score_factors` (`list[str] | None`), `score_result` (`float | None`, 0-100) and `score_cap` (`float | None`). When the note has no known form, `score_factors` is empty and `score_result` is `None`.
  - `related` is `list[IndicatorRelated] | None`. The list is not cut. `IndicatorRelated.event_id` is `None` when the event has no behaviour event; `t_offset_s` is `None` on rows stored before the analysis recorded the time of each event.
  - `actor` is `IndicatorActor | None`, `target` is `IndicatorTarget | None`. Their nullable fields are `None` when the analysis did not record them.
  - `t_offset_s` and `span_s` are `float | None` (seconds). `occurrences` is `int | None`.
- Rows from the submission overview have an empty `id`. On these rows, `finding_source` (`str | None`, for example `static_scan`, `config_extractor`, `ioc_extractor` or `dynamic_scan`) is the job that produced the row and has the same value as `category[0]`. `artifacts` (`list[str] | None`) lists the related `Artifact.id` values. `dynamic_indicator_id` (`str | None`) is the `id` of the dynamic row that a `dynamic_scan` overview row describes.
- `Artifact.process_attribution` is `ArtifactProcessAttribution` (`unknown`, or a new value) or `None`. `None` when an older server omits it.
- `Artifact.source` is `ArtifactSource` (`dynamic_report`, `static_report`, `url_report`, `unpacker`, `config_extractor`, `yara_generator`, `user_upload`, `manual`, or a new value). `get_artifacts(uuid, source=...)` returns only the artifacts with that value. An unknown value raises `BadRequestError`.
- `Artifact.analysis_status` is `ArtifactAnalysisStatus` (`not_analyzed`, `analyzing`, `analyzed`, `failed`, `skipped`, or a new value). `not_analyzed` means no engine job was created. `Artifact.analysis_trigger` is `ArtifactAnalysisTrigger` (`auto`, `manual`, or a new value), `None` when no analysis started. `Artifact.analysis_reason` is the reason text of a `skipped` or `failed` analysis, as the web UI shows it. `Artifact.download_link` is the path of the artifact download route; that route needs the `downloadSample` plan permission. All four are `None` when an older server omits them.
- `ArtifactJob.engine_type` is `ArtifactJobEngineType` (`ioc_extractor`, `yara_scanner`, `config_extractor`, `dynamic_scan`, `static_scan`, `signature_checker`, `cdr`, `eml_analyzer`, `url_analysis`, or a new value). `ArtifactJob.status` is `ArtifactJobStatus` (`pending`, `queued`, `running`, `waiting_callback`, `success`, `retrying`, `failed`, `skipped`, or a new value). `ArtifactJob.error_code` is `ArtifactJobErrorCode` (`JOB_FAILED`, `JOB_DEAD_LETTERED`, `JOB_SKIPPED`, or a new value) or `None` for every other status. The API never returns the platform error text.
- `IoC.type` is `IoCType = Literal["ip", "domain", "url", "email", "sha512", "sha256", "sha1", "md5", "registry", "path", "uuid"] | str`. The server compares the stored type text without case, so a stored `IP` is `ip`. Unexpected values become `path` today; a new server value does not fail the parse.
- `IoC.raw_type` is `str | None`: the type text as the extractor stored it, before the server maps it to `type`. `None` when the extractor stored no type, and when an older server omits it.
- `YaraRule.category` is `YaraRuleCategory = Literal["malicious", "suspicious", "benign"]`.
- `Artifact.type` is `ArtifactType` (17-value literal including `sample`, `dropped_file`,
  `memory_dump`, `pcap`, `yara_rule`, `email_file`, `email_attachment`, `embedded_file`,
  &hellip;). Unknown values from a newer server are kept as plain strings.
- `CdrSanitizedFileInfoDetail.data` is `list[str] | dict[str, object] | str | None`. The API
  sends a list of strings.
- `CdrSanitizedFileInfoDetail.action` is `CdrAction` (`removed`, `sanitized`, `skipped`, or a
  new value). `count`, `description` and `file_name` are `None` when the engine did not record
  them. `sha256` is `list[str] | None`. `details` holds the nested items of an inner file, for
  example a member of an archive; it is empty when there are none and on older servers.
- `StaticScanFileInfo.real_filename` and `real_sha256` come from the NSRL (National Software
  Reference Library) check. Both are `None` when the engine did not record a value and on older
  servers.
- `StaticScanResponse.one_note_embedded_files` is `list[StaticScanOneNoteEmbeddedFile] | None`.
  It is `None` when the report has no `oneNoteEmbeddedFiles` key. The new engine fields
  (`extension`, `identity`, `filesize`, `entropy`, `last_modified_time`, `embedded_file_name`,
  `source_filepath`) are `None` when the engine did not record them. `entropy` goes from 0 to
  8; 7.0 or more is a signal of packed, compressed or encrypted content, not a verdict.
- `StringObservable.kind` is `StringObservableKind` (`url`, `domain`, `ip`, `email`, `wallet`,
  `bot-token`, `webhook`, `command`, `registry`, `path`, or a new value). `value`, `display` and
  `source` always hold the full text. `secret` is a label for filters only: the API and the SDK
  never mask, cut or hide secret values. The server returns at most 500 observables of each
  kind; `StringFacts.truncated` is `True` when a kind had more.
- `StringFact.value` is a label. The text can change; use `code` for machine use.
- `StringsPage.items_count` is the number of strings that match `search` (all strings without
  `search`). `start` and `end` are the window the server applied.
- `OverviewSummary.network` is `Optional` &mdash; `None` on submissions without a
  completed dynamic report. `OverviewSummary.network` also carries `counts_available`,
  `availability` and `source_scope` (same types as `NetworkSummary`). When `counts_available`
  is `False` the counts are 0 and do not mean the sample had no network activity.

Cross-references: `Indicator.pids` points at `Process.pid` (see Dynamic Scan), 
`Indicator.attack_codes` at `MitreResponse.techniques`, `Indicator.syscall_line_numbers`
at `SyscallsResponse.items`, `IoC.artifacts` / `YaraRule.artifacts` / 
`ExtractedConfig.artifacts` / overview `Indicator.artifacts` at `Artifact.id`,
`Indicator.related[].event_id` at `BehaviourEvent.event_id`, and `Indicator.dynamic_indicator_id` at
the `id` of a dynamic `Indicator` row.

---

## Dynamic Scan

Process, behaviour, network, and syscall data captured during sandbox execution. Every
type in this group is only populated when the submission has a completed **dynamic**
report. Every endpoint is guarded by `ReportStatusGuard('dynamic')`; read the code of 
`ReportUnavailableError.code` to branch on "report not yet ready" vs. "report errored".

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Process` | Single observed process with `pid`, `ppid`, `pid_gen`, `origin`, `tid`, `name`, `cmd`, `cwd`, `image`, `method`, `timestamp`, `exit_timestamp`, `network`, `events`. `(pid, pid_gen)` identifies one process when the OS reuses a pid. `origin` is `ProcessOrigin` (`sample`, `shell`, or a new value). `timestamp` and `exit_timestamp` are unix seconds (`float`). Each new field is `None` when the report does not record it and on older servers. | `GET /submissions/:uuid/processes` |
| `ProcessesResponse` | Envelope wrapping a `List[Process]`. | same |
| `ProcessNetwork` / `ProcessNetworkItem` | Per-process network activity (`count` is authoritative, `items` may be truncated). | nested |
| `ProcessEvents` / `ProcessEventItem` | Per-process system events (files, registry, &hellip;). | nested |
| `ProcessTreeNode` | Recursive spawn-tree node. Does **not** carry network/events &mdash; only `pid`, `ppid`, `pid_gen`, `origin`, `tid`, `name`, `cmd`, `cwd`, `children`. Each `(pid, pid_gen)` is its own node. `pid_gen`, `origin` and `cwd` are `None` when the report does not record them and on older servers. | `GET /submissions/:uuid/processes/tree` |
| `ProcessTreeResponse` | `{nodes: List[ProcessTreeNode]}`. | same |
| `Killchain` | `{dump_collector_active, artifact_inventory_coverage, created_processes, dropped_files, mem_dumps}`. The kill chain timeline that the web UI kill chain view shows. Heavy route: above the per-token limit the API returns 429 (`RateLimitError`). | `GET /submissions/:uuid/killchain` |
| `KillchainProcess` | `{pid, pid_gen, origin, ppid, tid, process_name, image, cmd, method, work_dir, timestamp, exit_timestamp, events, network}`, in report order. `work_dir` is the same value as `Process.cwd`. `events` and `network` are `ProcessEvents` and `ProcessNetwork`. | nested |
| `KillchainDroppedFileGroup` / `KillchainDroppedFile` | One group for each writing process (`pid`, `pid_gen`, `process_name`, `executable_path`, `files`). A file has the `KillchainMemoryDump` fields plus the Windows V2 fields `raw_path`, `path_authority`, `path_authority_reason`, `source_actor_bound`, `capture_closed`, `retention`, `retention_detail`, `pid_gen`, `event_seq`. | nested |
| `KillchainMemoryDumpGroup` / `KillchainMemoryRegion` / `KillchainMemoryDump` | One group for each dumped process (`pid`, `process_name`, `executable_path`, `regions`). A region has `offset_start`, `offset_end` (hex strings) and `dumps`. A dump has `path`, `sha256`, `file_size`, `timestamp`, `artifact_id`, `analysis_status`, `analysis_reason`. | nested |
| `KillchainInventoryCoverage` / `KillchainCoverageCount` | `{source_status, source_error, counts, unretained_rows_omitted}`. Coverage of the Windows V2 dropped-file inventory. `counts` are `(name, value)` rows sorted by name. | nested in `Killchain` |
| `BehaviourEvent` | OS-specific behaviour event with `type`, `pid`, `ppid`, `pid_gen`, `process_name`, `operation`, `event_id`, `event_count`, `syscall_line_number`, `timestamp`, `subject`, `details`. `timestamp` is a `float` (seconds) or `None`; Windows V2 events have fractional seconds, and an event without a time has `0`. `subject` is the object the event acted on, as the web UI shows it (command line, path, registry key, mutex, endpoint or API name). `pid_gen` and `subject` are `None` when the server has no value and on older servers. With an index parameter, `details` holds the values that the web UI shows. | `GET /submissions/:uuid/behaviours` |
| `BehavioursResponse` | `{items, total, page, limit, total_pages, sorted_by, many_processes_match}`. `sorted_by` is `BehaviourPageOrder` (`eventId`, `time`, `file`, or a new value). The last two fields are set only when the request used an index parameter. | same |
| `BehaviourSummary` | `{total_count, first_timestamp, last_timestamp, by_type, by_operation, by_process, exits}`. The counts that the web UI shows above the Behaviour view. `by_type` and `by_operation` hold at most 200 `BehaviourValueCount` values; `by_process` holds at most 500 `BehaviourProcessCount` rows (`process_id`, `process_name`, `count`, `first_timestamp`, `last_timestamp`); `exits` holds `BehaviourExit` rows (`process_id`, `event_id`, `status`). | `GET /submissions/:uuid/behaviours/summary` |
| `BehaviourFacets` | `{items, complete, scanned_rows}`. `items` are `BehaviourValueCount` (`value`, `count`), most frequent first. `complete` is `False` when the read limit stopped the scan, so the counts are too low. | `GET /submissions/:uuid/behaviours/facets` |
| `BehaviourMatches` | `{items}`. One `BehaviourMatch` for each distinct text of `get_behaviour_matches()`, in the request order; empty when the run has no behaviour file. The "find in events" counts of the web UI. Heavy route. | `GET /submissions/:uuid/behaviours/match` |
| `BehaviourMatch` | `{needle, count, first_event_id, samples, complete, scanned_rows}`. `count` is the number of events whose `subject` contains `needle`, without case. `first_event_id` is the smallest matching `event_id`, or `None`. `samples` holds up to three distinct matching subjects, in file order, not masked. `complete` is `False` when the read limit stopped the scan, so the count is too low. Texts that differ only in case get the same counts. | nested in `BehaviourMatches` |
| `BehaviourEventSort` / `BehaviourFacetField` / `BehaviourFieldFilterKey` | Parameter values of `get_behaviours(sort=...)` (`eventId`, `time`), `get_behaviour_facets(field)` (`operation`, `type`, `processName`, `function`, `subject`) and the `fields` keys (`path`, `key`, `mutex`, `cmd`, `status`, `value`, &hellip;). | parameters |
| `BehaviourOs` | Deprecated compatibility alias; the endpoint derives the OS from the submission. | same |
| `SyscallsResponse` | `{items: List[str], total, page, limit, total_pages, first_line}`. `items` are raw unparsed log lines. `items[i]` is line `first_line + i`, the same number as `BehaviourEvent.syscall_line_number`. `first_line` is `None` when `items` is empty. `page`, `limit`, `total_pages` and `first_line` are `None` when an older server omits them. | `GET /submissions/:uuid/syscalls` |
| `SyscallSearchResult` | `{lines, next_from_line, scanned_to, total_count, done, truncated, busy, retry_after_seconds}`. `lines` are `SyscallSearchLine` (`line`, `raw`). Send `next_from_line` as `after_line` to get the next page; it is `None` when the scan read the last line. `busy` is `True` when the server did not scan; then `total_count` is `None` and `retry_after_seconds` gives the wait. | `GET /submissions/:uuid/syscalls/search` |
| `NetworkSummary` | `{dns_count, http_count, tcp_count, udp_count, threat_count, pcap_available, exfil_request_count, counts_available, availability, source_scope, windows_background_count, https_pcap_available, has_https_inspection, unattributed_pcap_available, attribution_counts, unattributed_counts, submission_only_alerts}`. `exfil_request_count` gives the entries of `get_network_exfil_requests()`; it is not set to 0 when `counts_available` is `False`. `windows_background_count` gives the rows that the counts and lists omit by default. Legacy reports send `counts_available=True`, `availability=None`, `source_scope=None`; all three are `None` when an older server omits them. `https_pcap_available` tells that `download_https_pcap()` has a file. `unattributed_pcap_available` is `True` when `download_pcap()` returns the full capture of a `submission_unattributed` report. `unattributed_counts` and `submission_only_alerts` are `None` when the report has none. Every field after `windows_background_count` is `None` when an older server omits it. | `GET /submissions/:uuid/network/summary` |
| `NetworkAvailability` | `{state, reason, coverage}`. Network evidence state of a Windows V2 report. | nested in `NetworkSummary` |
| `NetworkAttributionCounts` / `NetworkSourceCounts` | `{dns, http, tcp, udp, threats}`, each `{sample, sample_child, sensor_only, windows_background}`. Rows of each list by source, also the `windows_background` rows. Rows without a stored source count as `sample`. | nested in `NetworkSummary` |
| `NetworkUnattributedCounts` | `{dns, http, tcp, udp, threats}`. Records of the sensor summary of an older report that no sample process is linked to. The lists do not return them. | nested in `NetworkSummary` |
| `NetworkSubmissionOnlyAlerts` | `{scope, source, total, omitted, rows}`. Suricata alerts outside the remote addresses of the sample (`source_scope == "submission_ip_scoped"`). `rows` are at most 100 `NetworkSubmissionOnlyAlertRow` (`line_number`, `sid`, `signature`, `severity`, `protocol`, `source_ip`, `destination_ip`). `get_network_threats()` does not return them. | nested in `NetworkSummary` |
| `NetworkRowSource` | `{attribution, attribution_reason, process_id, process_image}` on every network row. `attribution` is `NetworkAttribution` (`sample`, `sample_child`, `sensor_only`, `windows_background`, or a new value). The server sends `sample` for rows of older reports; each field is `None` when an older server omits it. | base of the network rows |
| `DnsQuery` | `{id, host, type, status, status_text, records, answered, timeshift, timeshift_seconds, source_scope}` plus the `NetworkRowSource` fields. `answered` is `False` for a query that got no answer. `status` is `TIMEOUT` for such a query and `UNKNOWN` for a non-standard sensor text; `status_text` keeps the sensor text. | `GET /submissions/:uuid/network/dns` |
| `HttpRequest` | `{id, host, ip, port, country, source_scope}` plus the `NetworkRowSource` fields &mdash; slimmed-down shape. Read the method, URL, headers and bodies with `get_http_request_packets(uuid, row.id)`. | `GET /submissions/:uuid/network/http` |
| `Connection` | `{id, protocol, source_ip, source_port, destination_ip, destination_port, domain, ptr_domain, asn, country, packets, app_proto, hostname, pkts_to_server, pkts_to_client, bytes_to_server, bytes_to_client, packets_total, packets_omitted, connect_outcome, timeshift, timeshift_seconds, source_scope}` plus the `NetworkRowSource` fields. Used for both TCP and UDP. `connect_outcome` is `ConnectOutcome`: `established`, `no_response`, `refused` or `not_captured` (the process monitor saw the connect, but the capture holds no flow). `domain` is the best host name of `destination_ip` (DNS answer, TLS SNI, HTTP `Host`, reverse DNS, then sensor host name); `ptr_domain` is the reverse DNS name and can differ. `app_proto`, `hostname` and the `pkts_*`/`bytes_*` counters come from the live network sensor. `packets_omitted` counts the capture packets that the report packet limit left out. Each new field is `None` for rows of older reports and when an older server omits it. | `GET /submissions/:uuid/network/tcp`, `GET /submissions/:uuid/network/udp` |
| `ConnectionPackets` | `{sent, received, empty}`. | nested |
| `NetworkThreat` | Suricata alert: `signature`, `description`, `severity`, `severity_level`, `protocol`, `app_proto`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `timeshift`, `timeshift_seconds`, `metadata`, `details`, optional `tls`, `capture`, `source_scope`, plus the `NetworkRowSource` fields. | `GET /submissions/:uuid/network/threats` |
| `NetworkThreatTls` | TLS fingerprint block: `version`, `sni`, `ja3_hash`, `ja3s_hash`, `ja3_string`, `ja3s_string`. Present iff `app_proto == "TLS"`. | nested in `NetworkThreat` |
| `NetworkExfilRequest` | Chat bot and webhook requests from the decrypted HTTPS capture: `api`, `kind`, `host`, `method`, `api_method`, `target_id`, `masked_target`, `request_bytes`, `reply_status`, `request_count`, `capture`, `first_seen`, `score`, `tier`, `process_id`, `process_image`, `text`. `masked_target` is the request target as sent, with the full bot token or webhook secret; old reports show a shortened token. Every field is `None` when the server omits it. | `GET /submissions/:uuid/network/exfil-requests` |
| `TotalCountList[T]` | Return type of the six network list methods. It is a plain `list` of the rows with one more attribute: `total_count`, the `X-Total-Count` header (rows that match the request without `skip` and `limit`, with the same filters). `total_count` is `None` when the server does not send the header. More pages exist while `skip + len(page) < total_count`. | network lists |
| `NetworkHttpPackets` | `{items, truncated, source_scope}`. `items` are at most 200 `NetworkHttpPacket` values (`timeshift`, `url`, `method`, `destination_ip`, `destination_port`, `port_known`, `headers`, `body`, `response`). `response` is a `NetworkHttpPacketResponse` (`timeshift`, `destination_ip`, `destination_port`, `headers`, `status_code`, `body`) or `None`. When `port_known` is `False` (a sensor summary record of an older report), the ports are 0 and the headers and bodies are `None`. | `GET /submissions/:uuid/network/http/:requestId/packets` |
| `NetworkFlowPackets` | `{protocol, source_ip, source_port, destination_ip, destination_port, items, truncated, source_scope}`. `items` are at most 200 `NetworkFlowPacket` values (`type`, `data`). `type` is `NetworkPacketDirection` (`send`, `receive`, or a new value). | `GET /submissions/:uuid/network/tcp/:connectionId/packets`, `.../udp/:connectionId/packets` |
| `NetworkPacketData` | `{trimmed, sha256, md5, sha1, ssdeep, data}`. `data` is `bytes`: the SDK decodes the base64 text of the API. `model_dump(mode="json")` encodes it as base64 again. `trimmed` is `True` when the sandbox stored only the first part of the payload. The hashes cover the stored bytes and are `None` when the sandbox did not compute them. The payload is not masked. | nested in the packet models |
| `NetworkEndpoints` | `{items, total, truncated}`. `items` are `NetworkEndpoint` values (`key`, `host`, `ips`, `ports`, `protocols`, `source`, `first_timeshift`, `last_timeshift`, `request_count`, `alert_count`, `max_alert_severity`, `max_alert_severity_level`, `process_ids`, `attribution_note`), sample endpoints first. `max_alert_severity_level` is the highest alert severity as a number, `1` (high) to `4` (info); `max_alert_severity` is the deprecated text form. `total` is the count before `limit`, a lower limit when `truncated` is `True`. Send `key` as `host` to `get_network_host_flows()`. | `GET /submissions/:uuid/network/endpoints` |
| `NetworkHostFlows` | `{flows, totals, alerts, page_info, truncated}`. `flows` are `NetworkHostFlow` values (`protocol`, `remote_ip`, `remote_port`, `local_port`, `count`, `bytes_sent`, `bytes_received`, `first_timeshift`, `last_timeshift`, `process_ids`, `methods`, `sample_paths`), the busiest first. `totals` is `NetworkHostFlowTotals` (`dns_queries`, `http_requests`, `tcp_flows`, `udp_flows`). `alerts` are up to 20 `NetworkHostAlert` groups (`signature`, `severity`, `count`, `first_timeshift`), the most severe first; it is empty when an older server omits it. `page_info` is `NetworkHostFlowsPageInfo` (`end_cursor`, `has_next_page`). | `GET /submissions/:uuid/network/endpoints/:host/flows` |

**Discriminative fields.**

- `DnsQuery.type` is `DnsRecordType` (16-value literal: `A`, `AAAA`, `CNAME`, `MX`, &hellip;).
- `DnsQuery.status` is `DnsStatus` (DNS RCODE literal, e.g. `NOERROR`, `NXDOMAIN`, `TIMEOUT`, `UNKNOWN`, or any other string).
- `NetworkAvailability.state` is `NetworkAvailabilityState` (`disabled`, `unavailable`, `verified_zero`, `observed`); `coverage` is `NetworkCoverage` (`none`, `partial`, `complete`). When `NetworkSummary.counts_available` is `False`, all counts are 0 and do not mean the sample had no network activity.
- `source_scope` is `NetworkSourceScope` (`sample_attributed`, `submission_ip_scoped`, `submission_unattributed`, `none`) or `None` on legacy reports. Unknown values from a newer server are kept as plain strings.
- The list endpoints send the `X-Network-Evidence-Availability` response header on Windows V2. The SDK does not surface it. Read `get_network_summary().availability` instead. The SDK surfaces only the `X-Total-Count` header, as `TotalCountList.total_count`.
- `NetworkThreat.severity_level` is `NetworkThreatSeverityLevel` (`1` to `4`, `1` is the highest). It is `None` when the stored value is not 1 to 4 and on older servers. `NetworkHostFlow.protocol` is `NetworkHostFlowProtocol` (`DNS`, `HTTP`, `TCP`, `UDP`, or a new value).
- `Connection.protocol` is `ConnectionProtocol = Literal["tcp", "udp"]`.
- `NetworkThreat.protocol` is `ThreatProtocol = Literal["TCP", "UDP"]` (uppercase!).
- `NetworkThreat.app_proto` is `ThreatAppProto = Literal["HTTP", "TLS", "DNS"]`.
- `NetworkThreat.capture` is `NetworkThreatCapture` (`decrypted_https`, `offline_scan`, or a new value) or `None`. `decrypted_https`: Suricata matched the alert in the decrypted traffic of a relayed HTTPS connection. `offline_scan`: Suricata found the alert by scanning the recorded traffic after the run. `None` for other alerts, older reports, and older servers.
- `NetworkExfilRequest.api` is `NetworkExfilRequestApi` (`telegram_bot`, `discord_webhook`, `slack_webhook`); `kind` is `NetworkExfilRequestKind` (`poll`, `send_message`, `send_file`); `capture` is `NetworkExfilRequestCapture` (`decrypted_https`). Unknown values from a newer server are kept as plain strings.
- `NetworkThreat.severity` is `ThreatSeverity = Literal["high", "low", "info"] | str`. The API
  maps Suricata priority `1` to `high`, `2` to `low`, and `3` and `4` to `info`. Unknown values
  from a newer server are kept as plain strings.

**Kill chain fields.**

- `artifact_id` identifies the stored copy of a file. Download it with
  `download_artifact(uuid, artifact_id)`. The kill chain has no download link. `artifact_id` is
  `None` when no stored artifact of the current analysis exists for the file. Every non-null
  `artifact_id` is also in `get_artifacts()`.
- `analysis_status` is `ArtifactAnalysisStatus` and `analysis_reason` is an error code, never
  free text. Both are `None` when `artifact_id` is `None`.
- The Windows V2 file fields are `None` on V1 reports. `capture_closed` tells that the sandbox
  observed a native close of the file. It does not prove a completed write.
- `KillchainDroppedFile.path_authority` is `KillchainPathAuthority` (`literal`,
  `verified_volume_map`, `unverified`). `retention` is `KillchainFileRetention` (`retained`,
  `observed_only`, `invalid_ref`, `unavailable`, `ambiguous`, `withheld`).
- `KillchainInventoryCoverage.source_error` is `KillchainInventorySourceError`
  (`inventory_not_captured`, `inventory_coverage_missing`, `sidecar_source_unavailable`,
  `sidecar_folder_missing`, `sidecar_dir_missing`, `sidecar_count_limit`, `sidecar_byte_limit`,
  `source_unreadable`). When `source_status` is not `available`, the counts are not measured
  values. `artifact_inventory_coverage` is `None` on reports without a Windows V2 inventory.
- `dump_collector_active` is `False` when the memory dump collector did not run. Then an empty
  `mem_dumps` does not tell that no dump was possible.
- Old reports have no process times, so `timestamp` and `exit_timestamp` are `None`.
- Unknown enum values from a newer server are kept as plain strings.

---

## URL Analysis

Full URL analysis report types. Returned by `get_url_analysis()`. URL analysis is a
peer report type to dynamic/static/cdr &mdash; it is guarded separately by
`ReportStatusGuard('url_analysis')`.

| Type | Purpose |
|------|---------|
| `UrlAnalysisResponse` | Top-level report: `level`, `status`, `job_id` (the analysis run; `None` on older servers), `general_info`, `screenshot`, optional `ip_info`, `dns_records`, optional `whois`, optional `ssl_certificate`, optional `response_headers`, optional `extracted_file`, optional `threat_analysis`, `pages`, plus the scoring fields `threat_score`, `risk_level`, `privacy_score`, `privacy_risk_level`, `privacy_breakdown`, `verdict_provenance`, `impersonation_target`, `completeness`, `intel_detections`, `metafields`, `scored_at`. |
| `UrlAnalysisGeneralInfo` | `{url, domain, website_title}`. |
| `UrlAnalysisScreenshot` | `{available: bool}`. Fetch actual bytes with `client.get_screenshot(uuid)`. |
| `UrlAnalysisIpInfo` | `{ip, asn, city, country, isp, organization, threat_status}`. |
| `UrlAnalysisThreatStatus` | `{verdict, title, description}`. Reused across `ip_info`, `extracted_file`. |
| `UrlAnalysisDnsRecord` | `{type, records}`. |
| `UrlAnalysisWhoisInfo` | Parsed WHOIS: `domain_name`, `name_servers`, `creation_date`, `expiration_date`, `registrar`, `email`, `phone`, &hellip; |
| `UrlAnalysisSslCertificate` | Parsed leaf cert: `subject`, `issuer`, `renewed_at`, `expires_at`, `serial_number`, `fingerprint`. |
| `UrlAnalysisExtractedFile` | `{uuid, threat_status}`. Set when the page served a downloadable file. |
| `UrlAnalysisThreatAnalysis` | `{overview, blacklist, threat_details}`. |
| `UrlAnalysisThreatOverviewItem` | `{source, title, description, verdict}`. Per-intel-source verdict. |
| `UrlAnalysisThreatDetailItem` | `{source, details}`. Per-intel-source raw detail payload. |
| `UrlAnalysisPrivacyFactor` | `{factor, label, delta, detail}`. One contributor to the privacy score. |
| `UrlAnalysisVerdictProvenance` | `{raw_verdict, quorum_applied, allowlist_applied, collection_state, pass_}`. How the verdict was produced. `pass_` maps to the wire field `pass`. |
| `UrlAnalysisImpersonationTarget` | `{brand_name, canonical_domain, signals, confidence}`. Brand the page most likely impersonates. |
| `UrlAnalysisCompleteness` | `{measured_sources, skipped_sources, unavailable_sources, browser_collection}`. Which sources produced evidence. |
| `UrlAnalysisIntelDetection` | `{source, detection_type, severity, details}`. One threat-intelligence hit. |
| `UrlAnalysisSession` | Interactive browser session state: `state`, `collection_status`, `recording_status`, `queue_position`, `vnc_available`, `report_available`, `started_at`, `ready_at`, `expires_at`, `finished_at`, `failure_code`, `extensions_used`, `extensions_max`, `session_config`, `link`, `expired`. Returned by `get_url_analysis_session()`. |
| `UrlAnalysisSessionConfig` | `{device_profile_id, network_config_id, network_config_source, network_config_name, session_duration_seconds, device_preset_id, device_preset_name}`. Device and network choice the session runs with. `network_config_source` is `UrlAnalysisNetworkConfigSource` (`submit`, `admin-default`, or a new value). `network_config_source` and `network_config_name` are `None` when no network configuration was recorded, and on older servers. |
| `UrlAnalysisIndicators` | `{state, unavailable_reason, snapshot}`. Returned by `get_url_analysis_indicators()`. `state` is `UrlScoreIndicatorsState` (`available`, `pending`, `unavailable`, or a new value). `unavailable_reason` is `UrlScoreExplanationUnavailableReason` (`legacy`, `size_limit`, `scoring_error`, or a new value) or `None`. |
| `UrlScoreExplanation` | `{schema_version, scoring_version, job_id, pass_, scored_at, browser_snapshot, threat_score, verdict, indicators, aggregation, verdict_adjustments}`. `pass_` maps to the wire field `pass` (`UrlScorePass`: `submit`, `final`, or a new value). `scored_at` is the server text, not a `datetime`: send it unchanged to `get_url_analysis_indicator_evidence()`. `verdict` is `UrlScoreVerdict` (`unknown`, `benign`, `suspicious`, `malicious`, or a new value). |
| `UrlScoreBrowserSnapshot` | `{job_id, manifest_hash}`. Browser snapshot that the score used. |
| `UrlScoreIndicator` | `{id, rule_id, source, family, title, reason, availability, confidence, original_rule_score, weighted_points, disposition, suppressed_by, evidence_refs}`. `availability` is `UrlScoreIndicatorAvailability` (`measured`, `not_measured`, `unavailable`, or a new value). `confidence` is `UrlScoreIndicatorConfidence` (`high`, `heuristic`, or a new value). `disposition` is `UrlScoreIndicatorDisposition` (`contributing`, `informational`, `suppressed`, `no_match`, `not_measured`, `unavailable`, or a new value). `title` and `reason` are display text that can change. |
| `UrlScoreEvidenceRef` | `{kind, id, available}`. `kind` is `UrlScoreEvidenceKind` (`network`, `finding`, `intel`, `report`, or a new value). |
| `UrlScoreAggregation` | `{high_points, heuristic_points, reputation_credits, credit_scope, effective_credit, score_before_clamp, score_after_clamp, rounding_adjustment, impersonation_floor_adjustment}`. `credit_scope` is `UrlScoreCreditScope` (`heuristic`, `all`, or a new value). |
| `UrlScoreReputationCredit` | `{rule_id, eligible, nominal_points, reason}`. |
| `UrlScoreVerdictAdjustment` | `{rule_id, from_, to, reason}`. `from_` maps to the wire field `from`. |
| `UrlAnalysisIndicatorEvidence` | `{state, text, truncated}`. Returned by `get_url_analysis_indicator_evidence()`. `state` is `UrlScoreEvidenceState` (`available`, `unavailable`, or a new value). `text` is pretty-printed JSON of 8192 characters or fewer; `truncated` is `True` when the API cut it. Network evidence holds metadata only. |
| `UrlAnalysisBrowserSection` | `{section, job_id, revision, updated_at, data}`. Returned by `get_url_analysis_browser_section()`. `section` is `UrlAnalysisBrowserSectionName` (`overview`, `findings`, `tls`, `network-summary`). `revision` is the snapshot manifest hash. `updated_at` is Unix milliseconds or `None`. `data` is free-form; `network-summary` holds only `redirects`, `domainTable` and `ipTable`. The API never returns cookies, full network entries, or bodies. |

`UrlAnalysisResponse.level` is `ThreatLevel`, shared with submission level. Everything
`Optional` is intentional &mdash; a submission may have no WHOIS (e.g. raw-IP URL), no TLS
cert (plain HTTP), etc.

The scoring fields are `None` (or `[]` for `intel_detections`) until scoring finishes.
Read them after the report reaches `completed`. `threat_score`, `privacy_score` and
`UrlAnalysisPrivacyFactor.delta` are `float`, because the API can send fractional values.

---

## AI Report

The AI analyst report of a submission. Returned by `get_ai_report()`. The report is advisory:
the AI verdict never changes the submission `score` or `level`. Requires the `aiReport` plan
permission.

| Type | Purpose |
|------|---------|
| `AiReport` | HTTP 200 body: `status`, `job_id`, `verdict`, `confidence`, `agrees_with_engine`, `family`, `family_status`, `report`, `updated_at`, `reason`, `error`, `analysis_finalized`. `report` and the verdict fields are set only when `status` is `completed` or `stale`. `reason` is `finalized`, `regenerate`, or `stale_refresh`. `error` is set only when `status` is `failed`. `analysis_finalized` is `True` when the analysis score is final; `regenerate_ai_report()` needs a final score. |
| `AiReportError` | `{code}`. Machine-readable failure code, for example `PIPELINE_TIMEOUT`. The API never returns the platform error text. Treat an unknown code as a generic failure. |
| `AiReportRegenerateResult` | HTTP 202 body of `regenerate_ai_report()`: `status` (`queued`), `message`. A subclass of `AiReportPending`. Poll `get_ai_report()` for the new report. |
| `AiReportPending` | HTTP 202 body: `status` (`waiting_for_analysis`, `queued`, `in_progress`), `job_id`, `stage` (`collecting`, `screenshots`, `writing`). `job_id` and `stage` are set only for `in_progress`. Poll again later. |
| `AiReportContent` | `{summary, classification, iocs, techniques, attack_flow, narrative, screenshots, engine_agreement, recommendations, ioc_review}`. |
| `AiReportSummary` | `{verdict, confidence, text, engine_verdict, agrees_with_engine, disagreement_reason}`. |
| `AiReportClassification` / `AiReportFamily` | `{family, category, impersonated_brand}` / `{name, status, evidence}`. |
| `AiReportIoc` | `{value, kind, status, reason, evidence}`. |
| `AiReportTechnique` | `{id, name, tactic, origin, confidence, evidence}`. `origin` is `engine` or `ai_proposed`. |
| `AiReportAttackFlow` / `AiReportFlowNode` / `AiReportFlowEdge` | Attack flow graph. `AiReportFlowEdge.from_` maps to the wire field `from`. |
| `AiReportNarrative` | `{phase, text, evidence}`. One kill chain phase. |
| `AiReportScreenshot` | `{ordinal, observation, kind, threat_relevant}`. `ordinal` matches the media list. |
| `AiReportEngineAgreement` | `{engine, reported, agrees, note}`. |
| `AiReportRecommendation` | `{kind, text}`. `kind` is `containment`, `detection`, or `hunting`. |
| `AiReportIocReview` / `AiReportIocCandidate` / `AiReportIocReviewSummary` | IoC curation. The curated list is every candidate with `verdict == "valid"`. `ioc_review` is `None` on older reports and on URL submissions. `AiReportIocReviewSummary.reviewed_by_model` (an `int` or `None`) is the recorded count of candidates sent to the AI review; it is `None` on reports generated before the platform recorded the count. |
| `AiReportEvidence` | `{source, ref, label}`. Engine evidence for one statement. |

Every enum-like field (`AiVerdict`, `AiConfidence`, `AiReportStatus`, `AiReportPendingStatus`,
`AiReportProgressStage`, `AiReportQueueReason`, `AiReportErrorCode`, `AiFamilyStatus`,
`AiIocStatus`, `AiTechniqueOrigin`, `AiFlowNodeKind`,
`AiKillChainPhase`, `AiScreenshotKind`, `AiRecommendationKind`, `AiIocKind`, `AiIocVerdict`,
`AiIocDecider`, `AiEvidenceSource`) keeps an unknown value from a newer server as a plain
string. Every field except `status` is `None` when the server omits it.

---

## Verdict and Run Notes

The dynamic verdict narrative and the notes about how the dynamic run went. Returned by
`get_verdict()` and `get_run()`. Both need a dynamic report. The framework writes every text
field. The text can change between releases: show it, do not parse it.

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Verdict` | `{format, score, tier, summary, narrative, story}`. `score` is from 0 to 100. Every field is `None` for a legacy report, and for a stored verdict that does not belong to the committed analysis attempt. `summary` and `narrative` are `None` on reports older than schema 2.1. `story` is `None` on older reports and on runs that were not measured. | `GET /submissions/:uuid/verdict` |
| `VerdictNarrative` | `{headline, sequence, decisive, tier_reason, not_observed, would_raise, would_lower, coverage_note, text}`. | nested in `Verdict.narrative` |
| `VerdictSequenceEntry` | `{seq, t_offset_s, pid, image, text}`. An observed action that led to the verdict, in order. | nested in `VerdictNarrative.sequence` |
| `VerdictDecisive` | `{source, text}`. An indicator row that decided the tier. | nested in `VerdictNarrative.decisive` |
| `VerdictStory` | `{summary, truncated, steps, headline}`. `truncated` is `True` when the framework shortened the story. `headline` is `None` on stories from before the typed segments. | nested in `Verdict.story` |
| `VerdictStoryHeadline` | `{text, parts, detail}`. | nested in `VerdictStory.headline` |
| `VerdictStoryStep` | `{t_offset_s, process, category, text, count, evidence_seqs, key, parts, command, reason, caveat}`. `key`, `parts`, `command`, `reason` and `caveat` are `None` when the framework did not write them. `command` is the full command line. | nested in `VerdictStory.steps` |
| `VerdictStoryProcess` / `VerdictStoryPart` | `{image, pid}` / `{type, value}`. | nested in `VerdictStoryStep` |
| `RunNotes` | `{java_output, analysis_cut_short, network_notes, submission_hints, run_notes, is_dump_collector_activated}`. For a legacy report, `java_output` and `analysis_cut_short` are `None` and the lists are empty. | `GET /submissions/:uuid/run` |
| `RunJavaOutput` | `{summary, error, cause, text, size, truncated}`. `text` is the full stored Java console text. The sandbox worker stores only the start of a long output; `truncated` tells if it did. `size` is the number of bytes the program wrote. The API does not mask secrets in the text. | nested in `RunNotes.java_output` |
| `RunAnalysisCutShort` | `{basis, ended_at_s, requested_window_s, text, transfer}`. Set only when the framework is certain that the analysis did not see the sample finish. `transfer` (`RunUnfinishedTransfer`: `url`, `received_bytes`, `declared_bytes`) is set only for the `unfinished_download` basis. | nested in `RunNotes.analysis_cut_short` |
| `RunNote` | `{code, text}`. `code` is a stable snake_case code; new codes can appear. Show `text`. | nested in `RunNotes.submission_hints` and `RunNotes.run_notes` |

- `Verdict.tier` is `VerdictTier` (`Malicious`, `Suspicious`, `Benign`, `Not Measured`, or a
  new value). Older reports stored `Informative`; the API returns `Benign` for them.
- `VerdictStoryStep.category` is `VerdictStoryCategory` (`execution`, `persistence`,
  `network`, `credential`, `evasion`, `injection`, `file`, `registry`, `discovery`, `other`,
  or a new value). `VerdictStoryPart.type` is `VerdictStoryPartType` (`text`, `process`,
  `path`, `api`, `constant`, or a new value).
- `RunAnalysisCutShort.basis` is `RunCutShortBasis` (`monitor_stopped`,
  `unfinished_download`, `manual_stop`, or a new value). Show `text`, not this code.

---

## Annotations

The evidence pins and the note that your workspace keeps on a submission. Returned by
`get_annotations()`, `pin_evidence()`, `unpin_evidence()` and `set_note()`. Every write
returns the full view after the change.

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Annotations` | `{submission_uuid, pins, note}`. `pins` are in the order they were added. `note` is `None` when your workspace has no note. | `GET /submissions/:uuid/annotations`, `POST .../annotations/pins`, `DELETE .../annotations/pins/:pinId`, `PUT .../annotations/note` |
| `AnnotationPin` | `{id, kind, ref, label, created_by, created_at}`. Pass `id` to `unpin_evidence()`. `created_by` is a user ID. | nested in `Annotations.pins` |
| `AnnotationNote` | `{text, updated_by, updated_at}`. | nested in `Annotations.note` |

- Pins and the note belong to the workspace of the API token. Each workspace that can see the
  submission keeps its own pins and note, also on a public submission of another workspace. A
  caller never reads or changes the annotations of another workspace.
- `AnnotationPin.kind` is `AnnotationPinKind` (`finding`, `finding-group`, `process`,
  `endpoint`, `technique`, `tactic`, `events`, `moment`, `syscalls`, `file`, `indicator`,
  `artifacts`, `mail-attachment`, `mail-link`, `view`, `preview`, `family`, or a new value).
  The web UI opens the evidence only when `ref` uses the web UI format, for example
  `technique:T1055`.
- A second pin with the same `kind` and `ref` changes nothing. A workspace can keep 200 pins on
  one submission. An empty note text removes the note.

---

## Run Compare

Returned by `get_previous_run()` and `compare_runs()`. Both routes read only runs that your
workspace can open: runs of your workspace and public runs of other workspaces.

| Type | Purpose | Endpoint |
|------|---------|----------|
| `PreviousRun` | `{previous_run_uuid}`. The latest earlier run with the same SHA256 and type in the workspace of the submission. `None` when no run matches. | `GET /submissions/:uuid/previous-run` |
| `RunComparison` | `{submission_uuid, other_submission_uuid, detections, techniques, iocs, dropped_files}`. | `GET /submissions/:uuid/compare/:otherUuid` |
| `CompareDetectionDiff` | `added` / `removed` lists of `CompareDetection` (`title`, `level`), compared by title. | nested in `RunComparison.detections` |
| `CompareTechniqueDiff` | `added` / `removed` lists of uppercase MITRE ATT&CK technique IDs. | nested in `RunComparison.techniques` |
| `CompareIocDiff` | `added` / `removed` lists of `CompareIoc` (`value`, `category`), compared by category and lowercase value. | nested in `RunComparison.iocs` |
| `CompareDroppedFileDiff` | `added` / `removed` lists of `CompareDroppedFile` (`path`, `sha256`), compared by SHA256, else by lowercase path. `sha256` is `None` when the run did not hash the file. | nested in `RunComparison.dropped_files` |

- `added` items are in the run of `submission_uuid` only. `removed` items are in the run of
  `other_submission_uuid` only.
- Each list holds at most 200 items. `added_total` and `removed_total` count the items before
  that cap.
- `techniques` and `dropped_files` come from the dynamic analysis. A run without a dynamic
  analysis gives empty lists.

---

## Account

User, workspace, plan, and quota types. Returned by `get_user_info()`.

| Type | Purpose |
|------|---------|
| `UserInfo` | Top-level response: `user_info`, `plan`, `modules`. Has convenience accessors `email`, `full_name`, `workspace`, `workspace_name`, `workspace_alias`, `plan_permissions`, `ai_report_resets_at`. |
| `UserInfoDetails` | Nested user details: `email`, `full_name`, `workspace`, `limits_count`. |
| `WorkspaceBasicInfo` | `{name, alias, private, type}`. `type` is `Literal["personal", "organization"]`. |
| `LimitsCount` | Current usage: `api_request_count`, `daily_submission_count`, `concurrent_submission_count`, `ai_report_count`, `ai_report_resets_at`. `ai_report_count` counts the AI report quota units used since 00:00 UTC; a report in progress counts as used. `ai_report_resets_at` is the next 00:00 UTC. |
| `PlanInfo` | `{plan_name, start_time, end_time, starts_at, ends_at, subs_time, file_limits, submission_limits, permissions}`. `start_time` and `end_time` are display text; read `starts_at` and `ends_at` (`datetime` or `None`) in code. |
| `PlanPermissions` | `{download_sample, html_report, stix_report, pdf_report, download_report, ai_report}`. A `False` value means that the matching routes return 403. |
| `FileLimits` | `{extensions, file_size, file_size_bytes}`. `file_size` is display text; read `file_size_bytes` in code. |
| `SubmissionLimits` | `{api_limit, daily_limit, concurrent_limit, ai_report_limit}`. `ai_report_limit` is `0` when the plan has no AI report. |
| `ModuleInfo` | One enabled module: `{module_id, module_name, start_time, end_time, starts_at, ends_at}`. |

Check `account.user_info.limits_count.api_request_count` to decide whether to back off
before hammering rate-limited endpoints.

Every AI report quota field and `PlanInfo.permissions` is `None` when an older server omits it.

---

## Errors

Typed error surface. Import from the top-level `threatzone` module or from
`threatzone.types.errors` for the `ApiError` envelope class.

| Class | Kind | Key Fields |
|-------|------|------------|
| `ThreatZoneError` | Base class for every SDK error. | `message` |
| `APIError` | Base class for HTTP errors. | `status_code`, `code`, `response`, `body` |
| `AuthenticationError` (401) | Invalid/missing API key. | inherits from `APIError` |
| `PaymentRequiredError` (402) | `WORKSPACE_INACTIVE`: the workspace is not active. Renew the plan or contact the workspace owner. | `code` |
| `PermissionDeniedError` (403) | Plan permission or module missing (`FORBIDDEN`), a plan without API access (`PLAN_API_ACCESS_DENIED`, a retry does not help), or an unlicensed self-hosted deployment (`LICENSE_INVALID`). | `code` |
| `NotFoundError` (404) | `NOT_FOUND` for a missing submission and for a private submission of another workspace. Route codes such as `ARTIFACT_NOT_FOUND` and `MEDIA_NOT_FOUND`. | inherits from `APIError` |
| `BadRequestError` (400) | Validation failure (`INVALID_QUERY_PARAM`, also for a malformed UUID or ID). | `code`, `field` (`details.field`, the first field that failed) |
| `RateLimitError` (429) | `RATE_LIMIT_EXCEEDED` (heavy-route limit, monthly API request limit), `SUBMISSION_LIMIT_EXCEEDED` (daily or concurrent submission limit) or `AI_REPORT_QUOTA_EXCEEDED`. | `code`, `retry_after` (from the `Retry-After` header, else the `retryAfter` body field, else `details.retryAfterSeconds`) |
| `ReportUnavailableError` (409) | Required report not yet available. | `code`, `submission_uuid`, `required_report`, `current_status`, `available_reports` |
| `BehaviourIndexingError` (409) | `BEHAVIOUR_INDEXING` from an older server: the behaviour index is not ready. Subclass of `ReportUnavailableError`. | `code`, `retry_after` |
| `BehaviourIndexBuildingError` (503) | `BEHAVIOUR_INDEX_BUILDING`: the server builds the behaviour index and the direct read cannot answer. Subclass of `BehaviourIndexingError` and `ServiceUnavailableError`. | `code`, `retry_after` |
| `BehaviourTooLargeError` (413) | `BEHAVIOUR_TOO_LARGE`: the behaviour file or the index scan is above the read limit. Use `download_behaviour()`. | `code`, `size_bytes`, `max_bytes`, `download_route` |
| `BehaviourUnreadableError` (502) | `BEHAVIOUR_UNREADABLE`: the stored behaviour file is not a valid JSON array. Subclass of `InternalServerError`. | `code` |
| `YaraRulePendingError` (202) | YARA rule generation still in progress. | `retry_after` |
| `PdfReportPendingError` (202) | The PDF report is not ready: `download_pdf_report(wait=False)` got 202, or `download_pdf_report(wait=True)` reached its timeout. | `retry_after` |
| `ServiceUnavailableError` (503) | Any other `503`, for example `STORAGE_UNAVAILABLE`. Subclass of `InternalServerError`. | `code`, `retry_after` |
| `QuotaUnavailableError` (503) | `QUOTA_UNAVAILABLE`: the server cannot check the submission quota, so it did not create the submission. Subclass of `ServiceUnavailableError`. | `code`, `retry_after` |
| `InternalServerError` (5xx) | Server-side failure. | inherits from `APIError` |
| `TimeoutError` | HTTP request timed out. | `message` |
| `ConnectionError` | Network-level failure. | `message` |
| `AnalysisTimeoutError` | `wait_for_completion()` exceeded its timeout. | `uuid`, `elapsed` |
| `ApiError` (model) | Pydantic model of the canonical error envelope: `status_code`, `error`, `message`, `code`, `details`. | &mdash; |
| `ApiErrorCode` (literal) | The known error codes of the API, or any other string. A code that a newer server adds does not fail the parse. | &mdash; |

**ApiErrorCode values:**

`INVALID_QUERY_PARAM`, `UNAUTHORIZED`, `WORKSPACE_INACTIVE`, `PLAN_API_ACCESS_DENIED`,
`LICENSE_INVALID`, `FORBIDDEN`, `NOT_FOUND`,
`METHOD_NOT_ALLOWED`, `CONFLICT`, `ANNOTATION_PIN_LIMIT_REACHED`, `ANNOTATION_PIN_NOT_FOUND`,
`ARTIFACT_NOT_FOUND`, `SAMPLE_NOT_AVAILABLE`, `MEDIA_NOT_FOUND`,
`NETWORK_ROW_NOT_FOUND`, `URL_SCORE_EVIDENCE_NOT_FOUND`, `URL_BROWSER_SECTION_NOT_FOUND`,
`URL_BROWSER_SECTION_UNAVAILABLE`, `DYNAMIC_REPORT_UNAVAILABLE`, `STATIC_REPORT_UNAVAILABLE`,
`CDR_REPORT_UNAVAILABLE`, `URL_ANALYSIS_REPORT_UNAVAILABLE`, `RATE_LIMIT_EXCEEDED`,
`SUBMISSION_LIMIT_EXCEEDED`, `QUOTA_UNAVAILABLE`, `INTERNAL_ERROR`, `STORAGE_UNAVAILABLE`,
`BEHAVIOUR_INDEX_BUILDING`, `BEHAVIOUR_INDEXING` (older servers), `BEHAVIOUR_TOO_LARGE`,
`BEHAVIOUR_UNREADABLE`, `SESSION_SERVICE_UNAVAILABLE`, `SESSION_NOT_FOUND`, `AI_REPORT_NOT_FOUND`,
`AI_REPORTS_DISABLED`, `AI_REPORT_NOT_FINALIZED`, `AI_REPORT_IN_PROGRESS`,
`AI_REPORT_QUOTA_EXCEEDED`, `AI_REPORT_QUEUE_UNAVAILABLE`.

The API never sends `INVALID_UUID`, `SUBMISSION_PRIVATE` or `SUBMISSION_NOT_FOUND`, so they
are not in the list. A malformed UUID gives `INVALID_QUERY_PARAM`. A missing submission gives
`404 NOT_FOUND`. A private submission of another workspace gives the same response.

Always branch on `code`, never on `message`. See
[recipe 9](./RECIPES.md#9-discriminate-errors-by-their-code-field) for the full pattern.

---

## Common

Types shared across multiple surfaces.

| Type | Purpose |
|------|---------|
| `Hashes` | `{md5, sha1, sha256}`. Used by `Submission.hashes` and `ArtifactHashes`. |
| `FileInfo` | File metadata on a submission: `name`, `size`, `extension`, `mimetype`, `is_mimetype_checked`, `declared_extension`, `real_extension`, `is_mimetype_mismatched`, `entrypoint`, `source`, `history` (`FileHistory`, detail only). `declared_extension` is the lowercased extension of the original filename; `real_extension` is the extension detected from the content; `is_mimetype_mismatched` is `True` when they disagree (display only). The three fields are `None` when an older server omits them. |
| `FileSource` | `{type: Literal["upload", "url"], url}`. How the file arrived at the platform. |
| `FileEntrypoint` | `{filename}`. Entrypoint inside an archive submission. |
| `FileHistory` | `{filenames, last_received_at}`. `FileInfo.history` on `get_submission()`: every file name of the same sample (same SHA256) on the platform, newest first, without duplicates. The list includes names from other workspaces, the same as the web UI. `last_received_at` is a Unix time in milliseconds. `None` when the sample has one file name and on older servers. |
| `Tag` | `{type, value, origin, author}`. `origin` is `TagOrigin` (`dynamic`, `network`, `static`, `yara`, `config_extractor`, `signature`, `email`, `url`, `import`, or a new value): the engine that wrote a system tag. `None` for user tags, older tags, and older servers. `author` is `TagAuthor` (`system`, `user`, or a new value); `None` on older servers. |
| `ReportStatus` | Per-report state &mdash; see Submissions section. |
| `Message` | `{message}`. One-line acknowledgement returned by an action endpoint. |
| `ReportOperatingSystem` | `{name, platform}`. `platform` is `OperatingSystemPlatform` (`windows`/`linux`/`android`/`macos`) or another string. The API can send `""` when it does not know the platform. |
| `ThreatLevel` | Literal union: `unknown` / `benign` / `suspicious` / `malicious`. |
| `ReportType` | Literal union: `dynamic` / `static` / `cdr` / `url_analysis` / `open_in_browser`. |
| `ReportStatusValue` | Literal union: `error` / `not_started` / `accepted` / `in_progress` / `clean_up` / `completed`. |
| `OperatingSystemPlatform` | Literal union: `windows` / `linux` / `android` / `macos`. |

---

## Config & Downloads

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Metafields` | Metafields grouped by scan type: `sandbox`, `static`, `cdr`, `url`, `open_in_browser`. | `GET /config/metafields` |
| `MetafieldOption` | Single metafield: `key`, `label`, `description`, `type`, `default`, optional `options`. | same |
| `EnvironmentOption` | `{key, name, platform, default}`. One available OS environment. | `GET /config/environments` |
| `DevicePresetOption` | `{id, name, category, base_key, default}`. One selectable browser device preset. Pass `id` as the `device_preset` metafield. | `GET /config/device-presets` |
| `MediaFile` | `{id, name, content_type, size, kind}`. `kind` is `"video"`, `"screenshot"`, or `None`. | `GET /submissions/:uuid/media` |
| `PdfReportStatus` | `{status, message, retry_after_seconds}`. `status` is `PdfReportStatusValue` (`analysis_in_progress`, `queued`, `generating`, `ready`, `failed`, or a new value). | `GET /submissions/:uuid/download/pdf-report/status` |
| `IocExportFormat` | Literal union for `download_iocs(uuid, format=...)`: `csv`, `text`, `stix` (STIX 2.1 bundle), `misp` (MISP event JSON). `stix` and `misp` need the `stixReport` plan permission. | `GET /submissions/:uuid/download/iocs` |

Download endpoints return `DownloadResponse` (sync) or `AsyncDownloadResponse` (async)
from `threatzone._streaming`. Both are context managers; both expose `filename`,
`content_type`, `size`, `status_code`, `read()`, `iter_bytes()`, and `save(path)`.
`download_behaviour()` and `download_syscalls()` stream the raw `behaviour.json` and
`syscalls.txt` files of the dynamic analysis without changes. Both need the
`downloadReport` plan permission. Both are heavy routes and raise `RateLimitError` above the
per-token limit.
`download_artifact_yara_rule()` streams the generated YARA rule of one artifact
(`{uuid}_{artifact_id}.yar`). The first request starts the generation and raises
`YaraRulePendingError`; retry after `retry_after` seconds. The route needs no plan
permission.
`download_iocs()` streams the IP, domain, URL and SHA-256 indicators of a submission as one
file (`threatzone_iocs_{uuid}.csv`, `.txt`, or a `.json` STIX or MISP file). The file has no
grade field. The server reads at most the first 50,000 IoC records. The values are not masked.
`download_https_pcap()` streams the HTTPS inspection capture (`{uuid}_https.pcap`) with
the decrypted HTTPS traffic of the relayed connections. It needs the `downloadReport` plan
permission. Read `NetworkSummary.https_pcap_available` first.
