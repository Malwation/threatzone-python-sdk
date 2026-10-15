# Changelog

All notable changes to the Threat.Zone Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Network rows (`DnsQuery`, `HttpRequest`, `Connection`, `NetworkThreat`) add `attribution`,
  `attribution_reason`, `process_id` and `process_image` (new base model `NetworkRowSource`,
  new type `NetworkAttribution`). `DnsQuery` adds `status_text`. `NetworkSummary` adds
  `windows_background_count`. The network list methods accept `attribution=[...]`; when it is
  unset, the server omits `windows_background` rows. Every new field is `None` when an older
  server omits it, and existing fields do not change.
- `Indicator.summary` (`str | None`) carries the one-sentence analyst summary of Windows V2 schema 2.1 rows. It is `None` on legacy rows and when an older server omits it. On rows with a summary, `Indicator.description` holds the long analyst text.
- `Indicator.score_maximum` (`10` legacy, `100` Windows V2) gives the scale of `Indicator.score`.
- `NetworkSummary` adds `counts_available`, `availability` (new `NetworkAvailability` model
  with `state`, `reason`, `coverage`) and `source_scope`. `DnsQuery`, `HttpRequest`,
  `Connection` and `NetworkThreat` add `source_scope`. Legacy reports send `counts_available=True`, `availability=None` and `source_scope=None`. Every new field is `None` when an older server omits it. Enum-like fields accept unknown values, so a new server value does not fail the call.
  `SummaryNetwork` (`OverviewSummary.network`) adds the same three fields.
  The `X-Network-Evidence-Availability` header of the list endpoints is not exposed. Use
  `get_network_summary().availability`.
- `create_url_submission()` accepts `metafields` and `configurations`. Use
  `metafields={"timeout": ..., "device_preset": ...}` to set the interactive session
  duration and the emulated device. Use
  `configurations={"networkConfig": ..., "sessionDurationSeconds": ...}` to select an
  egress profile and the session duration (30-600 seconds).
- `get_url_analysis_session(uuid)` returns the interactive browser session state and the
  viewer link as a `UrlAnalysisSession`.
- `start_url_analysis_session(uuid)` opens a session on an existing URL submission.
- `restart_url_analysis_session(uuid)` ends the current session and starts a clean one
  with the same device and network choice.
- `restart_url_analysis(uuid)` re-runs a completed or errored URL-analysis report.
- `get_device_presets()` lists the selectable browser device presets as
  `DevicePresetOption` values.
- `list_media_files()` and `get_media_file()` accept `source="dynamic"` or
  `source="url_analysis"`. The parameter is omitted from the request when unset.
- `MediaFile.kind` reports `"video"`, `"screenshot"`, or `None`.
- `UrlAnalysisResponse` carries the scoring fields: `threat_score`,
  `risk_level`, `privacy_score`, `privacy_risk_level`, `privacy_breakdown`,
  `verdict_provenance`, `impersonation_target`, `completeness`, `intel_detections`,
  `metafields`, and `scored_at`. Each is `None` or empty until scoring finishes.
- New types: `Message`, `DevicePresetOption`, `UrlAnalysisSession`,
  `UrlAnalysisSessionConfig`, `UrlAnalysisPrivacyFactor`, `UrlAnalysisVerdictProvenance`,
  `UrlAnalysisImpersonationTarget`, `UrlAnalysisCompleteness`, and
  `UrlAnalysisIntelDetection`.
- The bundled `FakeThreatZoneAPI` serves the session, restart, and device-preset routes,
  and returns the extended URL-analysis report. The new
  `scenarios.seed_interactive_url_session()` seeds a submission with a running session.
- `Indicator` adds `why_matched` and `in_verdict_chain`. `Artifact` adds
  `process_attribution`. `SyscallsResponse` adds `page`, `limit` and `total_pages`.
  `FileInfo` adds `declared_extension`, `real_extension` and `is_mimetype_mismatched`.
  `Tag` adds `origin` (new type `TagOrigin`). `NetworkSummary` adds `exfil_request_count`.
  `NetworkThreat` adds `capture` (new type `NetworkThreatCapture`). The API already sends
  these fields. Every new field is `None` when an older server omits it.
- `get_network_exfil_requests(uuid, *, limit, skip)` returns the chat bot and webhook
  requests of the decrypted HTTPS capture as `NetworkExfilRequest` values.
  `masked_target` holds the full bot token or webhook secret as sent.
- `search_by_sha256(sha256, *, page, limit)` reads more than the first page. Without the
  parameters, the server returns the first 20 rows, as before. The SDK omits unset
  parameters.
- `download_stix_report(uuid)` downloads the STIX 2.1 bundle.
- `get_pdf_report_status(uuid)` returns a `PdfReportStatus` (`status`, `message`,
  `retry_after_seconds`).
- `download_pdf_report(uuid, *, wait=True, timeout=600, poll_interval=None)` downloads the
  PDF report. With `wait=True` it polls `get_pdf_report_status()` until the status is
  `ready`, and raises `PdfReportPendingError` after `timeout` seconds. With `wait=False` it
  raises `PdfReportPendingError` when the server answers 202.
- `get_ai_report(uuid)` returns the AI analyst report as an `AiReport`, or an
  `AiReportPending` when the server answers 202. New AI report types: `AiReportContent`,
  `AiReportSummary`, `AiReportClassification`, `AiReportFamily`, `AiReportIoc`,
  `AiReportTechnique`, `AiReportAttackFlow`, `AiReportFlowNode`, `AiReportFlowEdge`,
  `AiReportNarrative`, `AiReportScreenshot`, `AiReportEngineAgreement`,
  `AiReportRecommendation`, `AiReportIocReview`, `AiReportIocCandidate`,
  `AiReportIocReviewSummary` and `AiReportEvidence`.
- New exception: `PdfReportPendingError` (HTTP 202, `retry_after`).
- The docstrings of `download_html_report()` and `download_pdf_report()` state that the
  report shows the pinned evidence of the caller workspace. The docstrings of
  `start_url_analysis_session()` and `restart_url_analysis_session()` state that the server
  returns 409 when the URL report is in `error`.
- The bundled `FakeThreatZoneAPI` serves the exfil-request, AI report, STIX and PDF routes,
  pages the SHA-256 search, and returns the new fields.
- `Submission.score_breakdown` (new types `ScoreBreakdown`, `ScoreContributor` and
  `ScoreLayer`) explains the submission score: `deciding_layer`, `verdict`, `score`, `cap`,
  `contributors` and `what_would_change`. Only `get_submission()` sends it. The contributor
  titles and the `what_would_change` sentences can change between releases. Do not parse
  them; match on `indicator_id`.
- `Submission.score` from `get_submission()` is the live score that the web UI shows. A pure
  URL submission returns `None` until the final URL verdict.
- `get_submission()` adds `overview.duration` (the longest report run time in seconds),
  `file.history` (new type `FileHistory` with `filenames` and `last_received_at`) and
  `reports[].metafields` (the analysis options as the web UI shows them).
- `Tag.author` (new type `TagAuthor`: `system`, `user`, or a new value) tells who added
  the tag.
- Every new field is `None` when an older server omits it, and on routes that do not send
  it (`list_submissions()`, `search_by_sha256()`).
- The bundled `FakeThreatZoneAPI` returns these fields on `GET /submissions/{uuid}` only.
  `scenarios.seed_malicious_pe()` seeds a score breakdown, a file name history and report
  metafields.
- `regenerate_ai_report(uuid)` queues a new AI analyst report and returns an
  `AiReportRegenerateResult` (`status == "queued"`, `message`). The result is an
  `AiReportPending`. Poll `get_ai_report()` for the new report. The caller must be the
  submitter or a workspace admin, the plan must have the `aiReport` permission, and the
  analysis score must be final. A 409 raises `ReportUnavailableError` with
  `code == "AI_REPORT_NOT_FINALIZED"` or `"AI_REPORT_IN_PROGRESS"`. A used daily quota raises
  `RateLimitError`; `retry_after` gives the seconds until 00:00 UTC.
- `AiReport` adds `reason` (new type `AiReportQueueReason`: `finalized`, `regenerate`,
  `stale_refresh`), `error` (new type `AiReportError` with only `code`, new type
  `AiReportErrorCode`) and `analysis_finalized`. The API never returns the platform error
  text. `AiReportIocReviewSummary.reviewed_by_model` is `None` on reports generated before the
  platform recorded the count.
- `get_user_info()` adds `LimitsCount.ai_report_count`, `LimitsCount.ai_report_resets_at`,
  `SubmissionLimits.ai_report_limit` and `PlanInfo.permissions` (new type `PlanPermissions`:
  `download_sample`, `html_report`, `stix_report`, `pdf_report`, `download_report`,
  `ai_report`). `UserInfo.plan_permissions` and `UserInfo.ai_report_resets_at` are shortcuts.
  Every new field is `None` when an older server omits it.
- The bundled `FakeThreatZoneAPI` serves `POST /submissions/{uuid}/ai-report/regenerate`. It
  returns 409 `AI_REPORT_NOT_FINALIZED` before the analysis completes. After a regenerate, the
  next `get_ai_report()` returns `queued`, and the read after that returns the report with
  `reason == "regenerate"`. `GET /me` returns the AI report quota and the plan permissions.
- `Indicator` adds the Windows V2 fields `pid_gens`, `rule_source`, `what_happened`,
  `why_it_matters`, `why_this_tier`, `not_observed`, `outcome`, `score_note`,
  `score_factors`, `score_result`, `score_cap`, `related`, `actor`, `target`, `t_offset_s`,
  `span_s` and `occurrences`. New types: `IndicatorRelated`, `IndicatorRelatedActor`,
  `IndicatorActor` and `IndicatorTarget`. `related` is not cut. The `score_note` text can
  change; read `score_factors`, `score_result` and `score_cap` for machine use.
- Overview rows of `get_indicators()` (rows with an empty `id`) add `finding_source`,
  `artifacts` and `dynamic_indicator_id`. `finding_source` has the same value as
  `category[0]` on these rows.
- `IoC.raw_type` holds the type text as the extractor stored it, before the server maps it to
  `type`.
- `Artifact` adds `analysis_status` (new type `ArtifactAnalysisStatus`), `analysis_trigger`
  (new type `ArtifactAnalysisTrigger`), `analysis_reason` and `download_link`.
- `get_artifacts(uuid, *, source=None)` returns only the artifacts with the given stored
  source value (new type `ArtifactSource`). An unknown value raises `BadRequestError`. The
  SDK omits the parameter when it is unset.
- `get_artifact_jobs(uuid, artifact_id)` returns the engine analysis jobs of an artifact as a
  list of `ArtifactJob` (`engine_type`, `status`, `error_code`), oldest first. New types:
  `ArtifactJobEngineType`, `ArtifactJobStatus` and `ArtifactJobErrorCode`. The API returns
  only a fixed error code, never the platform error text. An artifact of another submission
  raises `NotFoundError` (`ARTIFACT_NOT_FOUND`).
- Every new field is `None` when an older server omits it. Enum-like fields accept unknown
  values, so a new server value does not fail the call.
- The bundled `FakeThreatZoneAPI` serves `GET /submissions/{uuid}/artifacts/{artifactId}/jobs`,
  applies the `source` filter of `GET /submissions/{uuid}/artifacts`, and returns the new
  indicator, IoC and artifact fields. `scenarios.seed_malicious_pe()` seeds an IoC stored as
  `IP`, which the fake returns as `type == "ip"` and `raw_type == "IP"`.
- `MitreResponse.items` (`list[MitreTechniqueUsage] | None`) has one entry for each matched
  technique that is in the ATT&CK catalog of the platform, sorted by `technique_id`. New type
  `MitreTechniqueUsage` gives `technique_id`, `name`, `tactic_ids`, `score` (0 to 100),
  `score_maximum` (always `100`), `in_verdict_chain` and `indicator_ids` (`Indicator.id`
  values). A code that is not in the catalog is in `techniques` but not in `items`, so `items`
  can be shorter than `techniques`. `items` is `None` when an older server omits it.
- `Process` adds `pid_gen`, `origin` (new type `ProcessOrigin`: `sample`, `shell`, or a new
  value), `image`, `method`, `timestamp` and `exit_timestamp` (unix seconds, `float`).
  `ProcessTreeNode` adds `pid_gen`, `origin` and `cwd`. `(pid, pid_gen)` identifies one
  process when the OS reuses a pid; the server gives each incarnation its own tree node.
- `BehaviourEvent` adds `pid_gen` and `subject` (the object the event acted on, as the web UI
  shows it). `BehavioursResponse` adds `sorted_by` (new type `BehaviourPageOrder`) and
  `many_processes_match`.
- `get_behaviours()` accepts `event_ids` and the index filters `pids`, `parent_pids`, `types`,
  `operations`, `statuses`, `process_name_contains`, `from_timestamp`, `to_timestamp`,
  `syscall_line_from`, `syscall_line_to`, `text`, `fields` (sent as `field.<key>`, new type
  `BehaviourFieldFilterKey`) and `sort` (new type `BehaviourEventSort`). All are keyword-only
  and the SDK omits unset values. A call without the new parameters sends the same request
  as before.
- `get_behaviour_summary(uuid)` returns a `BehaviourSummary` (new types `BehaviourValueCount`,
  `BehaviourProcessCount` and `BehaviourExit`). `get_behaviour_facets(uuid, field, *,
  contains=None, first=None, ...)` returns a `BehaviourFacets` (new type
  `BehaviourFacetField`) and accepts the same filters as `get_behaviours()`, without `text`.
- `SyscallsResponse.first_line` gives the line number of `items[0]`.
  `search_syscalls(uuid, *, query, pids=None, failed_only=None, apis=None, after_line=None,
  limit=None)` returns a `SyscallSearchResult` (new type `SyscallSearchLine`).
- `download_behaviour(uuid)` and `download_syscalls(uuid)` stream the raw `behaviour.json` and
  `syscalls.txt` files. Both need the `downloadReport` plan permission.
- New exceptions: `BehaviourIndexingError` (409 `BEHAVIOUR_INDEXING`, subclass of
  `ReportUnavailableError`, `retry_after`), `BehaviourTooLargeError` (413
  `BEHAVIOUR_TOO_LARGE`, `size_bytes`, `max_bytes`, `download_route`) and
  `BehaviourUnreadableError` (502 `BEHAVIOUR_UNREADABLE`, subclass of
  `InternalServerError`). `ApiErrorCode` adds the three codes. The behaviour index routes and
  the index parameters raise `BehaviourIndexingError` when the index is not ready; the public
  API never builds the index.
- `get_behaviour_summary()`, `get_behaviour_facets()` and `search_syscalls()` are heavy routes
  with a per-token request limit. Above the limit they raise `RateLimitError`.
  `RateLimitError.retry_after` reads the `Retry-After` header and, when the header is absent,
  the `retryAfter` body field.
- The bundled `FakeThreatZoneAPI` serves the summary, facet, syscall search and raw download
  routes, applies the behaviour index filters, and returns the new process, behaviour and
  syscall fields. `mark_behaviour_index_missing(uuid)` makes the index routes return 409
  `BEHAVIOUR_INDEXING`. `deny_download_report(uuid)` makes the raw downloads return 403. The
  fake run has a second behaviour event and Windows-style syscall lines.
- `get_killchain(uuid)` returns the kill chain timeline of the dynamic analysis as a
  `Killchain`: `dump_collector_active`, `artifact_inventory_coverage`, `created_processes`,
  `dropped_files` and `mem_dumps`. New types: `KillchainProcess`, `KillchainDroppedFileGroup`,
  `KillchainDroppedFile`, `KillchainMemoryDumpGroup`, `KillchainMemoryRegion`,
  `KillchainMemoryDump`, `KillchainInventoryCoverage`, `KillchainCoverageCount`,
  `KillchainPathAuthority`, `KillchainFileRetention` and `KillchainInventorySourceError`.
  Each file has an `artifact_id` instead of a download link. Download the file with
  `download_artifact(uuid, artifact_id)`. `artifact_id` is `None` when no stored artifact of
  the current analysis exists for the file. The route is a heavy route; above the per-token
  limit it raises `RateLimitError`. A missing dynamic report raises `ReportUnavailableError`.
- The bundled `FakeThreatZoneAPI` serves `GET /submissions/{uuid}/killchain`. The dropped file
  links to the first seeded artifact; the memory dump has no stored artifact.
- `Connection` adds `source_ip`, `source_port`, `ptr_domain` and the live network sensor
  fields `app_proto`, `hostname`, `pkts_to_server`, `pkts_to_client`, `bytes_to_server`,
  `bytes_to_client`, `packets_total` and `packets_omitted`. `ptr_domain` is the reverse DNS
  name of `destination_ip`; `domain` stays the best host name. `NetworkThreat` adds
  `source_ip`, `source_port` and `severity_level` (new type `NetworkThreatSeverityLevel`,
  `1` is the highest). Every new field is `None` for rows of older reports and when an older
  server omits it.
- `NetworkSummary` adds `https_pcap_available`, `has_https_inspection`,
  `unattributed_pcap_available`, `attribution_counts` (new types `NetworkAttributionCounts`,
  `NetworkSourceCounts`), `unattributed_counts` (new type `NetworkUnattributedCounts`) and
  `submission_only_alerts` (new types `NetworkSubmissionOnlyAlerts`,
  `NetworkSubmissionOnlyAlertRow`). Every new field is `None` when an older server omits it.
- `get_http_request_packets(uuid, request_id)` returns the stored request and response pairs
  of one HTTP row as `NetworkHttpPackets`. `get_tcp_connection_packets(uuid, connection_id)`
  and `get_udp_connection_packets(uuid, connection_id)` return the stored packets of one
  connection as `NetworkFlowPackets`. `NetworkPacketData.data` holds the payload as `bytes`,
  decoded from base64, with the `sha256`, `md5`, `sha1` and `ssdeep` hashes and `trimmed`.
  The payloads are not masked. A row ID of another submission raises `NotFoundError`
  (`NETWORK_ROW_NOT_FOUND`, added to `ApiErrorCode`).
- `get_network_endpoints(uuid, *, attribution, limit)` returns the network map endpoints as
  `NetworkEndpoints`. `get_network_host_flows(uuid, host, *, attribution, first, after)`
  returns one page of the flows, totals and alert groups of one endpoint as
  `NetworkHostFlows`. The SDK percent-encodes `host`. Both are heavy routes; above the
  per-token limit they raise `RateLimitError`.
- `download_https_pcap(uuid)` downloads the HTTPS inspection capture with the decrypted
  HTTPS traffic. The plan needs the `downloadReport` permission; without it the call raises
  `PermissionDeniedError`.
- The network list methods (`get_dns_queries`, `get_http_requests`, `get_tcp_connections`,
  `get_udp_connections`, `get_network_threats`, `get_network_exfil_requests`) return a
  `TotalCountList`. It is a `list` subclass, so existing code does not change.
  `total_count` is the `X-Total-Count` header: the rows that match the request without
  `skip` and `limit`. It is `None` when an older server does not send the header.
- The bundled `FakeThreatZoneAPI` serves the packet, endpoint, host flow and HTTPS capture
  routes, pages the network lists with `limit` and `skip`, and sends `X-Total-Count`.
  `mark_https_pcap_missing(uuid)` makes the HTTPS capture download return 404.
- `StaticScanFileInfo` adds `real_filename` and `real_sha256` from the NSRL (National
  Software Reference Library) check. Both are `None` when the engine did not record a value.
- `StaticScanResponse.one_note_embedded_files` returns the `oneNoteEmbeddedFiles` entries of
  an `onenote` report as `StaticScanOneNoteEmbeddedFile` values (common embedded-file fields
  plus `extension`, `identity`, `filesize`, `entropy`, `last_modified_time`,
  `embedded_file_name` and `source_filepath`). The raw list stays in `.model_extra`.
- `CdrSanitizedFileInfoDetail` adds `count`, `sha256` (`list[str] | None`), `description`,
  `file_name` and nested `details` (same shape). `action` is `CdrAction` (`removed`,
  `sanitized`, `skipped`, or a new value).
- `get_static_scan_string_facts(uuid)` returns the observables and facts of the extracted
  strings as `StringFacts` (new types `StringObservable`, `StringObservableKind` and
  `StringFact`). `value`, `display` and `source` always hold the full text. `secret` is a
  label for filters only. The SDK does not mask, cut or hide secret values.
- `get_static_scan_strings_page(uuid, *, start=None, end=None, search=None)` returns one
  window of the extracted strings as `StringsPage` (new type `StringItem`). The server filters
  by `search` first and then applies the window. `end - start` must be 1000 or less. The SDK
  omits unset parameters. Both string routes are heavy routes; above the per-token limit they
  raise `RateLimitError`.
- The bundled `FakeThreatZoneAPI` serves the string facts and strings window routes, applies
  the window and search rules, and returns the NSRL fields and nested CDR details.

- `UrlAnalysisResponse.job_id` identifies the URL analysis run. A restart starts a new run
  with a new `job_id`. `UrlAnalysisSessionConfig` adds `network_config_source` (`submit`,
  `admin-default`, or a new value) and `network_config_name`. All three are `None` on older
  servers.
- `get_url_analysis_indicators(uuid)` returns the URL score explanation as
  `UrlAnalysisIndicators` (new types `UrlScoreExplanation`, `UrlScoreIndicator`,
  `UrlScoreEvidenceRef`, `UrlScoreAggregation`, `UrlScoreReputationCredit`,
  `UrlScoreVerdictAdjustment` and `UrlScoreBrowserSnapshot`). All plans can use it.
- `get_url_analysis_indicator_evidence(uuid, indicator_id, reference_id, *, job_id=None,
  scored_at=None)` returns one evidence item as `UrlAnalysisIndicatorEvidence`. When
  `job_id` or `scored_at` is `None`, the SDK reads the explanation first and uses the
  snapshot values.
- `get_url_analysis_browser_section(uuid, section)` returns one approved browser section as
  `UrlAnalysisBrowserSection`: `overview`, `findings`, `tls` or `network-summary`. The API
  never returns cookies, full network entries, or request and response bodies.
- `ApiErrorCode` adds `URL_SCORE_EVIDENCE_NOT_FOUND`, `URL_BROWSER_SECTION_NOT_FOUND` and
  `URL_BROWSER_SECTION_UNAVAILABLE`.
- The bundled `FakeThreatZoneAPI` serves the URL score explanation, evidence and browser
  section routes, and returns the run `jobId` and the network configuration source and name.
- `download_iocs(uuid, *, format)` downloads the IP, domain, URL and SHA-256 indicators of a
  submission as one file. `format` is `IocExportFormat`: `csv`, `text`, `stix` (STIX 2.1
  bundle) or `misp` (MISP event JSON). `stix` and `misp` need the `stixReport` plan
  permission; without it the call raises `PermissionDeniedError`. The file has no grade field
  and the values are not masked. The server reads at most the first 50,000 IoC records.
- `get_verdict(uuid)` returns the Windows V2 verdict with its narrative and story as a
  `Verdict`. New types: `VerdictNarrative`, `VerdictSequenceEntry`, `VerdictDecisive`,
  `VerdictStory`, `VerdictStoryHeadline`, `VerdictStoryStep`, `VerdictStoryProcess`,
  `VerdictStoryPart`, `VerdictTier`, `VerdictStoryCategory` and `VerdictStoryPartType`. Every
  field is `None` for a legacy report.
- `get_run(uuid)` returns the run facts as `RunNotes`: `java_output` (`RunJavaOutput`, the
  full stored Java console text), `analysis_cut_short` (`RunAnalysisCutShort`,
  `RunUnfinishedTransfer`, `RunCutShortBasis`), `network_notes`, `submission_hints`,
  `run_notes` (`RunNote`) and `is_dump_collector_activated`. Both routes need a dynamic report
  and raise `ReportUnavailableError` without it.
- `get_annotations(uuid)` returns the evidence pins and the note of your workspace as
  `Annotations` (`AnnotationPin`, `AnnotationNote`, `AnnotationPinKind`).
  `pin_evidence(uuid, *, kind, ref, label)`, `unpin_evidence(uuid, pin_id)` and
  `set_note(uuid, text)` change them and return the full view. These are the first SDK
  methods that write data. Your workspace can annotate every submission that it can see, also
  a public submission of another workspace; the annotations stay in your workspace. A caller
  never reads or changes the annotations of another workspace. An empty note text removes the
  note.
- `get_previous_run(uuid)` returns the latest earlier run of the same sample or URL as
  `PreviousRun`. `compare_runs(uuid, other_uuid)` returns the detection, technique, IoC and
  dropped-file difference of two runs as `RunComparison` (`CompareDetectionDiff`,
  `CompareTechniqueDiff`, `CompareIocDiff`, `CompareDroppedFileDiff`, `CompareDetection`,
  `CompareIoc`, `CompareDroppedFile`). Each list holds at most 200 items; `added_total` and
  `removed_total` count the items before that cap.
- `search_by_sha256(sha256, *, page, limit, scope)` accepts `scope` (new type
  `SubmissionSearchScope`): `workspace` (the server default) or `public`. `public` returns
  only public submissions of all workspaces, also URL submissions whose downloaded payload has
  the SHA256. The SDK omits `scope` when it is `None`, so the request does not change.
- `ApiErrorCode` adds `FORBIDDEN`, `NOT_FOUND`, `ANNOTATION_PIN_LIMIT_REACHED` and
  `ANNOTATION_PIN_NOT_FOUND`.
- The bundled `FakeThreatZoneAPI` serves the verdict, run, annotation, previous-run, compare
  and IoC export routes, and applies the `scope` rule of the SHA-256 search. On these routes a
  private submission of another workspace returns 404 `NOT_FOUND`. New helpers:
  `register_previous_run(uuid, ...)` seeds an earlier run of the same sample, and
  `deny_stix_report(uuid)` makes the `stix` and `misp` exports return 403.

Every method above is mirrored on `AsyncThreatZone`.

### Changed

- `ReportStatus.score`, `Indicator.score`, `UrlAnalysisResponse.threat_score`,
  `UrlAnalysisResponse.privacy_score` and `UrlAnalysisPrivacyFactor.delta` change from `int`
  to `float`. Integer values from the API stay valid. A strict type checker can now report
  code that uses these fields as `int`.
- `BehaviourEvent.timestamp` changes from `int` to `float | None`.
- `Artifact.source` changes from `str` to `ArtifactSource` (the known values, or any other
  string). Runtime values do not change.

### Removed

- `UrlAnalysisResponse.verdict_state` is removed. The API no longer sends `verdictState`.
  Read `UrlAnalysisResponse.status`: the URL report stays `in_progress` until the final score
  and is `completed` after that. Code that reads `verdict_state` now raises `AttributeError`.

### Fixed

- `get_behaviours` no longer fails on Windows V2 events. Their `timestamp` has fractional
  seconds (for example `1790376279.35`).
- `get_network_threats` no longer fails on `info` alerts. `ThreatSeverity` adds `info` and
  keeps unknown values as plain strings.
- `get_artifacts` no longer fails on EML, Office, PDF, RTF and OneNote submissions.
  `ArtifactType` adds `email_file`, `email_attachment` and `embedded_file`, and keeps unknown
  values as plain strings.
- `get_cdr_results` no longer fails when `CdrSanitizedFileInfoDetail.data` is a list of
  strings. `data` accepts a list of strings, an object or a string.
- A fractional score no longer fails the whole call (`ReportStatus.score`, `Indicator.score`,
  the URL-analysis scores and `UrlAnalysisPrivacyFactor.delta`).
- `ReportOperatingSystem.platform` accepts an empty string and other values outside
  `OperatingSystemPlatform`.
- Server fix: `get_overview_summary()` counts each Windows V2 schema 2.1 dynamic indicator
  row once. Before the fix, `indicators.total` and `indicators.levels` counted such a row two
  times: once as the dynamic row and once as its overview row. The counts can drop for those
  reports. They now match `get_indicators()` without filters.
- Server fix: `IoC.type` is always lowercase. The server compares the stored type text without
  case, so an IoC stored as `IP` returns `type == "ip"` instead of `path`, and
  `get_iocs(uuid, type="ip")` also returns it. Read `IoC.raw_type` for the stored text.

## 1.1.1

### Fixed

- `get_behaviours` no longer requires or sends the obsolete `os` query parameter.
- `BehavioursResponse` now matches the Public API pagination envelope with `page`,
  `limit`, and `total_pages` instead of the obsolete `os` field.
- The SDK version and `User-Agent` header are now `1.1.1`.

## 1.1.0

API-sync release: brings the SDK into exact agreement with the current
`public-api` HTTP contract. Includes three breaking response-shape changes
(jobs, CDR, static-scan) alongside additive fields and endpoints.

### Breaking

- **Submission overview `jobs` reshape:** `SubmissionOverviewJobs` now carries
  `total`, `succeeded`, `failed`, `skipped`, and `finished`. `completed` is
  retained as a **deprecated** alias of `finished` (always equal) for
  backward compatibility; new code should use `finished`.
- **CDR response is a per-submission singleton:** `CdrResponse` was rewritten
  from an items envelope to a single object
  (`submission`, `status`, `sanitized`, `removed`, `sanitizedFileInfo`,
  `elapsedTime`, `metafields`). The old `CdrResult` envelope is gone.
- **Static-scan response is a per-format singleton:** `StaticScanResponse` was
  rewritten from an items envelope to a single object discriminated by
  `reportFormat` (`submission`, `status`, `reportFormat`, `level`, `score`,
  `fileInfo`, `strings`, `dieResults`, `analysisTime`, `metafields`).
  Format-specific inlined keys are preserved as model extras
  (`extra="allow"`). The old `StaticScanResult` envelope is gone.

### Added

- `Submission.score` (`float | None`) and `Submission.family` (`str | None`).
- `ReportStatus.duration` (`float | None`).
- `OverviewSummary.score` (`float | None`) and `OverviewSummary.family`
  (`str | None`).
- Config `active` / `accessible` flags on metafield options, metafield option
  values, and environment options.
- `get_static_scan_strings(uuid)` — streams the raw extracted-strings JSON
  for a static report.
- `list_network_configs()` — lists the workspace's network configurations via
  `GET /v1/network-configs`; new `NetworkConfigListItem` /
  `NetworkConfigListResponse` models.
- Request parameters: `safe_browsing` on `create_url_submission`;
  `sort` / `order` on `list_submissions`; `type` / `process_name` on
  `get_behaviours`.

### Changed

- `Indicator.category` is now `list[str]` (was a scalar `str`).
- `User-Agent` header bumped to `threatzone-python-sdk/1.1.0`.
- Fixed the `configurations` docstring key on `create_sandbox_submission` /
  `create_open_in_browser_submission` to `networkConfig` (the only key the
  API accepts).
