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
  The `X-Network-Evidence-Availability` header of the list endpoints is not exposed, because
  the list methods return plain lists. Use `get_network_summary().availability`.
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

Every method above is mirrored on `AsyncThreatZone`.

### Changed

- `ReportStatus.score`, `Indicator.score`, `UrlAnalysisResponse.threat_score`,
  `UrlAnalysisResponse.privacy_score` and `UrlAnalysisPrivacyFactor.delta` change from `int`
  to `float`. Integer values from the API stay valid. A strict type checker can now report
  code that uses these fields as `int`.
- `BehaviourEvent.timestamp` changes from `int` to `float | None`.

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
