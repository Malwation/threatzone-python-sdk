# Changelog

All notable changes to the Threat.Zone Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

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
- `UrlAnalysisResponse` carries the scoring fields: `verdict_state`, `threat_score`,
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

Every method above is mirrored on `AsyncThreatZone`.

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
