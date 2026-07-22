# Changelog

All notable changes to the Threat.Zone Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
