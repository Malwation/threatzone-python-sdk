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
| `SubmissionListItem` | One row in a paginated list. Carries enrichment (indicators rollup, overview). | `GET /submissions` |
| `PaginatedSubmissions` | Full list envelope with `items`, `total`, `page`, `limit`, `total_pages`. | `GET /submissions` |
| `Submission` | Full submission detail including `file`, `mitre_techniques`, `overview`. | `GET /submissions/:uuid`, `GET /submissions/search/sha256/:sha256` |
| `SubmissionOverview` | Aggregated analysis status + job progress (`status`, optional `jobs`). | Nested in `Submission` and `SubmissionListItem` |
| `SubmissionIndicatorsRollup` | Severity rollup attached to a submission (`levels`, `artifact_count`). | Nested in `Submission` and `SubmissionListItem` |
| `ReportStatus` | Per-report state (`type`, `status`, `level`, `score`, `format`, `operating_system`). | Nested `reports[]` on `Submission` |

**Discriminative fields.**

- `Submission.level` is `ThreatLevel = Literal["unknown", "benign", "suspicious", "malicious"]`.
- `Submission.type` is `Literal["file", "url"]`.
- `Submission.reports[].status` is `Literal["error", "not_started", "accepted", "in_progress", "clean_up", "completed"]`.
- `Submission.reports[].type` is `Literal["dynamic", "static", "cdr", "url_analysis", "open_in_browser"]`.
- `Submission.is_complete()` returns `True` when every report is in `completed` or `error`.

Related: `Tag`, `FileInfo`, `Hashes` (in `threatzone.types.common`).

---

## Indicators Surface

Everything under the "observation" streams produced by the analysis pipeline. Every type
in this group is envelope-wrapped (`items`, `total`) for server-side pagination.

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Indicator` | A single rule hit with cross-reference IDs. Fields: `id`, `name`, `description`, `category`, `level`, `score`, `pids`, `attack_codes`, `event_ids`, `syscall_line_numbers`, `author`. | `GET /submissions/:uuid/indicators` |
| `IndicatorsResponse` | `{items, total, levels}` envelope. `levels` is a `{malicious, suspicious, benign}` severity rollup. | same |
| `IndicatorLevels` | Severity counts: `malicious`, `suspicious`, `benign`. | nested |
| `IoC` | `{type, value, artifacts}`. `type` is the 11-value literal below. | `GET /submissions/:uuid/iocs` |
| `IoCsResponse` | Paginated IoC envelope. | same |
| `YaraRule` | `{rule, category, artifacts}`. `category` is `malicious`/`suspicious`/`benign`. | `GET /submissions/:uuid/yara-rules` |
| `YaraRulesResponse` | Paginated YARA rule envelope. | same |
| `ExtractedConfig` | `{family, config, c2s, artifacts}`. `config` is a free-form family-specific dict. | `GET /submissions/:uuid/extracted-configs` |
| `ExtractedConfigsResponse` | Paginated extracted config envelope. | same |
| `Artifact` | `{id, filename, size, type, source, hashes, tags}`. SHA-256 is under `hashes.sha256`. | `GET /submissions/:uuid/artifacts` |
| `ArtifactHashes` | `{md5, sha1, sha256}`. | nested in `Artifact` |
| `ArtifactsResponse` | Paginated artifact envelope. | same |
| `EmlAnalysis` | Parsed `.eml` artifact: `headers`, `other_headers`, `attachments`, `qr_results`, `artifact`. | `GET /submissions/:uuid/eml-analysis` |
| `MitreResponse` | `{techniques: List[str], total}`. Sorted, de-duplicated MITRE IDs. | `GET /submissions/:uuid/mitre` |
| `StaticScanResult` | Per-artifact static analyzer output. `data` is engine-specific. | `GET /submissions/:uuid/static-scan` |
| `StaticScanResponse` | Envelope. | same |
| `CdrResult` | Per-artifact CDR transformation record. | `GET /submissions/:uuid/cdr` |
| `CdrResponse` | Envelope. | same |
| `SignatureCheckResult` | Per-artifact code-signing verification result. | `GET /submissions/:uuid/signature-check` |
| `SignatureCheckResponse` | Envelope. | same |
| `OverviewSummary` | Aggregated counts for the whole submission: `indicators`, `behavior_event_count`, `syscall_count`, `ioc_count`, `yara_rule_count`, `config_count`, `artifact_count`, `mitre_technique_count`, optional `network`. | `GET /submissions/:uuid/summary` |

**Discriminative fields.**

- `Indicator.level` is `IndicatorLevel = Literal["malicious", "suspicious", "benign"]`.
- `Indicator.author` is `Literal["system", "user"]`.
- `IoC.type` is `IoCType = Literal["ip", "domain", "url", "email", "sha512", "sha256", "sha1", "md5", "registry", "path", "uuid"]`.
- `YaraRule.category` is `YaraRuleCategory = Literal["malicious", "suspicious", "benign"]`.
- `Artifact.type` is `ArtifactType` (14-value literal including `sample`, `dropped_file`,
  `memory_dump`, `pcap`, `yara_rule`, &hellip;).
- `OverviewSummary.network` is `Optional` &mdash; `None` on submissions without a
  completed dynamic report.

Cross-references: `Indicator.pids` points at `Process.pid` (see Dynamic Scan), 
`Indicator.attack_codes` at `MitreResponse.techniques`, `Indicator.syscall_line_numbers`
at `SyscallsResponse.items`, `IoC.artifacts` / `YaraRule.artifacts` / 
`ExtractedConfig.artifacts` at `Artifact.id`.

---

## Dynamic Scan

Process, behaviour, network, and syscall data captured during sandbox execution. Every
type in this group is only populated when the submission has a completed **dynamic**
report. Every endpoint is guarded by `ReportStatusGuard('dynamic')`; read the code of 
`ReportUnavailableError.code` to branch on "report not yet ready" vs. "report errored".

| Type | Purpose | Endpoint |
|------|---------|----------|
| `Process` | Single observed process with `pid`, `ppid`, `tid`, `name`, `cmd`, `cwd`, `network`, `events`. | `GET /submissions/:uuid/processes` |
| `ProcessesResponse` | Envelope wrapping a `List[Process]`. | same |
| `ProcessNetwork` / `ProcessNetworkItem` | Per-process network activity (`count` is authoritative, `items` may be truncated). | nested |
| `ProcessEvents` / `ProcessEventItem` | Per-process system events (files, registry, &hellip;). | nested |
| `ProcessTreeNode` | Recursive spawn-tree node. Does **not** carry network/events &mdash; only `pid`, `ppid`, `tid`, `name`, `cmd`, `children`. | `GET /submissions/:uuid/processes/tree` |
| `ProcessTreeResponse` | `{nodes: List[ProcessTreeNode]}`. | same |
| `BehaviourEvent` | OS-specific behaviour event with `type`, `pid`, `ppid`, `process_name`, `operation`, `event_id`, `event_count`, `syscall_line_number`, `timestamp`, `details`. | `GET /submissions/:uuid/behaviours` |
| `BehavioursResponse` | `{items, total, os}`. | same |
| `BehaviourOs` | `Literal["windows", "linux", "android", "macos"]`. **Required** query parameter. | same |
| `SyscallsResponse` | `{items: List[str], total}`. `items` are raw unparsed log lines. | `GET /submissions/:uuid/syscalls` |
| `NetworkSummary` | `{dns_count, http_count, tcp_count, udp_count, threat_count, pcap_available}`. | `GET /submissions/:uuid/network/summary` |
| `DnsQuery` | `{id, host, type, status, records, timeshift}`. | `GET /submissions/:uuid/network/dns` |
| `HttpRequest` | `{id, host, ip, port, country}` &mdash; slimmed-down shape, no method/URL/headers. | `GET /submissions/:uuid/network/http` |
| `Connection` | `{id, protocol, destination_ip, destination_port, domain, asn, country, packets, timeshift}`. Used for both TCP and UDP. | `GET /submissions/:uuid/network/tcp`, `GET /submissions/:uuid/network/udp` |
| `ConnectionPackets` | `{sent, received, empty}`. | nested |
| `NetworkThreat` | Suricata alert: `signature`, `description`, `severity`, `protocol`, `app_proto`, `destination_ip`, `destination_port`, `timeshift`, `metadata`, `details`, optional `tls`. | `GET /submissions/:uuid/network/threats` |
| `NetworkThreatTls` | TLS fingerprint block: `version`, `sni`, `ja3_hash`, `ja3s_hash`, `ja3_string`, `ja3s_string`. Present iff `app_proto == "TLS"`. | nested in `NetworkThreat` |

**Discriminative fields.**

- `DnsQuery.type` is `DnsRecordType` (16-value literal: `A`, `AAAA`, `CNAME`, `MX`, &hellip;).
- `DnsQuery.status` is `DnsStatus` (DNS RCODE literal, e.g. `NOERROR`, `NXDOMAIN`, `TIMEOUT`).
- `Connection.protocol` is `ConnectionProtocol = Literal["tcp", "udp"]`.
- `NetworkThreat.protocol` is `ThreatProtocol = Literal["TCP", "UDP"]` (uppercase!).
- `NetworkThreat.app_proto` is `ThreatAppProto = Literal["HTTP", "TLS", "DNS"]`.
- `NetworkThreat.severity` is `ThreatSeverity = Literal["high", "low"]`.

---

## URL Analysis

Full URL analysis report types. Returned by `get_url_analysis()`. URL analysis is a
peer report type to dynamic/static/cdr &mdash; it is guarded separately by
`ReportStatusGuard('url_analysis')`.

| Type | Purpose |
|------|---------|
| `UrlAnalysisResponse` | Top-level report: `level`, `status`, `general_info`, `screenshot`, optional `ip_info`, `dns_records`, optional `whois`, optional `ssl_certificate`, optional `response_headers`, optional `extracted_file`, optional `threat_analysis`, `pages`. |
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

`UrlAnalysisResponse.level` is `ThreatLevel`, shared with submission level. Everything
`Optional` is intentional &mdash; a submission may have no WHOIS (e.g. raw-IP URL), no TLS
cert (plain HTTP), etc.

---

## Account

User, workspace, plan, and quota types. Returned by `get_user_info()`.

| Type | Purpose |
|------|---------|
| `UserInfo` | Top-level response: `user_info`, `plan`, `modules`. Has convenience accessors `email`, `full_name`, `workspace`, `workspace_name`, `workspace_alias`. |
| `UserInfoDetails` | Nested user details: `email`, `full_name`, `workspace`, `limits_count`. |
| `WorkspaceBasicInfo` | `{name, alias, private, type}`. `type` is `Literal["personal", "organization"]`. |
| `LimitsCount` | Current usage: `api_request_count`, `daily_submission_count`, `concurrent_submission_count`. |
| `PlanInfo` | `{plan_name, start_time, end_time, subs_time, file_limits, submission_limits}`. |
| `FileLimits` | `{extensions, file_size}`. |
| `SubmissionLimits` | `{api_limit, daily_limit, concurrent_limit}`. |
| `ModuleInfo` | One enabled module: `{module_id, module_name, start_time, end_time}`. |

Check `account.user_info.limits_count.api_request_count` to decide whether to back off
before hammering rate-limited endpoints.

---

## Errors

Typed error surface. Import from the top-level `threatzone` module or from
`threatzone.types.errors` for the `ApiError` envelope class.

| Class | Kind | Key Fields |
|-------|------|------------|
| `ThreatZoneError` | Base class for every SDK error. | `message` |
| `APIError` | Base class for HTTP errors. | `status_code`, `response`, `body` |
| `AuthenticationError` (401) | Invalid/missing API key. | inherits from `APIError` |
| `PaymentRequiredError` (402) | Workspace subscription inactive. | inherits from `APIError` |
| `PermissionDeniedError` (403) | Module not enabled or cross-workspace access. | inherits from `APIError` |
| `NotFoundError` (404) | Submission/artifact/media not found. | inherits from `APIError` |
| `BadRequestError` (400) | Validation failure. | inherits from `APIError` |
| `RateLimitError` (429) | API quota exceeded. | `retry_after` |
| `ReportUnavailableError` (409) | Required report not yet available. | `code`, `submission_uuid`, `required_report`, `current_status`, `available_reports` |
| `YaraRulePendingError` (202) | YARA rule generation still in progress. | `retry_after` |
| `InternalServerError` (5xx) | Server-side failure. | inherits from `APIError` |
| `TimeoutError` | HTTP request timed out. | `message` |
| `ConnectionError` | Network-level failure. | `message` |
| `AnalysisTimeoutError` | `wait_for_completion()` exceeded its timeout. | `uuid`, `elapsed` |
| `ApiError` (model) | Pydantic model of the canonical error envelope: `status_code`, `error`, `message`, `code`, `details`. | &mdash; |
| `ApiErrorCode` (literal) | Closed enum of all possible error codes. | &mdash; |

**ApiErrorCode values:**

`INVALID_UUID`, `INVALID_QUERY_PARAM`, `UNAUTHORIZED`, `SUBMISSION_PRIVATE`,
`SUBMISSION_NOT_FOUND`, `ARTIFACT_NOT_FOUND`, `SAMPLE_NOT_AVAILABLE`, `MEDIA_NOT_FOUND`,
`DYNAMIC_REPORT_UNAVAILABLE`, `STATIC_REPORT_UNAVAILABLE`, `CDR_REPORT_UNAVAILABLE`,
`URL_ANALYSIS_REPORT_UNAVAILABLE`, `RATE_LIMIT_EXCEEDED`, `SUBMISSION_LIMIT_EXCEEDED`,
`INTERNAL_ERROR`, `STORAGE_UNAVAILABLE`.

Always branch on `code`, never on `message`. See
[recipe 9](./RECIPES.md#9-discriminate-errors-by-their-code-field) for the full pattern.

---

## Common

Types shared across multiple surfaces.

| Type | Purpose |
|------|---------|
| `Hashes` | `{md5, sha1, sha256}`. Used by `Submission.hashes` and `ArtifactHashes`. |
| `FileInfo` | File metadata on a submission: `name`, `size`, `extension`, `mimetype`, `is_mimetype_checked`, `entrypoint`, `source`. |
| `FileSource` | `{type: Literal["upload", "url"], url}`. How the file arrived at the platform. |
| `FileEntrypoint` | `{filename}`. Entrypoint inside an archive submission. |
| `Tag` | `{type, value}`. |
| `ReportStatus` | Per-report state &mdash; see Submissions section. |
| `ReportOperatingSystem` | `{name, platform}`. `platform` is one of `windows`/`linux`/`android`/`macos`. |
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
| `MediaFile` | `{id, name, content_type, size}`. | `GET /submissions/:uuid/media` |

Download endpoints return `DownloadResponse` (sync) or `AsyncDownloadResponse` (async)
from `threatzone._streaming`. Both are context managers; both expose `filename`,
`content_type`, `size`, `status_code`, `read()`, `iter_bytes()`, and `save(path)`.
