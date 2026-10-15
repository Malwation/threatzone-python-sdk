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
| `Submission` | Full submission detail including `file`, `mitre_techniques`, `overview`, `score_breakdown`. `score` is the live score that the web UI shows; it is `None` for a pure URL submission until the final URL verdict. `search_by_sha256()` returns one page of these (`page`, `limit`; the server default is 20 rows). | `GET /submissions/:uuid`, `GET /submissions/search/sha256/:sha256` |
| `SubmissionOverview` | Aggregated analysis status + job progress (`status`, optional `jobs`, `duration`). `duration` is the longest report run time in seconds; only `get_submission()` sends it. | Nested in `Submission` and `SubmissionListItem` |
| `SubmissionIndicatorsRollup` | Severity rollup attached to a submission (`levels`, `artifact_count`). | Nested in `Submission` and `SubmissionListItem` |
| `ReportStatus` | Per-report state (`type`, `status`, `level`, `score`, `duration`, `format`, `operating_system`, `metafields`). `score` is a `float` or `None`. `metafields` is a `dict[str, str]` of the analysis options as the web UI shows them (option name to selected value); only `get_submission()` sends it. | Nested `reports[]` on `Submission` |
| `ScoreBreakdown` | Explanation of `Submission.score`: `deciding_layer`, `verdict`, `score`, `cap`, `contributors`, `what_would_change`. Only `get_submission()` sends it. `None` for a pure URL submission, before the overview exists, and when the stored score does not come from the current score rule. | `GET /submissions/:uuid` |
| `ScoreContributor` | One finding with a large effect on the score: `source`, `indicator_id`, `title`, `points`, `level`. At most ten, largest effect first. | Nested in `ScoreBreakdown.contributors` |

**Discriminative fields.**

- `Submission.level` is `ThreatLevel = Literal["unknown", "benign", "suspicious", "malicious"]`.
- `Submission.type` is `Literal["file", "url"]`.
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
| `Indicator` | A single rule hit with cross-reference IDs. Fields: `id`, `name`, `description`, `summary`, `why_matched`, `in_verdict_chain`, `category`, `level`, `score`, `score_maximum`, `pids`, `attack_codes`, `event_ids`, `syscall_line_numbers`, `author`. | `GET /submissions/:uuid/indicators` |
| `IndicatorsResponse` | `{items, total, levels}` envelope. `levels` is a `{malicious, suspicious, benign}` severity rollup. | same |
| `IndicatorLevels` | Severity counts: `malicious`, `suspicious`, `benign`. | nested |
| `IoC` | `{type, value, artifacts}`. `type` is the 11-value literal below. | `GET /submissions/:uuid/iocs` |
| `IoCsResponse` | Paginated IoC envelope. | same |
| `YaraRule` | `{rule, category, artifacts}`. `category` is `malicious`/`suspicious`/`benign`. | `GET /submissions/:uuid/yara-rules` |
| `YaraRulesResponse` | Paginated YARA rule envelope. | same |
| `ExtractedConfig` | `{family, config, c2s, artifacts}`. `config` is a free-form family-specific dict. | `GET /submissions/:uuid/extracted-configs` |
| `ExtractedConfigsResponse` | Paginated extracted config envelope. | same |
| `Artifact` | `{id, filename, size, type, source, hashes, tags, process_attribution}`. SHA-256 is under `hashes.sha256`. | `GET /submissions/:uuid/artifacts` |
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
- `Indicator.score` is `float`. The API can send a fractional score. An integer score keeps its value.
- `Indicator.score_maximum` is `int | None`: the scale of `score` (10 legacy, 100 Windows V2). `None` when the API does not send it. Divide `score` by `score_maximum` before comparing rows from different scales.
- `Indicator.summary` is `str | None`: a one-sentence plain-language summary, sent for Windows V2 schema 2.1 rows only. `None` on legacy rows and when the API does not send it. On rows with a summary, `description` holds the long analyst text.
- `Indicator.why_matched` is `str | None`: why the indicator matched, in one sentence (Windows V2 reports). `Indicator.in_verdict_chain` is `bool | None`: `True` when the indicator is part of the finding that set the verdict. Both are `None` on legacy rows and when an older server omits them.
- `Artifact.process_attribution` is `ArtifactProcessAttribution` (`unknown`, or a new value) or `None`. `None` when an older server omits it.
- `IoC.type` is `IoCType = Literal["ip", "domain", "url", "email", "sha512", "sha256", "sha1", "md5", "registry", "path", "uuid"]`.
- `YaraRule.category` is `YaraRuleCategory = Literal["malicious", "suspicious", "benign"]`.
- `Artifact.type` is `ArtifactType` (17-value literal including `sample`, `dropped_file`,
  `memory_dump`, `pcap`, `yara_rule`, `email_file`, `email_attachment`, `embedded_file`,
  &hellip;). Unknown values from a newer server are kept as plain strings.
- `CdrSanitizedFileInfoDetail.data` is `list[str] | dict[str, object] | str | None`. The API
  sends a list of strings.
- `OverviewSummary.network` is `Optional` &mdash; `None` on submissions without a
  completed dynamic report. `OverviewSummary.network` also carries `counts_available`,
  `availability` and `source_scope` (same types as `NetworkSummary`). When `counts_available`
  is `False` the counts are 0 and do not mean the sample had no network activity.

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
| `BehaviourEvent` | OS-specific behaviour event with `type`, `pid`, `ppid`, `process_name`, `operation`, `event_id`, `event_count`, `syscall_line_number`, `timestamp`, `details`. `timestamp` is a `float` (seconds) or `None`; Windows V2 events have fractional seconds, and an event without a time has `0`. | `GET /submissions/:uuid/behaviours` |
| `BehavioursResponse` | `{items, total, page, limit, total_pages}`. | same |
| `BehaviourOs` | Deprecated compatibility alias; the endpoint derives the OS from the submission. | same |
| `SyscallsResponse` | `{items: List[str], total, page, limit, total_pages}`. `items` are raw unparsed log lines. `page`, `limit` and `total_pages` are `None` when an older server omits them. | `GET /submissions/:uuid/syscalls` |
| `NetworkSummary` | `{dns_count, http_count, tcp_count, udp_count, threat_count, pcap_available, exfil_request_count, counts_available, availability, source_scope, windows_background_count}`. `exfil_request_count` gives the entries of `get_network_exfil_requests()`; it is not set to 0 when `counts_available` is `False`. `windows_background_count` gives the rows that the counts and lists omit by default. Legacy reports send `counts_available=True`, `availability=None`, `source_scope=None`; all three are `None` when an older server omits them. | `GET /submissions/:uuid/network/summary` |
| `NetworkAvailability` | `{state, reason, coverage}`. Network evidence state of a Windows V2 report. | nested in `NetworkSummary` |
| `NetworkRowSource` | `{attribution, attribution_reason, process_id, process_image}` on every network row. `attribution` is `NetworkAttribution` (`sample`, `sample_child`, `sensor_only`, `windows_background`, or a new value). The server sends `sample` for rows of older reports; each field is `None` when an older server omits it. | base of the network rows |
| `DnsQuery` | `{id, host, type, status, status_text, records, timeshift, source_scope}` plus the `NetworkRowSource` fields. `status_text` keeps the sensor text when `status` is `TIMEOUT`. | `GET /submissions/:uuid/network/dns` |
| `HttpRequest` | `{id, host, ip, port, country, source_scope}` plus the `NetworkRowSource` fields &mdash; slimmed-down shape, no method/URL/headers. | `GET /submissions/:uuid/network/http` |
| `Connection` | `{id, protocol, destination_ip, destination_port, domain, asn, country, packets, timeshift, source_scope}` plus the `NetworkRowSource` fields. Used for both TCP and UDP. | `GET /submissions/:uuid/network/tcp`, `GET /submissions/:uuid/network/udp` |
| `ConnectionPackets` | `{sent, received, empty}`. | nested |
| `NetworkThreat` | Suricata alert: `signature`, `description`, `severity`, `protocol`, `app_proto`, `destination_ip`, `destination_port`, `timeshift`, `metadata`, `details`, optional `tls`, `capture`, `source_scope`, plus the `NetworkRowSource` fields. | `GET /submissions/:uuid/network/threats` |
| `NetworkThreatTls` | TLS fingerprint block: `version`, `sni`, `ja3_hash`, `ja3s_hash`, `ja3_string`, `ja3s_string`. Present iff `app_proto == "TLS"`. | nested in `NetworkThreat` |
| `NetworkExfilRequest` | Chat bot and webhook requests from the decrypted HTTPS capture: `api`, `kind`, `host`, `method`, `api_method`, `target_id`, `masked_target`, `request_bytes`, `reply_status`, `request_count`, `capture`, `first_seen`, `score`, `tier`, `process_id`, `process_image`, `text`. `masked_target` is the request target as sent, with the full bot token or webhook secret; old reports show a shortened token. Every field is `None` when the server omits it. | `GET /submissions/:uuid/network/exfil-requests` |

**Discriminative fields.**

- `DnsQuery.type` is `DnsRecordType` (16-value literal: `A`, `AAAA`, `CNAME`, `MX`, &hellip;).
- `DnsQuery.status` is `DnsStatus` (DNS RCODE literal, e.g. `NOERROR`, `NXDOMAIN`, `TIMEOUT`).
- `NetworkAvailability.state` is `NetworkAvailabilityState` (`disabled`, `unavailable`, `verified_zero`, `observed`); `coverage` is `NetworkCoverage` (`none`, `partial`, `complete`). When `NetworkSummary.counts_available` is `False`, all counts are 0 and do not mean the sample had no network activity.
- `source_scope` is `NetworkSourceScope` (`sample_attributed`, `submission_ip_scoped`, `submission_unattributed`, `none`) or `None` on legacy reports. Unknown values from a newer server are kept as plain strings.
- The list endpoints send the `X-Network-Evidence-Availability` response header on Windows V2. The `get_*` list methods return plain lists, so the SDK does not surface it. Read `get_network_summary().availability` instead.
- `Connection.protocol` is `ConnectionProtocol = Literal["tcp", "udp"]`.
- `NetworkThreat.protocol` is `ThreatProtocol = Literal["TCP", "UDP"]` (uppercase!).
- `NetworkThreat.app_proto` is `ThreatAppProto = Literal["HTTP", "TLS", "DNS"]`.
- `NetworkThreat.capture` is `NetworkThreatCapture` (`decrypted_https`, `offline_scan`, or a new value) or `None`. `decrypted_https`: Suricata matched the alert in the decrypted traffic of a relayed HTTPS connection. `offline_scan`: Suricata found the alert by scanning the recorded traffic after the run. `None` for other alerts, older reports, and older servers.
- `NetworkExfilRequest.api` is `NetworkExfilRequestApi` (`telegram_bot`, `discord_webhook`, `slack_webhook`); `kind` is `NetworkExfilRequestKind` (`poll`, `send_message`, `send_file`); `capture` is `NetworkExfilRequestCapture` (`decrypted_https`). Unknown values from a newer server are kept as plain strings.
- `NetworkThreat.severity` is `ThreatSeverity = Literal["high", "low", "info"] | str`. The API
  maps Suricata priority `1` to `high`, `2` to `low`, and `3` and `4` to `info`. Unknown values
  from a newer server are kept as plain strings.

---

## URL Analysis

Full URL analysis report types. Returned by `get_url_analysis()`. URL analysis is a
peer report type to dynamic/static/cdr &mdash; it is guarded separately by
`ReportStatusGuard('url_analysis')`.

| Type | Purpose |
|------|---------|
| `UrlAnalysisResponse` | Top-level report: `level`, `status`, `general_info`, `screenshot`, optional `ip_info`, `dns_records`, optional `whois`, optional `ssl_certificate`, optional `response_headers`, optional `extracted_file`, optional `threat_analysis`, `pages`, plus the scoring fields `threat_score`, `risk_level`, `privacy_score`, `privacy_risk_level`, `privacy_breakdown`, `verdict_provenance`, `impersonation_target`, `completeness`, `intel_detections`, `metafields`, `scored_at`. |
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
| `UrlAnalysisSessionConfig` | `{device_profile_id, network_config_id, session_duration_seconds, device_preset_id, device_preset_name}`. Device and network choice the session runs with. |

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

## Account

User, workspace, plan, and quota types. Returned by `get_user_info()`.

| Type | Purpose |
|------|---------|
| `UserInfo` | Top-level response: `user_info`, `plan`, `modules`. Has convenience accessors `email`, `full_name`, `workspace`, `workspace_name`, `workspace_alias`, `plan_permissions`, `ai_report_resets_at`. |
| `UserInfoDetails` | Nested user details: `email`, `full_name`, `workspace`, `limits_count`. |
| `WorkspaceBasicInfo` | `{name, alias, private, type}`. `type` is `Literal["personal", "organization"]`. |
| `LimitsCount` | Current usage: `api_request_count`, `daily_submission_count`, `concurrent_submission_count`, `ai_report_count`, `ai_report_resets_at`. `ai_report_count` counts the AI report quota units used since 00:00 UTC; a report in progress counts as used. `ai_report_resets_at` is the next 00:00 UTC. |
| `PlanInfo` | `{plan_name, start_time, end_time, subs_time, file_limits, submission_limits, permissions}`. |
| `PlanPermissions` | `{download_sample, html_report, stix_report, pdf_report, download_report, ai_report}`. A `False` value means that the matching routes return 403. |
| `FileLimits` | `{extensions, file_size}`. |
| `SubmissionLimits` | `{api_limit, daily_limit, concurrent_limit, ai_report_limit}`. `ai_report_limit` is `0` when the plan has no AI report. |
| `ModuleInfo` | One enabled module: `{module_id, module_name, start_time, end_time}`. |

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
| `APIError` | Base class for HTTP errors. | `status_code`, `response`, `body` |
| `AuthenticationError` (401) | Invalid/missing API key. | inherits from `APIError` |
| `PaymentRequiredError` (402) | Workspace subscription inactive. | inherits from `APIError` |
| `PermissionDeniedError` (403) | Module not enabled or cross-workspace access. | inherits from `APIError` |
| `NotFoundError` (404) | Submission/artifact/media not found. | inherits from `APIError` |
| `BadRequestError` (400) | Validation failure. | inherits from `APIError` |
| `RateLimitError` (429) | API quota exceeded. | `retry_after` |
| `ReportUnavailableError` (409) | Required report not yet available. | `code`, `submission_uuid`, `required_report`, `current_status`, `available_reports` |
| `YaraRulePendingError` (202) | YARA rule generation still in progress. | `retry_after` |
| `PdfReportPendingError` (202) | The PDF report is not ready: `download_pdf_report(wait=False)` got 202, or `download_pdf_report(wait=True)` reached its timeout. | `retry_after` |
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

Download endpoints return `DownloadResponse` (sync) or `AsyncDownloadResponse` (async)
from `threatzone._streaming`. Both are context managers; both expose `filename`,
`content_type`, `size`, `status_code`, `read()`, `iter_bytes()`, and `save(path)`.
