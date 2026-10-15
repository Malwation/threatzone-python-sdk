"""Asynchronous Threat.Zone client implementation."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from ._client import AsyncHTTPClient, FileInput
from ._config import ClientConfig
from ._constants import DEFAULT_POLL_INTERVAL, DEFAULT_WAIT_TIMEOUT
from ._exceptions import (
    AnalysisTimeoutError,
    InternalServerError,
    PdfReportPendingError,
    YaraRulePendingError,
)
from ._params import behaviour_filter_params, syscall_search_params
from ._streaming import AsyncDownloadResponse
from .types import (
    AiReport,
    AiReportPending,
    AiReportRegenerateResult,
    AnnotationPinKind,
    Annotations,
    ArtifactJob,
    ArtifactSource,
    ArtifactsResponse,
    BehaviourEventSort,
    BehaviourFacetField,
    BehaviourFacets,
    BehavioursResponse,
    BehaviourSummary,
    CdrResponse,
    Connection,
    DevicePresetOption,
    DnsQuery,
    EmlAnalysis,
    EnvironmentOption,
    ExtractedConfigsResponse,
    HttpRequest,
    IndicatorLevel,
    IndicatorsResponse,
    IocExportFormat,
    IoCsResponse,
    IoCType,
    Killchain,
    MediaFile,
    Message,
    MetafieldOption,
    Metafields,
    MitreResponse,
    NetworkConfigListItem,
    NetworkEndpoints,
    NetworkExfilRequest,
    NetworkFlowPackets,
    NetworkHostFlows,
    NetworkHttpPackets,
    NetworkSummary,
    NetworkThreat,
    OverviewSummary,
    PaginatedSubmissions,
    PdfReportStatus,
    PreviousRun,
    ProcessesResponse,
    ProcessTreeResponse,
    RunComparison,
    RunNotes,
    SignatureCheckResponse,
    StaticScanResponse,
    StringFacts,
    StringsPage,
    Submission,
    SubmissionCreated,
    SubmissionSearchScope,
    SyscallSearchResult,
    SyscallsResponse,
    TotalCountList,
    UrlAnalysisBrowserSection,
    UrlAnalysisBrowserSectionName,
    UrlAnalysisIndicatorEvidence,
    UrlAnalysisIndicators,
    UrlAnalysisResponse,
    UrlAnalysisSession,
    UserInfo,
    Verdict,
    YaraRuleCategory,
    YaraRulesResponse,
)


def _normalize_metafields_json(
    metafields: dict[str, Any] | list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Normalize JSON metafields into the object-map format expected by Public API."""
    if metafields is None:
        return None
    if isinstance(metafields, dict):
        return metafields
    if not isinstance(metafields, list):
        raise TypeError("metafields must be a dict or a list of {'key', 'value'} objects")

    normalized: dict[str, Any] = {}
    for item in metafields:
        if not isinstance(item, dict) or "key" not in item:
            raise TypeError("metafields list items must be dicts with at least a 'key' field")
        normalized[str(item["key"])] = item.get("value")
    return normalized


def _parse_retry_after(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _pending_body(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _total_count(response: httpx.Response) -> int | None:
    value = response.headers.get("x-total-count")
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


class AsyncThreatZone:
    """Asynchronous client for the Threat.Zone Public API."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        verify_ssl: bool = False,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """
        Initialize the async Threat.Zone client.

        Args:
            api_key: API key for authentication. Falls back to THREATZONE_API_KEY env var.
            base_url: Base URL for the Threat.Zone Public API including the
                ``/public-api`` suffix. Defaults to ``https://app.threat.zone/public-api``.
                For on-prem deployments, point this at your instance, e.g.
                ``https://threatzone.your-company.internal/public-api``.
            timeout: Request timeout in seconds. Defaults to 60. Ignored when
                ``http_client`` is supplied.
            max_retries: Maximum number of retries for failed requests. Defaults to 2.
                Ignored when ``http_client`` is supplied.
            verify_ssl: Whether to verify SSL certificates. Set to False for self-signed
                certificates in on-premise deployments. Defaults to False. Ignored when
                ``http_client`` is supplied.
            http_client: Optional pre-configured ``httpx.AsyncClient`` to use for every
                request. When provided, the SDK uses it as-is and the ``timeout``,
                ``verify_ssl``, and ``max_retries`` arguments are ignored — the caller
                is expected to have configured them on the supplied client. The SDK
                will not close a caller-supplied client; the caller retains ownership.
                When ``None`` (the default), the SDK builds and owns its own client.
        """
        self._config = ClientConfig.from_env(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            verify_ssl=verify_ssl,
        )
        self._http = AsyncHTTPClient(self._config, http_client=http_client)

    @property
    def _base_url(self) -> str:
        """The effective base URL the SDK is sending requests to."""
        return self._config.base_url

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        await self._http.close()

    async def __aenter__(self) -> AsyncThreatZone:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    # =========================================================================
    # User Info
    # =========================================================================

    async def get_user_info(self) -> UserInfo:
        """Get current user and workspace information."""
        response = await self._http.get("/me")
        return UserInfo.model_validate(response.json())

    # =========================================================================
    # Configuration
    # =========================================================================

    async def get_metafields(
        self, scan_type: str | None = None
    ) -> Metafields | list[MetafieldOption]:
        """
        Get available metafield options.

        Args:
            scan_type: Optional scan type to filter by (sandbox, static, cdr, url).
                       If not specified, returns all metafields grouped by type.

        Returns:
            Metafields object if no scan_type specified, or list of MetafieldOption for specific type.
        """
        if scan_type:
            response = await self._http.get(f"/config/metafields/{scan_type}")
            return [MetafieldOption.model_validate(item) for item in response.json()]
        else:
            response = await self._http.get("/config/metafields")
            return Metafields.model_validate(response.json())

    async def get_environments(self) -> list[EnvironmentOption]:
        """Get available sandbox environments."""
        response = await self._http.get("/config/environments")
        return [EnvironmentOption.model_validate(item) for item in response.json()]

    async def list_network_configs(self) -> list[NetworkConfigListItem]:
        """List the workspace's available network configurations (proxy/openvpn/wireguard).

        Secrets (passwords, VPN file contents) are never returned — only `has_config_file`.
        """
        response = await self._http.get("/v1/network-configs")
        data = response.json()
        return [NetworkConfigListItem.model_validate(item) for item in data.get("items", [])]

    async def get_device_presets(self) -> list[DevicePresetOption]:
        """List the browser device presets your plan can select.

        Pass a preset `id` as the `device_preset` metafield on
        create_url_submission().
        """
        response = await self._http.get("/config/device-presets")
        return [DevicePresetOption.model_validate(item) for item in response.json()]

    # =========================================================================
    # Submissions - Create
    # =========================================================================

    async def create_sandbox_submission(
        self,
        file: FileInput,
        *,
        environment: str | None = None,
        auto_select_environment: bool = False,
        metafields: dict[str, Any] | list[dict[str, Any]] | None = None,
        private: bool = False,
        entrypoint: str | None = None,
        password: str | None = None,
        configurations: dict[str, str] | None = None,
    ) -> SubmissionCreated:
        """
        Create a new sandbox (dynamic analysis) submission.

        Args:
            file: File to analyze. Can be a file path, bytes, or file-like object.
            environment: Sandbox environment to use. See get_environments() for options.
                Takes precedence over auto_select_environment.
            auto_select_environment: When True, the server picks the environment based
                on the file's detected extension. Ignored if `environment` is also set.
                Falls back to the plan's default OS for unknown extensions. Default: False.
            metafields: Optional analysis metafields.
                You can pass either:
                - a dict map, e.g. {"timeout": 120, "internet_connection": True}
                - a list of {"key": ..., "value": ...} objects (will be normalized)
            private: If True, submission is private to your workspace.
            entrypoint: Entry point for archive files.
            password: Password for encrypted archives.
            configurations: Advanced execution configuration options including:
                - preScript: Script to run before analysis
                - startArguments: Command line arguments for the sample
                - networkConfig: Network configuration ID (MongoDB ObjectId)

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        extra_fields: dict[str, Any] = {}
        if auto_select_environment:
            extra_fields["autoSelectEnvironment"] = auto_select_environment

        multipart = self._http._build_multipart_data(
            file,
            environment=environment,
            metafields=metafields,
            private=private,
            entrypoint=entrypoint,
            password=password,
            configurations=configurations,
            **extra_fields,
        )
        response = await self._http.post("/submissions/sandbox", **multipart)
        return SubmissionCreated.model_validate(response.json())

    async def create_static_submission(
        self,
        file: FileInput,
        *,
        private: bool = False,
        entrypoint: str | None = None,
        password: str | None = None,
        dynamic_mimetype_check: bool | None = None,
    ) -> SubmissionCreated:
        """
        Create a new static analysis submission.

        Args:
            file: File to analyze. Can be a file path, bytes, or file-like object.
            private: If True, submission is private to your workspace.
            entrypoint: Entry point for archive files.
            password: Password for encrypted archives.
            dynamic_mimetype_check: When True (default on the server),
                Magika-detected real extension is appended to the filename if
                it differs from the declared extension. Send False to keep the
                original filename verbatim. Omit to use the server default.

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        multipart = self._http._build_multipart_data(
            file,
            private=private,
            entrypoint=entrypoint,
            password=password,
            dynamic_mimetype_check=dynamic_mimetype_check,
        )
        response = await self._http.post("/submissions/static", **multipart)
        return SubmissionCreated.model_validate(response.json())

    async def create_cdr_submission(
        self,
        file: FileInput,
        *,
        private: bool = False,
        entrypoint: str | None = None,
        password: str | None = None,
        dynamic_mimetype_check: bool | None = None,
    ) -> SubmissionCreated:
        """
        Create a new CDR (Content Disarm & Reconstruction) submission.

        Args:
            file: File to sanitize. Can be a file path, bytes, or file-like object.
            private: If True, submission is private to your workspace.
            entrypoint: Entry point for archive files.
            password: Password for encrypted archives.
            dynamic_mimetype_check: When True (default on the server),
                Magika-detected real extension is appended to the filename if
                it differs from the declared extension. Send False to keep the
                original filename verbatim. Omit to use the server default.

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        multipart = self._http._build_multipart_data(
            file,
            private=private,
            entrypoint=entrypoint,
            password=password,
            dynamic_mimetype_check=dynamic_mimetype_check,
        )
        response = await self._http.post("/submissions/cdr", **multipart)
        return SubmissionCreated.model_validate(response.json())

    async def create_url_submission(
        self,
        url: str,
        *,
        private: bool = False,
        safe_browsing: bool = False,
        metafields: dict[str, Any] | None = None,
        configurations: dict[str, Any] | None = None,
    ) -> SubmissionCreated:
        """
        Create a new URL analysis submission.

        Args:
            url: URL to analyze. A missing scheme is normalised to http:// server-side.
            private: If True, submission is private to your workspace.
            safe_browsing: If True, start an interactive browser session alongside
                the analysis. Retrieve the viewer link with get_url_analysis_session().
                Sessions are queued when the workspace is at capacity. Default: False.
            metafields: URL-analysis metafields. Discover the accepted keys with
                get_metafields("url"). `timeout` sets the session duration in seconds;
                `device_preset` selects the emulated device (get_device_presets()).
            configurations: Per-scan configuration. `networkConfig` selects an egress
                profile (list_network_configs()); `sessionDurationSeconds` sets the
                interactive session duration (30-600, clamped by your plan).

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        payload: dict[str, Any] = {
            "url": url,
            "private": private,
            "safeBrowsing": safe_browsing,
        }
        if metafields is not None:
            payload["metafields"] = metafields
        if configurations is not None:
            payload["configurations"] = configurations

        response = await self._http.post("/submissions/url_analysis", json=payload)
        return SubmissionCreated.model_validate(response.json())

    async def create_open_in_browser_submission(
        self,
        url: str,
        *,
        environment: str | None = None,
        auto_select_environment: bool = False,
        metafields: dict[str, Any] | list[dict[str, Any]] | None = None,
        private: bool = False,
        configurations: dict[str, str] | None = None,
    ) -> SubmissionCreated:
        """
        Create a new open-in-browser submission.

        This submission runs URL analysis and browser-based dynamic analysis together.

        Args:
            url: URL to analyze.
            environment: Optional OS environment key for browser execution.
                Takes precedence over auto_select_environment.
            auto_select_environment: When True, server resolves to the plan's
                open_in_browser default. (No file extension exists for URL
                submissions, so this is effectively API symmetry with sandbox.)
                Ignored if `environment` is also set. Default: False.
            metafields: Optional open_in_browser metafields.
                You can pass either:
                - a dict map, e.g. {"timeout": 120}
                - a list of {"key": ..., "value": ...} objects (will be normalized)
            private: If True, submission is private to your workspace.
            configurations: Advanced execution configuration options.

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        payload: dict[str, Any] = {"url": url, "private": private}
        normalized_metafields = _normalize_metafields_json(metafields)
        if environment is not None:
            payload["environment"] = environment
        if auto_select_environment:
            payload["autoSelectEnvironment"] = auto_select_environment
        if normalized_metafields is not None:
            payload["metafields"] = normalized_metafields
        if configurations is not None:
            payload["configurations"] = configurations

        response = await self._http.post("/submissions/open_in_browser", json=payload)
        return SubmissionCreated.model_validate(response.json())

    # =========================================================================
    # Submissions - Query
    # =========================================================================

    async def list_submissions(
        self,
        *,
        page: int = 1,
        limit: int = 20,
        level: list[str] | None = None,
        type: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        start_date: datetime | str | None = None,
        end_date: datetime | str | None = None,
        private: bool | None = None,
        tags: list[str] | None = None,
        sort: str | None = None,
        order: str | None = None,
    ) -> PaginatedSubmissions:
        """
        List submissions with optional filters.

        Args:
            page: Page number (1-indexed).
            limit: Number of items per page (max 100).
            level: Filter by threat levels (unknown, benign, suspicious, malicious).
            type: Filter by submission type (file, url).
            sha256: Filter by SHA256 hash.
            filename: Filter by filename (partial match).
            start_date: Filter submissions created after this date.
            end_date: Filter submissions created before this date.
            private: Filter by privacy status.
            tags: Filter by tags.
            sort: Sort field (e.g. "createdAt").
            order: Sort order ("asc" or "desc").

        Returns:
            PaginatedSubmissions with items and pagination info.
        """
        params: dict[str, Any] = {"page": page, "limit": limit}
        if level:
            params["level"] = level
        if type:
            params["type"] = type
        if sha256:
            params["sha256"] = sha256
        if filename:
            params["filename"] = filename
        if start_date:
            params["startDate"] = (
                start_date.isoformat() if isinstance(start_date, datetime) else start_date
            )
        if end_date:
            params["endDate"] = end_date.isoformat() if isinstance(end_date, datetime) else end_date
        if private is not None:
            params["private"] = private
        if tags:
            params["tags"] = tags
        if sort is not None:
            params["sort"] = sort
        if order is not None:
            params["order"] = order

        response = await self._http.get("/submissions", params=params)
        return PaginatedSubmissions.model_validate(response.json())

    async def get_submission(self, uuid: str) -> Submission:
        """
        Get submission details by UUID.

        Args:
            uuid: Submission UUID.

        Returns:
            Full submission details.
        """
        response = await self._http.get(f"/submissions/{uuid}")
        return Submission.model_validate(response.json())

    async def search_by_sha256(
        self,
        sha256: str,
        *,
        page: int | None = None,
        limit: int | None = None,
        scope: SubmissionSearchScope | None = None,
    ) -> list[Submission]:
        """
        Search submissions by SHA256 hash.

        The match is exact. The server returns one page, newest submission
        first. Without ``page`` and ``limit`` the server returns the first 20
        rows. Private submissions of other workspaces never appear.

        Args:
            sha256: SHA256 hash to search for (64 hexadecimal characters).
            page: 1-indexed page number.
            limit: Maximum items per page (1-100). The server default is 20.
            scope: ``"workspace"`` (the server default) reads the file
                submissions of your workspace and the public file submissions
                of other workspaces. ``"public"`` reads only public
                submissions of all workspaces, also URL submissions whose
                downloaded payload has this SHA256. ``"public"`` never returns
                a private submission, also not one of your workspace. The SDK
                omits the parameter when it is ``None``.

        Returns:
            List of matching submissions on the requested page. The rows do
            not have the detail-only fields.

        Raises:
            BadRequestError: When the hash, ``page``, ``limit`` or ``scope`` is
                not valid (``INVALID_QUERY_PARAM``).
        """
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit
        if scope is not None:
            params["scope"] = scope

        response = await self._http.get(
            f"/submissions/search/sha256/{sha256}",
            params=params if params else None,
        )
        return [Submission.model_validate(item) for item in response.json()]

    async def wait_for_completion(
        self,
        uuid: str,
        *,
        timeout: float = DEFAULT_WAIT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> Submission:
        """
        Wait for a submission to complete all analysis.

        Args:
            uuid: Submission UUID to wait for.
            timeout: Maximum time to wait in seconds. Defaults to 600.
            poll_interval: Time between status checks in seconds. Defaults to 5.

        Returns:
            Final submission state with completed reports.

        Raises:
            AnalysisTimeoutError: If timeout is reached before completion.
            NotFoundError: If submission does not exist.
        """
        start_time = time.monotonic()

        while True:
            submission = await self.get_submission(uuid)

            if submission.is_complete():
                return submission

            elapsed = time.monotonic() - start_time
            if elapsed >= timeout:
                raise AnalysisTimeoutError(
                    f"Analysis did not complete within {timeout} seconds. "
                    f"Current status: {[r.status for r in submission.reports]}",
                    uuid=uuid,
                    elapsed=elapsed,
                )

            await asyncio.sleep(poll_interval)

    # =========================================================================
    # Indicators
    # =========================================================================

    async def get_overview_summary(self, uuid: str) -> OverviewSummary:
        """
        Get the analysis overview summary for a submission.

        Returns aggregate counts for indicators (with severity rollup), behaviour
        events, syscalls, IoCs, YARA rules, extracted configs, artifacts, MITRE
        techniques, and (when a dynamic report is available) network activity.

        Args:
            uuid: Submission UUID.

        Returns:
            Aggregated overview summary for the submission.
        """
        response = await self._http.get(f"/submissions/{uuid}/summary")
        return OverviewSummary.model_validate(response.json())

    # Backwards-compatible alias for the previous, narrower SDK method name.
    get_summary = get_overview_summary

    async def get_indicators(
        self,
        uuid: str,
        *,
        level: IndicatorLevel | None = None,
        category: str | None = None,
        pid: int | None = None,
        attack_code: str | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> IndicatorsResponse:
        """
        Get behavioural indicators for a submission.

        Args:
            uuid: Submission UUID.
            level: Filter by indicator severity level.
            category: Filter by free-form indicator category.
            pid: Filter by process ID that emitted the indicator.
            attack_code: Filter by MITRE ATT&CK technique code.
            page: 1-indexed page number.
            limit: Maximum items per page (1-100).

        Returns:
            Paginated indicators with severity rollup.
        """
        params: dict[str, Any] = {}
        if level is not None:
            params["level"] = level
        if category is not None:
            params["category"] = category
        if pid is not None:
            params["pid"] = pid
        if attack_code is not None:
            params["attackCode"] = attack_code
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        response = await self._http.get(
            f"/submissions/{uuid}/indicators",
            params=params if params else None,
        )
        return IndicatorsResponse.model_validate(response.json())

    async def get_iocs(
        self,
        uuid: str,
        *,
        type: IoCType | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> IoCsResponse:
        """
        Get Indicators of Compromise (IoCs) for a submission.

        Args:
            uuid: Submission UUID.
            type: Filter by IoC type.
            page: 1-indexed page number.
            limit: Maximum items per page (1-100).

        Returns:
            Paginated IoC list.
        """
        params: dict[str, Any] = {}
        if type is not None:
            params["type"] = type
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        response = await self._http.get(
            f"/submissions/{uuid}/iocs",
            params=params if params else None,
        )
        return IoCsResponse.model_validate(response.json())

    async def get_yara_rules(
        self,
        uuid: str,
        *,
        category: YaraRuleCategory | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> YaraRulesResponse:
        """
        Get matched YARA rules for a submission.

        Args:
            uuid: Submission UUID.
            category: Filter by YARA rule category.
            page: 1-indexed page number.
            limit: Maximum items per page (1-100).

        Returns:
            Paginated YARA rule matches.
        """
        params: dict[str, Any] = {}
        if category is not None:
            params["category"] = category
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        response = await self._http.get(
            f"/submissions/{uuid}/yara-rules",
            params=params if params else None,
        )
        return YaraRulesResponse.model_validate(response.json())

    async def get_extracted_configs(self, uuid: str) -> ExtractedConfigsResponse:
        """
        Get extracted malware configurations for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            Paginated extracted configurations including C2 endpoints and source artifacts.
        """
        response = await self._http.get(f"/submissions/{uuid}/extracted-configs")
        return ExtractedConfigsResponse.model_validate(response.json())

    async def get_artifacts(
        self,
        uuid: str,
        *,
        source: ArtifactSource | None = None,
    ) -> ArtifactsResponse:
        """
        Get extracted artifacts for a submission.

        Args:
            uuid: Submission UUID.
            source: Return only the artifacts with this stored source value, for example
                ``"dynamic_report"``. An unknown value raises ``BadRequestError``.

        Returns:
            Artifact list. Each artifact carries nested MD5/SHA1/SHA256 hashes, the engine
            analysis state and the download route path.
        """
        params: dict[str, Any] | None = {"source": source} if source is not None else None
        response = await self._http.get(f"/submissions/{uuid}/artifacts", params=params)
        return ArtifactsResponse.model_validate(response.json())

    async def get_artifact_jobs(self, uuid: str, artifact_id: str) -> list[ArtifactJob]:
        """
        Get the engine analysis jobs of an artifact.

        Args:
            uuid: Submission UUID.
            artifact_id: Artifact ID from get_artifacts().

        Returns:
            One ``ArtifactJob`` per engine job, oldest first. An empty list means that no
            engine job was created for the artifact.

        Raises:
            NotFoundError: When the artifact does not belong to the submission.
        """
        response = await self._http.get(f"/submissions/{uuid}/artifacts/{artifact_id}/jobs")
        return [ArtifactJob.model_validate(item) for item in response.json()["items"]]

    async def get_eml_analysis(self, uuid: str) -> list[EmlAnalysis]:
        """
        Get parsed EML analysis results for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            One ``EmlAnalysis`` per .eml artifact extracted from the submission.
        """
        response = await self._http.get(f"/submissions/{uuid}/eml-analysis")
        return [EmlAnalysis.model_validate(item) for item in response.json()]

    async def get_mitre_techniques(self, uuid: str) -> MitreResponse:
        """
        Get matched MITRE ATT&CK technique IDs for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            MITRE response containing the matched technique IDs and total count.
        """
        response = await self._http.get(f"/submissions/{uuid}/mitre")
        return MitreResponse.model_validate(response.json())

    async def get_static_scan_results(self, uuid: str) -> StaticScanResponse:
        """
        Get static analysis results for a submission.

        The response is a per-submission static analysis report, discriminated
        by ``reportFormat``. Format-specific keys (e.g. ``peExeSections``,
        ``apkInfo``) are inlined at the top level and preserved on
        ``.model_extra``.

        Args:
            uuid: Submission UUID.

        Returns:
            Static analysis report singleton.

        Raises:
            ReportUnavailableError: When the static report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/static-scan")
        return StaticScanResponse.model_validate(response.json())

    async def get_static_scan_strings(self, uuid: str) -> AsyncDownloadResponse:
        """Stream the raw extracted-strings JSON (``{uuid}_strings.json``) for a static report.

        The response is a streamed application/json file (can be multi-MB). Use
        ``.read()``, ``.iter_bytes()``, or ``.save(path)``. Raises
        ReportUnavailableError (409) when the static report is not complete,
        NotFoundError (404) when no strings file exists.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the strings JSON file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/static-scan/strings")

    async def get_static_scan_string_facts(self, uuid: str) -> StringFacts:
        """
        Get the observables and facts that the UI shows for the extracted strings.

        Observable ``value``, ``display`` and ``source`` contain the full text.
        ``secret`` is a label for filters only. The SDK does not mask values.
        This is a heavy route: each API token can send 30 heavy-route requests
        each minute.

        Args:
            uuid: Submission UUID.

        Returns:
            String observables, facts, the number of read strings and the
            truncation flag.

        Raises:
            ReportUnavailableError: When the static report is not yet available.
            RateLimitError: When the heavy-route rate limit is reached (429).
        """
        response = await self._http.get(f"/submissions/{uuid}/static-scan/string-facts")
        return StringFacts.model_validate(response.json())

    async def get_static_scan_strings_page(
        self,
        uuid: str,
        *,
        start: int | None = None,
        end: int | None = None,
        search: str | None = None,
    ) -> StringsPage:
        """
        Get a window of the extracted strings, as the strings table of the UI shows it.

        The API filters the strings by ``search`` first, then applies the
        ``start``/``end`` window to the matched strings. This is a heavy route:
        each API token can send 30 heavy-route requests each minute.

        Args:
            uuid: Submission UUID.
            start: Index of the first matched string (0-based). The API default is 0.
            end: Index after the last matched string. ``end - start`` must be
                1000 or less. The API default is ``start + 1000``.
            search: Return only strings that contain this text (case-insensitive,
                at most 200 characters).

        Returns:
            The strings window, the number of matched strings and the download link.

        Raises:
            BadRequestError: When ``start``/``end``/``search`` is not valid.
            NotFoundError: When the strings file is not available.
            ReportUnavailableError: When the static report is not yet available.
            RateLimitError: When the heavy-route rate limit is reached (429).
        """
        params: dict[str, Any] = {}
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        if search is not None:
            params["search"] = search

        response = await self._http.get(
            f"/submissions/{uuid}/static-scan/strings/items",
            params=params if params else None,
        )
        return StringsPage.model_validate(response.json())

    async def get_cdr_results(self, uuid: str) -> CdrResponse:
        """
        Get Content Disarm and Reconstruction (CDR) results for a submission.

        This returns the per-submission CDR transformation result. Use
        ``download_cdr_result()`` to download the sanitized file itself.

        Args:
            uuid: Submission UUID.

        Returns:
            CDR transformation result.

        Raises:
            ReportUnavailableError: When the CDR report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/cdr")
        return CdrResponse.model_validate(response.json())

    async def get_signature_check_results(self, uuid: str) -> SignatureCheckResponse:
        """
        Get authenticode/signature check results for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            Signature check results envelope.

        Raises:
            ReportUnavailableError: When the static report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/signature-check")
        return SignatureCheckResponse.model_validate(response.json())

    # =========================================================================
    # Dynamic Report
    # =========================================================================

    async def get_processes(self, uuid: str) -> ProcessesResponse:
        """
        Get processes captured during dynamic analysis.

        Args:
            uuid: Submission UUID.

        Returns:
            Flat list of processes with their network and event activity.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/processes")
        return ProcessesResponse.model_validate(response.json())

    async def get_process_tree(self, uuid: str) -> ProcessTreeResponse:
        """
        Get the process spawn tree captured during dynamic analysis.

        Args:
            uuid: Submission UUID.

        Returns:
            Recursive process tree rooted at the top-level processes.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/processes/tree")
        return ProcessTreeResponse.model_validate(response.json())

    async def get_killchain(self, uuid: str) -> Killchain:
        """
        Get the kill chain timeline of the dynamic analysis.

        The timeline has the processes the sandbox observed, the files each process dropped,
        and the memory dumps of each process. The web UI kill chain view shows the same data.

        Args:
            uuid: Submission UUID.

        Returns:
            Kill chain timeline. Download a stored file with ``download_artifact()`` and the
            ``artifact_id`` of the file. ``artifact_id`` is ``None`` when no stored artifact of
            the current analysis exists for the file.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
            RateLimitError: When the API token is above the heavy-route limit.
        """
        response = await self._http.get(f"/submissions/{uuid}/killchain")
        return Killchain.model_validate(response.json())

    async def get_behaviours(
        self,
        uuid: str,
        *,
        type: str | None = None,
        pid: int | None = None,
        operation: str | None = None,
        process_name: str | None = None,
        page: int | None = None,
        limit: int | None = None,
        event_ids: Sequence[int] | None = None,
        pids: Sequence[int] | None = None,
        parent_pids: Sequence[int] | None = None,
        types: Sequence[str] | None = None,
        operations: Sequence[str] | None = None,
        statuses: Sequence[str] | None = None,
        process_name_contains: str | None = None,
        from_timestamp: float | None = None,
        to_timestamp: float | None = None,
        syscall_line_from: int | None = None,
        syscall_line_to: int | None = None,
        fields: Mapping[str, str | Sequence[str]] | None = None,
        text: str | None = None,
        sort: BehaviourEventSort | None = None,
    ) -> BehavioursResponse:
        """
        Get behaviour events captured during dynamic analysis.

        A request without index parameters reads the behaviour file and returns the raw
        ``details`` object. ``event_ids`` does not need the index. The other new
        parameters (from ``pids`` to ``sort``) read the behaviour index, the same index
        that the web UI reads. Then ``details`` holds the values that the web UI shows,
        and the response sets ``sorted_by`` and ``many_processes_match``. Every set filter
        must match. The values of one list match as any of.

        Args:
            uuid: Submission UUID.
            type: Filter by event type (e.g. registry, file, network, process, mutex).
            pid: Filter by process ID.
            operation: Filter by operation name.
            process_name: Filter by process name (exact match).
            page: 1-indexed page number.
            limit: Maximum items per page (1-500).
            event_ids: Return only the events with these IDs (at most 500), for example
                the events of one indicator finding.
            pids: Return the events of any of these process IDs (at most 100).
            parent_pids: Return the events whose parent process ID is any of these IDs.
            types: Return the events of any of these types (exact match).
            operations: Return the events of any of these operations. The match does
                not use case.
            statuses: Return the events with any of these status details (exact match).
            process_name_contains: Text that the process name contains. The match does
                not use case. The server uses at most the 50 matching process names
                with the most events.
            from_timestamp: Lowest event time, in unix seconds.
            to_timestamp: Highest event time, in unix seconds.
            syscall_line_from: Lowest syscall log line (1-based).
            syscall_line_to: Highest syscall log line. The span must not be more than
                10,000 lines.
            fields: Detail filters, sent as ``field.<key>``. The key is a
                ``BehaviourFieldFilterKey`` (for example ``path``, ``key`` or ``cmd``).
                The value is the text that the detail contains (the match does not use
                case), or a list of texts that match as any of. At most 5 values in one
                request.
            text: Text that the process name, PIDs, operation, event time or any detail
                value contains (3 to 200 characters). The match does not use case.
            sort: Row order: ``eventId`` (file order) or ``time``. The server sorts by
                time only when the matching rows are few enough; read ``sorted_by``.

        Returns:
            Paginated behaviour events.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
            BehaviourIndexingError: When the request needs the behaviour index and the
                index is not ready. Retry after ``retry_after`` seconds.
            BehaviourTooLargeError: When an index filter needs a scan above the read
                limit.
            BehaviourUnreadableError: When the stored behaviour file is not valid.
        """
        params: dict[str, Any] = {}
        if type is not None:
            params["type"] = type
        if pid is not None:
            params["pid"] = pid
        if operation is not None:
            params["operation"] = operation
        if process_name is not None:
            params["processName"] = process_name
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit
        params.update(
            behaviour_filter_params(
                event_ids=event_ids,
                pids=pids,
                parent_pids=parent_pids,
                types=types,
                operations=operations,
                statuses=statuses,
                process_name_contains=process_name_contains,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
                syscall_line_from=syscall_line_from,
                syscall_line_to=syscall_line_to,
                fields=fields,
            )
        )
        if text is not None:
            params["text"] = text
        if sort is not None:
            params["sort"] = sort

        response = await self._http.get(
            f"/submissions/{uuid}/behaviours",
            params=params,
        )
        return BehavioursResponse.model_validate(response.json())

    async def get_behaviour_summary(self, uuid: str) -> BehaviourSummary:
        """
        Get the behaviour event counts that the web UI shows above the Behaviour view.

        The route reads the behaviour index and is a heavy route (a limited number of
        requests per minute for each API token).

        Args:
            uuid: Submission UUID.

        Returns:
            The total, the time span, the counts by type, operation and process, and the
            first exit event of each process. Zero counts when the run has no behaviour
            file.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
            BehaviourIndexingError: When the behaviour index is not ready.
            RateLimitError: When the API token is above the heavy-route limit.
                ``retry_after`` gives the seconds to wait.
        """
        response = await self._http.get(f"/submissions/{uuid}/behaviours/summary")
        return BehaviourSummary.model_validate(response.json())

    async def get_behaviour_facets(
        self,
        uuid: str,
        field: BehaviourFacetField,
        *,
        contains: str | None = None,
        first: int | None = None,
        event_ids: Sequence[int] | None = None,
        pids: Sequence[int] | None = None,
        parent_pids: Sequence[int] | None = None,
        types: Sequence[str] | None = None,
        operations: Sequence[str] | None = None,
        statuses: Sequence[str] | None = None,
        process_name_contains: str | None = None,
        from_timestamp: float | None = None,
        to_timestamp: float | None = None,
        syscall_line_from: int | None = None,
        syscall_line_to: int | None = None,
        fields: Mapping[str, str | Sequence[str]] | None = None,
    ) -> BehaviourFacets:
        """
        Count the most frequent values of one behaviour event field.

        The web UI shows these counts in its filter lists. The route reads the behaviour
        index and is a heavy route (a limited number of requests per minute for each API
        token).

        Args:
            uuid: Submission UUID.
            field: The field to count: ``operation``, ``type``, ``processName``,
                ``function`` or ``subject``.
            contains: Count only the values that contain this text. The match does not
                use case.
            first: Number of values to return, most frequent first (default 200,
                maximum 2000).
            event_ids: Return only the events with these IDs (at most 500), for example
                the events of one indicator finding.
            pids: Return the events of any of these process IDs (at most 100).
            parent_pids: Return the events whose parent process ID is any of these IDs.
            types: Return the events of any of these types (exact match).
            operations: Return the events of any of these operations. The match does
                not use case.
            statuses: Return the events with any of these status details (exact match).
            process_name_contains: Text that the process name contains. The match does
                not use case. The server uses at most the 50 matching process names
                with the most events.
            from_timestamp: Lowest event time, in unix seconds.
            to_timestamp: Highest event time, in unix seconds.
            syscall_line_from: Lowest syscall log line (1-based).
            syscall_line_to: Highest syscall log line. The span must not be more than
                10,000 lines.
            fields: Detail filters, sent as ``field.<key>``. The key is a
                ``BehaviourFieldFilterKey`` (for example ``path``, ``key`` or ``cmd``).
                The value is the text that the detail contains (the match does not use
                case), or a list of texts that match as any of. At most 5 values in one
                request.

        Returns:
            The value counts. ``complete`` is ``False`` when the read limit stopped the
            row scan, so the counts are too low.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
            BehaviourIndexingError: When the request needs the behaviour index and the
                index is not ready. Retry after ``retry_after`` seconds.
            BehaviourTooLargeError: When an index filter needs a scan above the read
                limit.
            RateLimitError: When the API token is above the heavy-route limit.
                ``retry_after`` gives the seconds to wait.
        """
        params: dict[str, Any] = {"field": field}
        if contains is not None:
            params["contains"] = contains
        if first is not None:
            params["first"] = first
        params.update(
            behaviour_filter_params(
                event_ids=event_ids,
                pids=pids,
                parent_pids=parent_pids,
                types=types,
                operations=operations,
                statuses=statuses,
                process_name_contains=process_name_contains,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
                syscall_line_from=syscall_line_from,
                syscall_line_to=syscall_line_to,
                fields=fields,
            )
        )

        response = await self._http.get(f"/submissions/{uuid}/behaviours/facets", params=params)
        return BehaviourFacets.model_validate(response.json())

    async def get_syscalls(
        self,
        uuid: str,
        *,
        page: int | None = None,
        limit: int | None = None,
    ) -> SyscallsResponse:
        """
        Get raw syscall log lines captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            page: 1-indexed page number.
            limit: Maximum items per page (default 500, max 2000).

        Returns:
            Paginated raw syscall log lines.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        response = await self._http.get(
            f"/submissions/{uuid}/syscalls",
            params=params if params else None,
        )
        return SyscallsResponse.model_validate(response.json())

    async def search_syscalls(
        self,
        uuid: str,
        *,
        query: str,
        pids: Sequence[int] | None = None,
        failed_only: bool | None = None,
        apis: Sequence[str] | None = None,
        after_line: int | None = None,
        limit: int | None = None,
    ) -> SyscallSearchResult:
        """
        Search the raw syscall log for lines that contain a text.

        The scan reads the log in line order. One request scans a limited number of lines
        for a limited time. To get the next page, send ``next_from_line`` of the result as
        ``after_line``. This is a heavy route (a limited number of requests per minute for
        each API token).

        Args:
            uuid: Submission UUID.
            query: Text to find (3 to 200 characters). The match does not use case and
                reads the text as plain text, not as a pattern.
            pids: Keep only the lines of these process IDs (at most 100).
            failed_only: When ``True``, keep only the failed calls.
            apis: Keep only the calls of these APIs, by the full call
                (``ntdll!NtCreateFile``) or by the name (``NtCreateFile``).
            after_line: Start the scan after this 1-based line number. ``0`` or unset
                starts at line 1.
            limit: Maximum number of hits (default 200, maximum 500).

        Returns:
            The hits and the scan position. ``busy`` is ``True`` when the server did not
            scan; send the same request again later.

        Raises:
            ReportUnavailableError: When the dynamic report is not yet available.
            RateLimitError: When the API token is above the heavy-route limit.
                ``retry_after`` gives the seconds to wait.
        """
        response = await self._http.get(
            f"/submissions/{uuid}/syscalls/search",
            params=syscall_search_params(
                query=query,
                pids=pids,
                failed_only=failed_only,
                apis=apis,
                after_line=after_line,
                limit=limit,
            ),
        )
        return SyscallSearchResult.model_validate(response.json())

    # =========================================================================
    # URL Analysis
    # =========================================================================

    async def get_url_analysis(self, uuid: str) -> UrlAnalysisResponse:
        """
        Get the URL analysis report for a URL submission.

        Args:
            uuid: Submission UUID (must be a URL or open-in-browser submission).

        Returns:
            Full URL analysis report (general info, IP, DNS, WHOIS, SSL, threat intel).

        Raises:
            ReportUnavailableError: When the URL analysis report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/url-analysis")
        return UrlAnalysisResponse.model_validate(response.json())

    async def get_url_analysis_session(self, uuid: str) -> UrlAnalysisSession:
        """
        Get the interactive browser session state and viewer link for a URL submission.

        Args:
            uuid: Submission UUID (must be a URL submission).

        Returns:
            UrlAnalysisSession. `link` is None until `vnc_available` is True, and
            again after the session expires. `queue_position` is set only while
            `state` is "queued".
        """
        response = await self._http.get(f"/submissions/{uuid}/url-analysis/session")
        return UrlAnalysisSession.model_validate(response.json())

    async def start_url_analysis_session(self, uuid: str) -> Message:
        """
        Start an interactive browser session on an existing URL submission.

        The response confirms acceptance only. Poll get_url_analysis_session()
        for the viewer link. A request over workspace capacity is queued, not
        rejected. This call consumes no daily submission quota.

        Args:
            uuid: Submission UUID (must be a URL submission).

        Returns:
            Message acknowledging the request.

        Raises:
            ReportUnavailableError: When the submission is a file submission,
                or when the URL report is in ``error`` (HTTP 409). Use
                restart_url_analysis() for a new capture.
        """
        response = await self._http.post(f"/submissions/{uuid}/url-analysis/session")
        return Message.model_validate(response.json())

    async def restart_url_analysis_session(self, uuid: str) -> Message:
        """
        Tear down the current interactive session and start a fresh one.

        The stored session configuration is re-supplied, so the new session keeps
        the original device and network choice. This call consumes no daily
        submission quota.

        Args:
            uuid: Submission UUID (must be a URL submission).

        Returns:
            Message acknowledging the request.

        Raises:
            ReportUnavailableError: When the submission is a file submission,
                or when the URL report is in ``error`` (HTTP 409). Use
                restart_url_analysis() for a new capture.
        """
        response = await self._http.post(f"/submissions/{uuid}/url-analysis/session/restart")
        return Message.model_validate(response.json())

    async def restart_url_analysis(self, uuid: str) -> Message:
        """
        Restart a completed or errored URL-analysis report.

        Counts against the concurrent-submission quota.

        Args:
            uuid: Submission UUID (must be a URL submission).

        Returns:
            Message acknowledging the request.
        """
        response = await self._http.post(f"/submissions/{uuid}/restart/url_analysis")
        return Message.model_validate(response.json())

    async def get_url_analysis_indicators(self, uuid: str) -> UrlAnalysisIndicators:
        """
        Get the stored explanation of the URL threat score.

        Every plan can use this call. Each indicator lists its points and its
        evidence references.

        Args:
            uuid: Submission UUID (must be a URL submission).

        Returns:
            UrlAnalysisIndicators. ``snapshot`` is set when ``state`` is
            ``"available"``. ``unavailable_reason`` is ``"legacy"``,
            ``"size_limit"`` or ``"scoring_error"`` when ``state`` is
            ``"unavailable"``.

        Raises:
            ReportUnavailableError: When the URL analysis report is not complete
                (HTTP 409).
            NotFoundError: When the submission does not exist or is private to
                another workspace.
        """
        response = await self._http.get(f"/submissions/{uuid}/url-analysis/indicators")
        return UrlAnalysisIndicators.model_validate(response.json())

    async def get_url_analysis_indicator_evidence(
        self,
        uuid: str,
        indicator_id: str,
        reference_id: str,
        *,
        job_id: str | None = None,
        scored_at: str | None = None,
    ) -> UrlAnalysisIndicatorEvidence:
        """
        Get one evidence item of an indicator in the URL score explanation.

        The API needs the ``job_id`` and ``scored_at`` of the snapshot that holds
        the indicator. When one of them is None, the SDK reads
        get_url_analysis_indicators() first and uses the snapshot values. Pass
        both to skip that extra request.

        Args:
            uuid: Submission UUID (must be a URL submission).
            indicator_id: ``UrlScoreIndicator.id`` of the snapshot.
            reference_id: ``UrlScoreEvidenceRef.id`` of the indicator.
            job_id: ``UrlScoreExplanation.job_id`` of the snapshot.
            scored_at: ``UrlScoreExplanation.scored_at`` of the snapshot, as the
                API sent it.

        Returns:
            UrlAnalysisIndicatorEvidence. ``state`` is ``"unavailable"`` when the
            evidence is not stored, or when ``job_id`` and ``scored_at`` are not
            the values of the current snapshot. ``text`` is pretty-printed JSON
            of 8192 characters or fewer.

        Raises:
            BadRequestError: When a value is malformed or too long (HTTP 400).
            NotFoundError: When the indicator or the reference is not in the
                current explanation (``URL_SCORE_EVIDENCE_NOT_FOUND``).
            ReportUnavailableError: When the URL analysis report is not complete
                (HTTP 409).
        """
        if job_id is None or scored_at is None:
            snapshot = (await self.get_url_analysis_indicators(uuid)).snapshot
            if snapshot is not None:
                job_id = snapshot.job_id if job_id is None else job_id
                scored_at = snapshot.scored_at if scored_at is None else scored_at
        response = await self._http.get(
            f"/submissions/{uuid}/url-analysis/indicators/{quote(indicator_id, safe='')}"
            f"/evidence/{quote(reference_id, safe='')}",
            params={"jobId": job_id, "scoredAt": scored_at},
        )
        return UrlAnalysisIndicatorEvidence.model_validate(response.json())

    async def get_url_analysis_browser_section(
        self, uuid: str, section: UrlAnalysisBrowserSectionName | str
    ) -> UrlAnalysisBrowserSection:
        """
        Get one section of the browser snapshot of the current URL analysis run.

        Every plan can use this call. The API returns only the approved
        sections. It never returns cookies, full network entries, or request
        and response bodies.

        Args:
            uuid: Submission UUID (must be a URL submission).
            section: ``"overview"``, ``"findings"``, ``"tls"`` or
                ``"network-summary"`` (redirects, hosts and IP addresses).

        Returns:
            UrlAnalysisBrowserSection. ``data`` holds the section as the report
            page shows it and can contain fields that the SDK does not model.

        Raises:
            NotFoundError: When the section name is not approved
                (``URL_BROWSER_SECTION_NOT_FOUND``), or when the current run has
                no data for the section (``URL_BROWSER_SECTION_UNAVAILABLE``).
            ReportUnavailableError: When the URL analysis report is not complete
                (HTTP 409).
        """
        response = await self._http.get(
            f"/submissions/{uuid}/url-analysis/browser/{quote(section, safe='')}"
        )
        return UrlAnalysisBrowserSection.model_validate(response.json())

    # =========================================================================
    # Verdict, run notes, annotations and run compare
    # =========================================================================

    async def get_verdict(self, uuid: str) -> Verdict:
        """
        Get the dynamic verdict of a Windows V2 report with its narrative and story.

        The web report shows the same data. The framework writes the narrative
        and story text. The text can change between releases: show it, do not
        parse it.

        Args:
            uuid: Submission UUID.

        Returns:
            Verdict. Every field is ``None`` for a legacy report, and for a
            stored verdict that does not belong to the committed analysis
            attempt. ``narrative`` and ``summary`` are ``None`` on reports
            older than schema 2.1.

        Raises:
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
            ReportUnavailableError: When the dynamic report is not available
                (``DYNAMIC_REPORT_UNAVAILABLE``).
        """
        response = await self._http.get(f"/submissions/{uuid}/verdict")
        return Verdict.model_validate(response.json())

    async def get_run(self, uuid: str) -> RunNotes:
        """
        Get the facts that a Windows V2 analysis states about its run.

        ``java_output.text`` is the full stored Java console text of a JAR
        sample. The API does not mask secrets that the sample wrote.

        Args:
            uuid: Submission UUID.

        Returns:
            RunNotes. For a legacy report, ``java_output`` and
            ``analysis_cut_short`` are ``None`` and the lists are empty.

        Raises:
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
            ReportUnavailableError: When the dynamic report is not available
                (``DYNAMIC_REPORT_UNAVAILABLE``).
        """
        response = await self._http.get(f"/submissions/{uuid}/run")
        return RunNotes.model_validate(response.json())

    async def get_annotations(self, uuid: str) -> Annotations:
        """
        Get the evidence pins and the note of your workspace on a submission.

        Pins and the note belong to the workspace of the API token. Each
        workspace that can see the submission keeps its own pins and note.
        You never read the annotations of another workspace.

        Args:
            uuid: Submission UUID.

        Returns:
            Annotations of your workspace. ``pins`` is empty and ``note`` is
            ``None`` when your workspace has none.

        Raises:
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
        """
        response = await self._http.get(f"/submissions/{uuid}/annotations")
        return Annotations.model_validate(response.json())

    async def pin_evidence(
        self,
        uuid: str,
        *,
        kind: AnnotationPinKind,
        ref: str,
        label: str,
    ) -> Annotations:
        """
        Add an evidence pin for your workspace.

        Your workspace can pin a submission that it can see: its own
        submissions and public submissions of other workspaces. The pin stays
        in your workspace. A second pin with the same ``kind`` and ``ref``
        changes nothing. The web UI and the HTML and PDF reports of your
        workspace show the pin.

        Args:
            uuid: Submission UUID.
            kind: Kind of the evidence, for example ``"process"`` or
                ``"technique"``.
            ref: The value that identifies the evidence (1 to 512
                characters). The web UI opens the evidence only when ``ref``
                uses the web UI format, for example ``"technique:T1055"``.
            label: Short text that names the evidence (1 to 200 characters
                after the server trims it).

        Returns:
            Annotations of your workspace after the change.

        Raises:
            BadRequestError: When the body is not valid
                (``INVALID_QUERY_PARAM``), or your workspace has 200 pins on
                the submission (``ANNOTATION_PIN_LIMIT_REACHED``).
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
        """
        response = await self._http.post(
            f"/submissions/{uuid}/annotations/pins",
            json={"kind": kind, "ref": ref, "label": label},
        )
        return Annotations.model_validate(response.json())

    async def unpin_evidence(self, uuid: str, pin_id: str) -> Annotations:
        """
        Remove one evidence pin of your workspace.

        Args:
            uuid: Submission UUID.
            pin_id: Pin ID from ``AnnotationPin.id``.

        Returns:
            Annotations of your workspace after the change.

        Raises:
            BadRequestError: When ``uuid`` or ``pin_id`` is not a UUID
                (``INVALID_QUERY_PARAM``).
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace (``NOT_FOUND``), or your
                workspace has no pin with this ID on the submission
                (``ANNOTATION_PIN_NOT_FOUND``).
        """
        response = await self._http.delete(
            f"/submissions/{uuid}/annotations/pins/{quote(pin_id, safe='')}"
        )
        return Annotations.model_validate(response.json())

    async def set_note(self, uuid: str, text: str) -> Annotations:
        """
        Replace the note of your workspace on a submission.

        The request replaces the full note text. An empty text, or a text with
        only spaces, removes the note. Your workspace can write a note on a
        submission that it can see; the note stays in your workspace.

        Args:
            uuid: Submission UUID.
            text: The full note text (0 to 10000 characters).

        Returns:
            Annotations of your workspace after the change. ``note`` is
            ``None`` after an empty text.

        Raises:
            BadRequestError: When the body is not valid
                (``INVALID_QUERY_PARAM``).
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
        """
        response = await self._http.put(
            f"/submissions/{uuid}/annotations/note", json={"text": text}
        )
        return Annotations.model_validate(response.json())

    async def get_previous_run(self, uuid: str) -> PreviousRun:
        """
        Find the previous run of the same sample or URL.

        The previous run has the same SHA256 and the same submission type, was
        created before this run, and is in the workspace of this submission.
        For a submission of another workspace, only a public previous run
        counts. Deleted runs never count.

        Args:
            uuid: Submission UUID.

        Returns:
            PreviousRun. ``previous_run_uuid`` is ``None`` when no run matches.

        Raises:
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
        """
        response = await self._http.get(f"/submissions/{uuid}/previous-run")
        return PreviousRun.model_validate(response.json())

    async def compare_runs(self, uuid: str, other_uuid: str) -> RunComparison:
        """
        Compare two runs.

        ``added`` items are in the ``uuid`` run only. ``removed`` items are in
        the ``other_uuid`` run only. Each list holds at most 200 items; the
        ``*_total`` fields count the items before that cap.

        Args:
            uuid: Submission UUID of the run to read.
            other_uuid: Submission UUID of the run to compare with, for example
                ``get_previous_run(uuid).previous_run_uuid``.

        Returns:
            RunComparison with the ``detections``, ``techniques``, ``iocs`` and
            ``dropped_files`` differences.

        Raises:
            NotFoundError: When either run does not exist, or is private and
                belongs to another workspace.
        """
        response = await self._http.get(f"/submissions/{uuid}/compare/{other_uuid}")
        return RunComparison.model_validate(response.json())

    # =========================================================================
    # AI Report
    # =========================================================================

    async def get_ai_report(self, uuid: str) -> AiReport | AiReportPending:
        """
        Get the AI analyst report of a submission.

        The report is advisory: the AI verdict never changes the submission
        ``score`` or ``level``. Requires the ``aiReport`` plan permission.

        Args:
            uuid: Submission UUID.

        Returns:
            AiReport when the server answers 200: ``status`` is ``completed``,
            ``stale``, ``failed``, or ``skipped_quota``. AiReportPending when
            the server answers 202: the report is ``waiting_for_analysis``,
            ``queued``, or ``in_progress``. Poll again later.

        Raises:
            PermissionDeniedError: When the plan has no ``aiReport`` permission.
            NotFoundError: When the submission has no AI report.
        """
        response = await self._http.get(f"/submissions/{uuid}/ai-report")
        if response.status_code == 202:
            return AiReportPending.model_validate(response.json())
        return AiReport.model_validate(response.json())

    async def regenerate_ai_report(self, uuid: str) -> AiReportRegenerateResult:
        """
        Queue a new AI analyst report for a submission.

        The new report replaces the current report when it completes. Only the
        user who submitted the submission, or an admin of its workspace, can
        queue a report. Requires the ``aiReport`` plan permission and a final
        analysis score (``AiReport.analysis_finalized``). A new report uses one
        unit of the daily AI report quota of the caller when it runs.

        Args:
            uuid: Submission UUID.

        Returns:
            AiReportRegenerateResult with ``status == "queued"`` (HTTP 202). It
            is an AiReportPending. A second request in the next 10 minutes
            returns the same result and does not queue a second report. Poll
            get_ai_report() for the new report.

        Raises:
            BadRequestError: When AI reports are disabled on the platform
                (``AI_REPORTS_DISABLED``).
            PermissionDeniedError: When the caller did not submit the submission
                and is not a workspace admin, when the submission belongs to
                another workspace, or when the plan has no ``aiReport``
                permission.
            NotFoundError: When the submission does not exist.
            ReportUnavailableError: When the analysis score is not final
                (``code == "AI_REPORT_NOT_FINALIZED"``) or an AI report is in
                progress (``code == "AI_REPORT_IN_PROGRESS"``).
            RateLimitError: When the caller used the daily AI report quota.
                ``retry_after`` gives the seconds until 00:00 UTC.
            InternalServerError: When the platform could not queue the report
                (``AI_REPORT_QUEUE_UNAVAILABLE``).
        """
        response = await self._http.post(f"/submissions/{uuid}/ai-report/regenerate")
        return AiReportRegenerateResult.model_validate(response.json())

    # =========================================================================
    # Network
    # =========================================================================

    async def get_network_summary(self, uuid: str) -> NetworkSummary:
        """
        Get network activity summary for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            Summary of network activity counts.
        """
        response = await self._http.get(f"/submissions/{uuid}/network/summary")
        return NetworkSummary.model_validate(response.json())

    async def get_dns_queries(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
        attribution: Sequence[str] | None = None,
    ) -> TotalCountList[DnsQuery]:
        """
        Get DNS queries captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.
            attribution: Row sources to return: "sample", "sample_child",
                "sensor_only", "windows_background". When unset, the server
                returns every row except "windows_background".

        Returns:
            DNS queries with host, type, status, records, and timeshift.
            ``total_count`` is the ``X-Total-Count`` header: the rows that match
            the request without ``skip`` and ``limit``, or ``None`` when the server
            does not send it.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip
        if attribution is not None:
            params["attribution"] = ",".join(attribution)

        response = await self._http.get(
            f"/submissions/{uuid}/network/dns",
            params=params if params else None,
        )
        return TotalCountList(
            (DnsQuery.model_validate(item) for item in response.json()),
            total_count=_total_count(response),
        )

    async def get_http_requests(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
        attribution: Sequence[str] | None = None,
    ) -> TotalCountList[HttpRequest]:
        """
        Get HTTP requests observed during dynamic analysis.

        The rows have a slim shape (host/ip/port/country only). To read the
        method, URL, headers and bodies of one row, call
        get_http_request_packets() with the ``id`` of the row.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.
            attribution: Row sources to return: "sample", "sample_child",
                "sensor_only", "windows_background". When unset, the server
                returns every row except "windows_background".

        Returns:
            HTTP requests in slimmed-down shape.
            ``total_count`` is the ``X-Total-Count`` header: the rows that match
            the request without ``skip`` and ``limit``, or ``None`` when the server
            does not send it.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip
        if attribution is not None:
            params["attribution"] = ",".join(attribution)

        response = await self._http.get(
            f"/submissions/{uuid}/network/http",
            params=params if params else None,
        )
        return TotalCountList(
            (HttpRequest.model_validate(item) for item in response.json()),
            total_count=_total_count(response),
        )

    async def get_tcp_connections(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
        attribution: Sequence[str] | None = None,
    ) -> TotalCountList[Connection]:
        """
        Get TCP connections captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.
            attribution: Row sources to return: "sample", "sample_child",
                "sensor_only", "windows_background". When unset, the server
                returns every row except "windows_background".

        Returns:
            TCP connections with destination, geolocation, and packet counts.
            ``total_count`` is the ``X-Total-Count`` header: the rows that match
            the request without ``skip`` and ``limit``, or ``None`` when the server
            does not send it.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip
        if attribution is not None:
            params["attribution"] = ",".join(attribution)

        response = await self._http.get(
            f"/submissions/{uuid}/network/tcp",
            params=params if params else None,
        )
        return TotalCountList(
            (Connection.model_validate(item) for item in response.json()),
            total_count=_total_count(response),
        )

    async def get_udp_connections(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
        attribution: Sequence[str] | None = None,
    ) -> TotalCountList[Connection]:
        """
        Get UDP connections captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.
            attribution: Row sources to return: "sample", "sample_child",
                "sensor_only", "windows_background". When unset, the server
                returns every row except "windows_background".

        Returns:
            UDP connections with destination, geolocation, and packet counts.
            ``total_count`` is the ``X-Total-Count`` header: the rows that match
            the request without ``skip`` and ``limit``, or ``None`` when the server
            does not send it.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip
        if attribution is not None:
            params["attribution"] = ",".join(attribution)

        response = await self._http.get(
            f"/submissions/{uuid}/network/udp",
            params=params if params else None,
        )
        return TotalCountList(
            (Connection.model_validate(item) for item in response.json()),
            total_count=_total_count(response),
        )

    async def get_network_threats(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
        attribution: Sequence[str] | None = None,
    ) -> TotalCountList[NetworkThreat]:
        """
        Get Suricata network threats detected during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.
            attribution: Row sources to return: "sample", "sample_child",
                "sensor_only", "windows_background". When unset, the server
                returns every row except "windows_background".

        Returns:
            Network threats with Suricata signature, protocol, and TLS fingerprint.
            ``total_count`` is the ``X-Total-Count`` header: the rows that match
            the request without ``skip`` and ``limit``, or ``None`` when the server
            does not send it.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip
        if attribution is not None:
            params["attribution"] = ",".join(attribution)

        response = await self._http.get(
            f"/submissions/{uuid}/network/threats",
            params=params if params else None,
        )
        return TotalCountList(
            (NetworkThreat.model_validate(item) for item in response.json()),
            total_count=_total_count(response),
        )

    async def get_network_exfil_requests(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
    ) -> TotalCountList[NetworkExfilRequest]:
        """
        Get chat bot and webhook requests read from the decrypted HTTPS capture.

        Each entry groups the requests of one API, bot or webhook, and kind.
        ``masked_target`` holds the full bot token or webhook secret as sent.
        Old reports, legacy reports, and non-Windows reports return an empty
        list. Read ``exfil_request_count`` on get_network_summary() for the count.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return (1-1000).
            skip: Number of items to skip.

        Returns:
            Chat bot and webhook requests, in the order of the first request.
            ``total_count`` is the ``X-Total-Count`` header: the rows that match
            the request without ``skip`` and ``limit``, or ``None`` when the server
            does not send it.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip

        response = await self._http.get(
            f"/submissions/{uuid}/network/exfil-requests",
            params=params if params else None,
        )
        return TotalCountList(
            (NetworkExfilRequest.model_validate(item) for item in response.json()),
            total_count=_total_count(response),
        )

    async def get_http_request_packets(self, uuid: str, request_id: str) -> NetworkHttpPackets:
        """
        Get the stored request and response pairs of one HTTP request entry.

        The payloads are not masked: a token, a password or a key in the traffic is
        returned in full. ``NetworkPacketData.data`` holds the bytes, decoded from base64.

        Args:
            uuid: Submission UUID.
            request_id: ``id`` of a row of get_http_requests(). The form ``eve-<number>``
                reads a record of the network sensor summary of an older report.

        Returns:
            At most 200 pairs in stored order. ``truncated`` is ``True`` when the entry has
            more. An empty ``items`` list means that the sandbox stored no packet.

        Raises:
            NotFoundError: When the row does not belong to the submission
                (``NETWORK_ROW_NOT_FOUND``).
            BadRequestError: When ``request_id`` is malformed.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        response = await self._http.get(
            f"/submissions/{uuid}/network/http/{quote(request_id, safe='')}/packets"
        )
        return NetworkHttpPackets.model_validate(response.json())

    async def get_tcp_connection_packets(self, uuid: str, connection_id: str) -> NetworkFlowPackets:
        """
        Get the stored packets of one TCP connection.

        The payloads are not masked. ``NetworkPacketData.data`` holds the bytes, decoded
        from base64.

        Args:
            uuid: Submission UUID.
            connection_id: ``id`` of a row of get_tcp_connections().

        Returns:
            At most 200 packets in stored order. ``truncated`` is ``True`` when the
            connection has more.

        Raises:
            NotFoundError: When the row is not a TCP row of the submission
                (``NETWORK_ROW_NOT_FOUND``).
            BadRequestError: When ``connection_id`` is malformed.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        response = await self._http.get(
            f"/submissions/{uuid}/network/tcp/{quote(connection_id, safe='')}/packets"
        )
        return NetworkFlowPackets.model_validate(response.json())

    async def get_udp_connection_packets(self, uuid: str, connection_id: str) -> NetworkFlowPackets:
        """
        Get the stored packets of one UDP connection.

        The payloads are not masked. ``NetworkPacketData.data`` holds the bytes, decoded
        from base64.

        Args:
            uuid: Submission UUID.
            connection_id: ``id`` of a row of get_udp_connections().

        Returns:
            At most 200 packets in stored order. ``truncated`` is ``True`` when the
            connection has more.

        Raises:
            NotFoundError: When the row is not a UDP row of the submission
                (``NETWORK_ROW_NOT_FOUND``).
            BadRequestError: When ``connection_id`` is malformed.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        response = await self._http.get(
            f"/submissions/{uuid}/network/udp/{quote(connection_id, safe='')}/packets"
        )
        return NetworkFlowPackets.model_validate(response.json())

    async def get_network_endpoints(
        self,
        uuid: str,
        *,
        attribution: Sequence[str] | None = None,
        limit: int | None = None,
    ) -> NetworkEndpoints:
        """
        Get the remote endpoints of the network map: the rows of each host joined.

        This is a heavy route. Each API token can send 30 heavy-route requests per minute.

        Args:
            uuid: Submission UUID.
            attribution: Row sources to return: "sample", "sample_child",
                "sensor_only", "windows_background". When unset, the server
                returns every row except "windows_background".
            limit: Maximum number of endpoints (1-500). The server default is 300.

        Returns:
            The endpoints, sample endpoints first. ``total`` is the count before ``limit``.

        Raises:
            RateLimitError: When the token sent too many heavy-route requests.
            BadRequestError: When a parameter is not valid.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        params: dict[str, Any] = {
            "attribution": ",".join(attribution) if attribution is not None else None,
            "limit": limit,
        }
        response = await self._http.get(f"/submissions/{uuid}/network/endpoints", params=params)
        return NetworkEndpoints.model_validate(response.json())

    async def get_network_host_flows(
        self,
        uuid: str,
        host: str,
        *,
        attribution: Sequence[str] | None = None,
        first: int | None = None,
        after: str | None = None,
    ) -> NetworkHostFlows:
        """
        Get one page of the flows and alerts of one network endpoint.

        This is a heavy route. Each API token can send 30 heavy-route requests per minute.
        The SDK percent-encodes ``host`` in the path.

        Args:
            uuid: Submission UUID.
            host: ``key`` of an endpoint of get_network_endpoints(). The match ignores case.
            attribution: Row sources. Send the value of the get_network_endpoints() call.
            first: Flows of the page (1-200). The server default is 50.
            after: ``page_info.end_cursor`` of the previous page. Omit it for the first
                page. Keep ``host`` and ``attribution`` the same.

        Returns:
            The flows, the totals and the alert groups of the host. An unknown host returns
            an empty page.

        Raises:
            RateLimitError: When the token sent too many heavy-route requests.
            BadRequestError: When ``host``, ``first``, ``after`` or ``attribution`` is not
                valid.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        params: dict[str, Any] = {
            "attribution": ",".join(attribution) if attribution is not None else None,
            "first": first,
            "after": after,
        }
        response = await self._http.get(
            f"/submissions/{uuid}/network/endpoints/{quote(host, safe='')}/flows",
            params=params,
        )
        return NetworkHostFlows.model_validate(response.json())

    # =========================================================================
    # Downloads
    # =========================================================================

    async def download_sample(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the original sample file for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/sample")

    async def download_artifact(self, uuid: str, artifact_id: str) -> AsyncDownloadResponse:
        """
        Download an extracted artifact.

        Args:
            uuid: Submission UUID.
            artifact_id: Artifact ID from get_artifacts().

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/artifact/{artifact_id}")

    async def download_pcap(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download network capture (PCAP) file for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/pcap")

    async def download_https_pcap(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the HTTPS inspection capture (PCAP) of the dynamic analysis.

        The capture holds the decrypted HTTPS traffic of the relayed connections. The plan
        needs the ``downloadReport`` permission. Read
        ``get_network_summary().https_pcap_available`` first.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.

        Raises:
            PermissionDeniedError: When the plan does not have the ``downloadReport``
                permission.
            NotFoundError: When the latest analysis attempt has no HTTPS inspection capture.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/pcap-https")

    async def download_behaviour(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the raw behaviour file (``behaviour.json``) of the dynamic analysis.

        The file is a JSON array of every behaviour event. The server streams the stored
        file without changes and without a size limit. Use it when ``get_behaviours()``
        raises ``BehaviourTooLargeError``. The plan needs the ``downloadReport``
        permission.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.

        Raises:
            PermissionDeniedError: When the plan does not have the ``downloadReport``
                permission.
            NotFoundError: When the dynamic report has no behaviour file.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/behaviour")

    async def download_syscalls(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the raw syscall log (``syscalls.txt``) of the dynamic analysis.

        The file holds one syscall per line. Line ``N`` of the file is
        ``BehaviourEvent.syscall_line_number`` ``N``. The server streams the stored file
        without changes. The plan needs the ``downloadReport`` permission.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.

        Raises:
            PermissionDeniedError: When the plan does not have the ``downloadReport``
                permission.
            NotFoundError: When the dynamic report has no syscall log.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/syscalls")

    async def download_yara_rule(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the generated YARA rule for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        download = await self._http.get_stream(f"/submissions/{uuid}/download/yara-rule")

        if download.status_code == 202:
            try:
                raw = await download.read()
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                payload = {}
            finally:
                await download.close()

            if not isinstance(payload, dict):
                payload = {}

            message = payload.get("message")
            if not isinstance(message, str) or not message.strip():
                message = "YARA rule generation is in progress. Please retry later."

            raise YaraRulePendingError(
                message,
                body=payload or None,
                retry_after=_parse_retry_after(payload.get("retryAfter")),
            )

        return download

    async def download_html_report(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the HTML analysis report for a submission.

        When analysts in your workspace pinned items or wrote a note on this
        submission, the report shows them in a "Pinned evidence" section.
        Other workspaces do not see them.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/html-report")

    async def download_stix_report(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the STIX 2.1 bundle (JSON) of a submission.

        The server builds the bundle on each request from the finalized
        analysis data. Use a long timeout for large submissions. Requires the
        ``stixReport`` plan permission.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the ``{uuid}_stix-2.1.json`` file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/stix-2.1-report")

    async def download_iocs(self, uuid: str, *, format: IocExportFormat) -> AsyncDownloadResponse:
        """
        Download the IP, domain, URL and SHA-256 indicators of a submission as one file.

        The web UI offers the same file. The file has no grade column and no
        grade field. The server removes values that are not valid for their
        type and duplicate values, and reads at most the first 50,000 IoC
        records; use ``get_iocs()`` to read every record of every type. Values
        are not masked: protect the file as sensitive data.

        Args:
            uuid: Submission UUID.
            format: ``"csv"`` (columns ``type``, ``value``, ``defanged``,
                ``sources``), ``"text"`` (one defanged value on each line),
                ``"stix"`` (STIX 2.1 bundle) or ``"misp"`` (MISP event JSON).
                ``"stix"`` and ``"misp"`` need the ``stixReport`` plan
                permission.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.

        Raises:
            BadRequestError: When ``format`` is not known
                (``INVALID_QUERY_PARAM``).
            PermissionDeniedError: When ``format`` is ``"stix"`` or ``"misp"``
                and the plan has no ``stixReport`` permission.
            NotFoundError: When the submission does not exist, or is private
                and belongs to another workspace.
        """
        return await self._http.get_stream(
            f"/submissions/{uuid}/download/iocs", params={"format": format}
        )

    async def get_pdf_report_status(self, uuid: str) -> PdfReportStatus:
        """
        Get the generation state of the PDF report.

        A call queues the PDF render when the analysis is finished and no PDF
        is cached. Requires the ``pdfReport`` plan permission.

        Args:
            uuid: Submission UUID.

        Returns:
            PdfReportStatus. ``status`` is ``analysis_in_progress``, ``queued``,
            ``generating``, ``ready``, or ``failed``.
        """
        response = await self._http.get(f"/submissions/{uuid}/download/pdf-report/status")
        return PdfReportStatus.model_validate(response.json())

    async def download_pdf_report(
        self,
        uuid: str,
        *,
        wait: bool = True,
        timeout: float = DEFAULT_WAIT_TIMEOUT,
        poll_interval: float | None = None,
    ) -> AsyncDownloadResponse:
        """
        Download the PDF report of a submission.

        The server renders the PDF in the background. When analysts in your
        workspace pinned items or wrote a note on this submission, the PDF
        shows them in a "Pinned evidence" section. Other workspaces do not see
        them. Requires the ``pdfReport`` plan permission.

        Args:
            uuid: Submission UUID.
            wait: When True (default), poll get_pdf_report_status() until the
                status is ``ready``, then download the file. The wait stops
                after ``timeout`` seconds. When False, request the file once.
            timeout: Maximum time to wait in seconds when ``wait`` is True.
                Defaults to 600.
            poll_interval: Time between status checks in seconds. Defaults to
                the server ``retry_after_seconds`` hint, or 5 seconds.

        Returns:
            AsyncDownloadResponse for streaming or saving the ``{uuid}_report.pdf`` file.

        Raises:
            PdfReportPendingError: When ``wait`` is False and the server
                answers 202, or when the PDF is not ready before ``timeout``.
            InternalServerError: When the status route reports ``failed``.
            ReportUnavailableError: When ``wait`` is False and the analysis
                is not finished (HTTP 409).
        """
        if not wait:
            return await self._open_pdf_report(uuid)

        deadline = time.monotonic() + timeout
        while True:
            status = await self.get_pdf_report_status(uuid)
            if status.status == "failed":
                raise InternalServerError(
                    status.message or "PDF report generation failed.",
                    status_code=500,
                    body=status.model_dump(mode="json", by_alias=True),
                )
            retry_after = status.retry_after_seconds
            if status.status == "ready":
                try:
                    return await self._open_pdf_report(uuid)
                except PdfReportPendingError as pending:
                    retry_after = pending.retry_after

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PdfReportPendingError(
                    f"PDF report was not ready within {timeout} seconds "
                    f"(last status: {status.status}).",
                    body=status.model_dump(mode="json", by_alias=True),
                    retry_after=retry_after,
                )
            if poll_interval is not None:
                delay = poll_interval
            elif retry_after is not None:
                delay = retry_after
            else:
                delay = DEFAULT_POLL_INTERVAL
            await asyncio.sleep(min(delay, remaining))

    async def _open_pdf_report(self, uuid: str) -> AsyncDownloadResponse:
        download = await self._http.get_stream(f"/submissions/{uuid}/download/pdf-report")
        if download.status_code != 202:
            return download

        try:
            payload = _pending_body(await download.read())
        finally:
            await download.close()

        message = payload.get("message")
        if not isinstance(message, str) or not message.strip():
            message = "PDF report generation is in progress. Please retry later."
        raise PdfReportPendingError(
            message,
            body=payload or None,
            retry_after=_parse_retry_after(payload.get("retryAfter")),
        )

    async def download_cdr_result(self, uuid: str) -> AsyncDownloadResponse:
        """
        Download the sanitized file from CDR analysis.

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/cdr")

    async def get_screenshot(self, uuid: str) -> bytes:
        """
        Get URL analysis screenshot.

        Args:
            uuid: Submission UUID (must be a URL submission).

        Returns:
            Screenshot image as bytes.
        """
        response = await self._http.get(f"/submissions/{uuid}/screenshot")
        return response.content

    async def list_media_files(self, uuid: str, *, source: str | None = None) -> list[MediaFile]:
        """
        List available media files (screenshots, videos) for a submission.

        Args:
            uuid: Submission UUID.
            source: Report family to read from: "dynamic" or "url_analysis".
                Defaults server-side to "dynamic" when the submission has a
                dynamic report, otherwise "url_analysis".

        Returns:
            List of available media files. Each item carries a `kind` of
            "video", "screenshot", or None.
        """
        response = await self._http.get(f"/submissions/{uuid}/media", params={"source": source})
        return [MediaFile.model_validate(item) for item in response.json()]

    async def get_media_file(self, uuid: str, file_id: str, *, source: str | None = None) -> bytes:
        """
        Get a specific media file.

        Args:
            uuid: Submission UUID.
            file_id: Media file ID from list_media_files().
            source: Report family to read from: "dynamic" or "url_analysis".
                Defaults server-side as described on list_media_files().

        Returns:
            Media file content as bytes.
        """
        response = await self._http.get(
            f"/submissions/{uuid}/media/{file_id}", params={"source": source}
        )
        return response.content
