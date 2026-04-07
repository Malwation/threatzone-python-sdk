"""Asynchronous Threat.Zone client implementation."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any

import httpx

from ._client import AsyncHTTPClient, FileInput
from ._config import ClientConfig
from ._constants import DEFAULT_POLL_INTERVAL, DEFAULT_WAIT_TIMEOUT
from ._exceptions import AnalysisTimeoutError, YaraRulePendingError
from ._streaming import AsyncDownloadResponse
from .types import (
    ArtifactsResponse,
    BehaviourOs,
    BehavioursResponse,
    CdrResponse,
    Connection,
    DnsQuery,
    EmlAnalysis,
    EnvironmentOption,
    ExtractedConfigsResponse,
    HttpRequest,
    IndicatorLevel,
    IndicatorsResponse,
    IoCsResponse,
    IoCType,
    MediaFile,
    MetafieldOption,
    Metafields,
    MitreResponse,
    NetworkSummary,
    NetworkThreat,
    OverviewSummary,
    PaginatedSubmissions,
    ProcessesResponse,
    ProcessTreeResponse,
    SignatureCheckResponse,
    StaticScanResponse,
    Submission,
    SubmissionCreated,
    SyscallsResponse,
    UrlAnalysisResponse,
    UserInfo,
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

    # =========================================================================
    # Submissions - Create
    # =========================================================================

    async def create_sandbox_submission(
        self,
        file: FileInput,
        *,
        environment: str | None = None,
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
                - network_config: Network configuration ID (MongoDB ObjectId)

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        multipart = self._http._build_multipart_data(
            file,
            environment=environment,
            metafields=metafields,
            private=private,
            entrypoint=entrypoint,
            password=password,
            configurations=configurations,
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
    ) -> SubmissionCreated:
        """
        Create a new static analysis submission.

        Args:
            file: File to analyze. Can be a file path, bytes, or file-like object.
            private: If True, submission is private to your workspace.
            entrypoint: Entry point for archive files.
            password: Password for encrypted archives.

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        multipart = self._http._build_multipart_data(
            file,
            private=private,
            entrypoint=entrypoint,
            password=password,
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
    ) -> SubmissionCreated:
        """
        Create a new CDR (Content Disarm & Reconstruction) submission.

        Args:
            file: File to sanitize. Can be a file path, bytes, or file-like object.
            private: If True, submission is private to your workspace.
            entrypoint: Entry point for archive files.
            password: Password for encrypted archives.

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        multipart = self._http._build_multipart_data(
            file,
            private=private,
            entrypoint=entrypoint,
            password=password,
        )
        response = await self._http.post("/submissions/cdr", **multipart)
        return SubmissionCreated.model_validate(response.json())

    async def create_url_submission(
        self,
        url: str,
        *,
        private: bool = False,
    ) -> SubmissionCreated:
        """
        Create a new URL analysis submission.

        Args:
            url: URL to analyze.
            private: If True, submission is private to your workspace.

        Returns:
            SubmissionCreated with the new submission UUID.
        """
        response = await self._http.post(
            "/submissions/url_analysis",
            json={"url": url, "private": private},
        )
        return SubmissionCreated.model_validate(response.json())

    async def create_open_in_browser_submission(
        self,
        url: str,
        *,
        environment: str | None = None,
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

    async def search_by_sha256(self, sha256: str) -> list[Submission]:
        """
        Search submissions by SHA256 hash.

        Args:
            sha256: SHA256 hash to search for.

        Returns:
            List of matching submissions.
        """
        response = await self._http.get(f"/submissions/search/sha256/{sha256}")
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

    async def get_artifacts(self, uuid: str) -> ArtifactsResponse:
        """
        Get extracted artifacts for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            Paginated artifact list. Each artifact carries nested MD5/SHA1/SHA256 hashes.
        """
        response = await self._http.get(f"/submissions/{uuid}/artifacts")
        return ArtifactsResponse.model_validate(response.json())

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
        Get static scan results (per artifact) for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            Static scan envelope with per-artifact analyzer output.

        Raises:
            ReportUnavailableError: When the static report is not yet available.
        """
        response = await self._http.get(f"/submissions/{uuid}/static-scan")
        return StaticScanResponse.model_validate(response.json())

    async def get_cdr_results(self, uuid: str) -> CdrResponse:
        """
        Get Content Disarm and Reconstruction (CDR) results for a submission.

        This returns the structured per-artifact CDR engine output. Use
        ``download_cdr_result()`` to download the sanitized file itself.

        Args:
            uuid: Submission UUID.

        Returns:
            CDR results envelope.

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

    async def get_behaviours(
        self,
        uuid: str,
        *,
        os: BehaviourOs,
        pid: int | None = None,
        operation: str | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> BehavioursResponse:
        """
        Get OS-specific behaviour events captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            os: REQUIRED. Target operating system (windows/linux/android/macos).
            pid: Filter by process ID.
            operation: Filter by operation name.
            page: 1-indexed page number.
            limit: Maximum items per page (1-500).

        Returns:
            Paginated behaviour events tagged with their source OS.

        Raises:
            ValueError: When ``os`` is None or empty.
            ReportUnavailableError: When the dynamic report is not yet available.
        """
        if not os:
            raise ValueError("get_behaviours() requires the 'os' keyword argument")

        params: dict[str, Any] = {"os": os}
        if pid is not None:
            params["pid"] = pid
        if operation is not None:
            params["operation"] = operation
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit

        response = await self._http.get(
            f"/submissions/{uuid}/behaviours",
            params=params,
        )
        return BehavioursResponse.model_validate(response.json())

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
    ) -> list[DnsQuery]:
        """
        Get DNS queries captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.

        Returns:
            DNS queries with host, type, status, records, and timeshift.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip

        response = await self._http.get(
            f"/submissions/{uuid}/network/dns",
            params=params if params else None,
        )
        return [DnsQuery.model_validate(item) for item in response.json()]

    async def get_http_requests(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[HttpRequest]:
        """
        Get HTTP requests observed during dynamic analysis.

        The API now returns a slim shape (host/ip/port/country only). Method
        and URL data are no longer available because they were never reliably
        recoverable from the captured packets.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.

        Returns:
            HTTP requests in slimmed-down shape.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip

        response = await self._http.get(
            f"/submissions/{uuid}/network/http",
            params=params if params else None,
        )
        return [HttpRequest.model_validate(item) for item in response.json()]

    async def get_tcp_connections(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[Connection]:
        """
        Get TCP connections captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.

        Returns:
            TCP connections with destination, geolocation, and packet counts.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip

        response = await self._http.get(
            f"/submissions/{uuid}/network/tcp",
            params=params if params else None,
        )
        return [Connection.model_validate(item) for item in response.json()]

    async def get_udp_connections(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[Connection]:
        """
        Get UDP connections captured during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.

        Returns:
            UDP connections with destination, geolocation, and packet counts.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip

        response = await self._http.get(
            f"/submissions/{uuid}/network/udp",
            params=params if params else None,
        )
        return [Connection.model_validate(item) for item in response.json()]

    async def get_network_threats(
        self,
        uuid: str,
        *,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[NetworkThreat]:
        """
        Get Suricata network threats detected during dynamic analysis.

        Args:
            uuid: Submission UUID.
            limit: Maximum number of items to return.
            skip: Number of items to skip.

        Returns:
            Network threats with Suricata signature, protocol, and TLS fingerprint.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if skip is not None:
            params["skip"] = skip

        response = await self._http.get(
            f"/submissions/{uuid}/network/threats",
            params=params if params else None,
        )
        return [NetworkThreat.model_validate(item) for item in response.json()]

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

        Args:
            uuid: Submission UUID.

        Returns:
            AsyncDownloadResponse for streaming or saving the file.
        """
        return await self._http.get_stream(f"/submissions/{uuid}/download/html-report")

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

    async def list_media_files(self, uuid: str) -> list[MediaFile]:
        """
        List available media files (screenshots, videos) for a submission.

        Args:
            uuid: Submission UUID.

        Returns:
            List of available media files.
        """
        response = await self._http.get(f"/submissions/{uuid}/media")
        return [MediaFile.model_validate(item) for item in response.json()]

    async def get_media_file(self, uuid: str, file_id: str) -> bytes:
        """
        Get a specific media file.

        Args:
            uuid: Submission UUID.
            file_id: Media file ID from list_media_files().

        Returns:
            Media file content as bytes.
        """
        response = await self._http.get(f"/submissions/{uuid}/media/{file_id}")
        return response.content
