"""In-process fake of the Threat.Zone Public API for SDK testing.

Builds an httpx ``MockTransport`` that the SDK clients can use through their
``http_client=`` constructor argument. Tests seed scenarios via
``register_sample`` / ``register_url_analysis`` and the fake hands back
Pydantic-validated JSON responses that exactly mirror the real API contract.
"""

from __future__ import annotations

import hashlib
import json
import struct
import uuid
import zlib
from collections import Counter
from collections.abc import Callable
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import BaseModel

from . import _responses
from .routes import RouteMatch, match_route
from .state import (
    IndicatorSeed,
    IocSeed,
    NetworkThreatSeed,
    SubmissionState,
    YaraRuleSeed,
)

ThreatLevelStr = Literal["unknown", "benign", "suspicious", "malicious"]
ReportTypeStr = Literal["dynamic", "static", "cdr", "url_analysis"]


_MIN_PNG = (
    b"\x89PNG\r\n\x1a\n"
    + b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    + b"\x00\x00\x00\rIDATx\x9cc\xfa\xcf\x00\x00\x00\x02\x00\x01\xe5\x27\xde\xfc"
    + b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _build_minimal_zip(filename: str, payload: bytes) -> bytes:
    """Build a tiny in-memory ZIP archive containing a single file."""
    name_bytes = filename.encode("utf-8")
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    compressed = payload
    local_header = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(compressed),
        len(payload),
        len(name_bytes),
        0,
    )
    local_entry = local_header + name_bytes + compressed
    central_header = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(compressed),
        len(payload),
        len(name_bytes),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    central_entry = central_header + name_bytes
    end_record = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central_entry),
        len(local_entry),
        0,
    )
    return local_entry + central_entry + end_record


def _deterministic_uuid(seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _deterministic_sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _serialize(model: BaseModel) -> bytes:
    payload = model.model_dump(mode="json", by_alias=True)
    return json.dumps(payload).encode("utf-8")


def _serialize_list(models: list[BaseModel]) -> bytes:
    payload = [m.model_dump(mode="json", by_alias=True) for m in models]
    return json.dumps(payload).encode("utf-8")


def _error(
    status_code: int,
    error: str,
    message: str,
    code: str,
    details: dict[str, Any] | None = None,
) -> httpx.Response:
    body: dict[str, Any] = {
        "statusCode": status_code,
        "error": error,
        "message": message,
        "code": code,
    }
    if details is not None:
        body["details"] = details
    return httpx.Response(
        status_code,
        content=json.dumps(body).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _json(model: BaseModel, *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=_serialize(model),
        headers={"content-type": "application/json"},
    )


def _json_list(models: list[BaseModel], *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=_serialize_list(models),
        headers={"content-type": "application/json"},
    )


def _binary(payload: bytes, content_type: str) -> httpx.Response:
    return httpx.Response(
        200,
        content=payload,
        headers={"content-type": content_type},
    )


class FakeThreatZoneAPI:
    """In-process fake of the Threat.Zone Public API for SDK testing.

    Usage::

        fake = FakeThreatZoneAPI()
        fake.register_sample(sha256="a" * 64, verdict="malicious")

        from threatzone import ThreatZone

        client = ThreatZone(
            api_key="test-key",
            base_url="https://fake.threat.zone/public-api",
            http_client=fake.as_httpx_client(),
        )
        submission = client.create_sandbox_submission("dummy.exe")
        completed = client.wait_for_completion(
            submission.uuid, poll_interval=0.001, timeout=5
        )
        assert completed.level == "malicious"
    """

    def __init__(self, *, base_url: str = "https://fake.threat.zone/public-api") -> None:
        self._base_url = base_url.rstrip("/")
        parsed = urlparse(self._base_url)
        self._host: str = parsed.hostname or "fake.threat.zone"
        self._path_prefix: str = parsed.path or ""
        self._states: dict[str, SubmissionState] = {}
        self._sha_to_uuid: dict[str, str] = {}
        self._url_to_uuid: dict[str, str] = {}
        self._pending_seeds: dict[str, SubmissionState] = {}
        self._request_log: list[httpx.Request] = []
        self._poll_counts: Counter[str] = Counter()
        self._transport = httpx.MockTransport(self._handle)

    @property
    def request_log(self) -> list[httpx.Request]:
        """Every request that went through the transport, in order."""
        return list(self._request_log)

    def poll_count(self, submission_uuid: str) -> int:
        """How many times the given submission's detail endpoint was polled."""
        return self._poll_counts[submission_uuid]

    def as_transport(self) -> httpx.MockTransport:
        """Return the underlying ``MockTransport`` for callers building their own client."""
        return self._transport

    def as_httpx_client(self) -> httpx.Client:
        """Return a sync ``httpx.Client`` whose transport routes into this fake."""
        return httpx.Client(transport=self._transport, base_url=self._base_url)

    def as_async_httpx_client(self) -> httpx.AsyncClient:
        """Return an async ``httpx.AsyncClient`` whose transport routes into this fake."""
        return httpx.AsyncClient(transport=self._transport, base_url=self._base_url)

    def reset(self) -> None:
        """Clear all seeded scenarios, submissions, and request history."""
        self._states.clear()
        self._sha_to_uuid.clear()
        self._url_to_uuid.clear()
        self._pending_seeds.clear()
        self._request_log.clear()
        self._poll_counts.clear()

    def register_sample(
        self,
        *,
        sha256: str,
        filename: str = "sample.exe",
        verdict: ThreatLevelStr = "malicious",
        advance_after_polls: int = 2,
        indicators: list[tuple[str, str, list[int]]] | None = None,
        network_threats: list[tuple[str, Literal["high", "low"], Literal["HTTP", "TLS", "DNS"]]]
        | None = None,
        yara_rules: list[tuple[str, Literal["malicious", "suspicious", "benign"]]] | None = None,
        iocs: list[tuple[str, str]] | None = None,
        mitre_techniques: list[str] | None = None,
        include_static_report: bool = False,
        include_cdr_report: bool = False,
    ) -> None:
        """Seed a file-submission scenario keyed by its SHA-256.

        The next ``POST /submissions/sandbox|static|cdr`` will pick this seed up
        and use it as the response shape for that submission. Tests can also
        directly look it up via ``GET /submissions/search/sha256/<sha>``.
        """
        seed = self._build_state(
            sha256=sha256,
            filename=filename,
            kind="file",
            verdict=verdict,
            advance_after_polls=advance_after_polls,
            indicators=indicators,
            network_threats=network_threats,
            yara_rules=yara_rules,
            iocs=iocs,
            mitre_techniques=mitre_techniques,
            include_static_report=include_static_report,
            include_cdr_report=include_cdr_report,
        )
        self._pending_seeds[sha256] = seed

    def register_url_analysis(
        self,
        *,
        url: str,
        verdict: ThreatLevelStr = "suspicious",
        advance_after_polls: int = 2,
        final_url: str | None = None,
        screenshot_available: bool = True,
        threat_analysis_summary: str = "Phishing kit detected",
    ) -> None:
        """Seed a URL-submission scenario keyed by its URL string."""
        submission_uuid = _deterministic_uuid(f"url::{url}")
        sha = _deterministic_sha256(f"url::{url}")
        state = SubmissionState(
            uuid=submission_uuid,
            sha256=sha,
            type="url",
            filename=url,
            level=verdict,
            advance_after_polls=advance_after_polls,
            has_dynamic_report=False,
            has_url_analysis_report=True,
            url=url,
            final_url=final_url,
            screenshot_available=screenshot_available,
            threat_analysis_summary=threat_analysis_summary,
            artifact_ids=[f"art-{submission_uuid[:8]}-1"],
            media_ids=[f"media-{submission_uuid[:8]}-1"],
        )
        self._url_to_uuid[url] = submission_uuid
        self._states[submission_uuid] = state

    def mark_report_unavailable(self, submission_uuid: str, report_type: str) -> None:
        """Force a report to appear unavailable when the SDK queries it."""
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        if report_type == "dynamic":
            state.has_dynamic_report = False
        elif report_type == "static":
            state.has_static_report = False
        elif report_type == "cdr":
            state.has_cdr_report = False
        elif report_type == "url_analysis":
            state.has_url_analysis_report = False

    def mark_private(
        self,
        submission_uuid: str,
        owning_workspace: str = "other-workspace",
    ) -> None:
        """Mark a submission as private and owned by a different workspace."""
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        state.private = True
        state.owning_workspace = owning_workspace

    def delete_submission(self, submission_uuid: str) -> None:
        """Remove a seeded submission from the fake."""
        state = self._states.pop(submission_uuid, None)
        if state is None:
            return
        if state.type == "file" and state.sha256 in self._sha_to_uuid:
            del self._sha_to_uuid[state.sha256]
        if state.type == "url" and state.url and state.url in self._url_to_uuid:
            del self._url_to_uuid[state.url]

    def _build_state(
        self,
        *,
        sha256: str,
        filename: str,
        kind: Literal["file", "url"],
        verdict: ThreatLevelStr,
        advance_after_polls: int,
        indicators: list[tuple[str, str, list[int]]] | None,
        network_threats: list[tuple[str, Literal["high", "low"], Literal["HTTP", "TLS", "DNS"]]]
        | None,
        yara_rules: list[tuple[str, Literal["malicious", "suspicious", "benign"]]] | None,
        iocs: list[tuple[str, str]] | None,
        mitre_techniques: list[str] | None,
        include_static_report: bool,
        include_cdr_report: bool,
    ) -> SubmissionState:
        submission_uuid = _deterministic_uuid(f"sample::{sha256}")
        seeds_indicators = [
            IndicatorSeed(attack_code=ac, level=lvl, pids=list(pids))  # type: ignore[arg-type]
            for (ac, lvl, pids) in (indicators or [])
        ]
        seeds_threats = [
            NetworkThreatSeed(signature=sig, severity=sev, app_proto=ap)
            for (sig, sev, ap) in (network_threats or [])
        ]
        seeds_yara = [YaraRuleSeed(rule=r, category=c) for (r, c) in (yara_rules or [])]
        seeds_iocs = [IocSeed(type=t, value=v) for (t, v) in (iocs or [])]
        return SubmissionState(
            uuid=submission_uuid,
            sha256=sha256,
            type=kind,
            filename=filename,
            level=verdict,
            advance_after_polls=advance_after_polls,
            indicators=seeds_indicators,
            network_threats=seeds_threats,
            yara_rules=seeds_yara,
            iocs=seeds_iocs,
            mitre_techniques=list(mitre_techniques or []),
            has_static_report=include_static_report,
            has_cdr_report=include_cdr_report,
            artifact_ids=[f"art-{submission_uuid[:8]}-1"],
            media_ids=[f"media-{submission_uuid[:8]}-1"],
        )

    def _activate_pending_seed(self, sha256: str) -> SubmissionState:
        seed = self._pending_seeds.pop(sha256)
        self._states[seed.uuid] = seed
        self._sha_to_uuid[sha256] = seed.uuid
        return seed

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self._request_log.append(request)

        path = request.url.path
        if self._path_prefix and path.startswith(self._path_prefix):
            path = path[len(self._path_prefix) :] or "/"

        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer ") or not auth[len("bearer ") :].strip():
            return _error(
                401,
                "Unauthorized",
                "Authentication required",
                "UNAUTHORIZED",
            )

        match = match_route(request.method, path)
        if match is None:
            return _error(
                404,
                "Not Found",
                f"Route not handled by fake: {request.method} {path}",
                "SUBMISSION_NOT_FOUND",
            )

        handler = self._handlers().get(match.name)
        if handler is None:
            return _error(
                404,
                "Not Found",
                f"No handler for route: {match.name}",
                "SUBMISSION_NOT_FOUND",
            )
        return handler(request, match)

    def _handlers(self) -> dict[str, Callable[[httpx.Request, RouteMatch], httpx.Response]]:
        return {
            "get_user_info": self._handle_get_user_info,
            "get_metafields_all": self._handle_metafields_all,
            "get_metafields_by_type": self._handle_metafields_by_type,
            "get_environments": self._handle_environments,
            "list_submissions": self._handle_list_submissions,
            "get_submission": self._handle_get_submission,
            "search_by_sha256": self._handle_search_by_sha256,
            "create_sandbox": self._handle_create_file,
            "create_static": self._handle_create_static,
            "create_cdr": self._handle_create_cdr,
            "create_url_analysis": self._handle_create_url,
            "create_open_in_browser": self._handle_create_open_in_browser,
            "get_summary": self._handle_get_summary,
            "get_indicators": self._handle_get_indicators,
            "get_iocs": self._handle_get_iocs,
            "get_yara_rules": self._handle_get_yara_rules,
            "get_extracted_configs": self._handle_get_extracted_configs,
            "get_artifacts": self._handle_get_artifacts,
            "get_eml_analysis": self._handle_get_eml,
            "get_mitre": self._handle_get_mitre,
            "get_static_scan": self._handle_get_static_scan,
            "get_cdr": self._handle_get_cdr_report,
            "get_signature_check": self._handle_get_signature_check,
            "get_processes": self._handle_get_processes,
            "get_process_tree": self._handle_get_process_tree,
            "get_behaviours": self._handle_get_behaviours,
            "get_syscalls": self._handle_get_syscalls,
            "get_network_summary": self._handle_get_network_summary,
            "get_network_dns": self._handle_get_dns,
            "get_network_http": self._handle_get_http,
            "get_network_tcp": self._handle_get_tcp,
            "get_network_udp": self._handle_get_udp,
            "get_network_threats": self._handle_get_network_threats,
            "download_pcap": self._handle_download_pcap,
            "download_sample": self._handle_download_sample,
            "download_artifact": self._handle_download_artifact,
            "download_yara_rule": self._handle_download_yara_rule,
            "download_html_report": self._handle_download_html,
            "download_cdr": self._handle_download_cdr,
            "get_url_analysis": self._handle_get_url_analysis,
            "get_screenshot": self._handle_get_screenshot,
            "list_media": self._handle_list_media,
            "get_media_file": self._handle_get_media_file,
        }

    @staticmethod
    def _query(request: httpx.Request) -> dict[str, list[str]]:
        return parse_qs(
            request.url.query.decode("ascii")
            if isinstance(request.url.query, bytes)
            else request.url.query
        )

    @staticmethod
    def _first(query: dict[str, list[str]], key: str) -> str | None:
        values = query.get(key)
        if not values:
            return None
        return values[0]

    @staticmethod
    def _int(query: dict[str, list[str]], key: str) -> int | None:
        raw = FakeThreatZoneAPI._first(query, key)
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError as exc:
            raise _BadQueryParam(key) from exc

    def _require_state(
        self, uuid_param: str
    ) -> tuple[SubmissionState | None, httpx.Response | None]:
        state = self._states.get(uuid_param)
        if state is None:
            return None, _error(
                404,
                "Not Found",
                "Submission not found",
                "SUBMISSION_NOT_FOUND",
                {"submissionUuid": uuid_param},
            )
        if state.private and state.owning_workspace != "test-workspace":
            return None, _error(
                403,
                "Forbidden",
                "Submission is private",
                "SUBMISSION_PRIVATE",
                {"submissionUuid": uuid_param},
            )
        return state, None

    def _require_dynamic(self, state: SubmissionState) -> httpx.Response | None:
        if not state.has_dynamic_report:
            return _error(
                409,
                "Conflict",
                "Dynamic report is not available",
                "DYNAMIC_REPORT_UNAVAILABLE",
                {
                    "submissionUuid": state.uuid,
                    "requiredReport": "dynamic",
                    "currentStatus": "not_started",
                    "availableReports": state.available_reports(),
                },
            )
        return None

    def _require_static(self, state: SubmissionState) -> httpx.Response | None:
        if not state.has_static_report:
            return _error(
                409,
                "Conflict",
                "Static report is not available",
                "STATIC_REPORT_UNAVAILABLE",
                {
                    "submissionUuid": state.uuid,
                    "requiredReport": "static",
                    "currentStatus": "not_started",
                    "availableReports": state.available_reports(),
                },
            )
        return None

    def _require_cdr(self, state: SubmissionState) -> httpx.Response | None:
        if not state.has_cdr_report:
            return _error(
                409,
                "Conflict",
                "CDR report is not available",
                "CDR_REPORT_UNAVAILABLE",
                {
                    "submissionUuid": state.uuid,
                    "requiredReport": "cdr",
                    "currentStatus": "not_started",
                    "availableReports": state.available_reports(),
                },
            )
        return None

    def _require_url_analysis(self, state: SubmissionState) -> httpx.Response | None:
        if not state.has_url_analysis_report:
            return _error(
                409,
                "Conflict",
                "URL analysis report is not available",
                "URL_ANALYSIS_REPORT_UNAVAILABLE",
                {
                    "submissionUuid": state.uuid,
                    "requiredReport": "url_analysis",
                    "currentStatus": "not_started",
                    "availableReports": state.available_reports(),
                },
            )
        return None

    def _handle_get_user_info(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del request, match
        return _json(_responses.build_user_info())

    def _handle_metafields_all(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del request, match
        return _json(_responses.build_metafields())

    def _handle_metafields_by_type(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        del request
        scan_type = match.params["scan_type"]
        if scan_type not in {"sandbox", "static", "cdr", "url", "open_in_browser"}:
            return _error(
                400,
                "Bad Request",
                f"Unknown scan type: {scan_type}",
                "INVALID_QUERY_PARAM",
                {"param": "scan_type"},
            )
        items = _responses.build_metafields_for(scan_type)
        return _json_list(list(items))

    def _handle_environments(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del request, match
        return _json_list(list(_responses.build_environments()))

    def _handle_list_submissions(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del match
        try:
            query = self._query(request)
            page = self._int(query, "page") or 1
            limit = self._int(query, "limit") or 20
        except _BadQueryParam as exc:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {exc.param}",
                "INVALID_QUERY_PARAM",
                {"param": exc.param},
            )
        if limit < 1 or limit > 100:
            return _error(
                400,
                "Bad Request",
                "limit must be between 1 and 100",
                "INVALID_QUERY_PARAM",
                {"param": "limit"},
            )
        if page < 1:
            return _error(
                400,
                "Bad Request",
                "page must be >= 1",
                "INVALID_QUERY_PARAM",
                {"param": "page"},
            )
        items = list(self._states.values())
        sha_filter = self._first(query, "sha256")
        if sha_filter:
            items = [s for s in items if s.sha256 == sha_filter]
        type_filter = self._first(query, "type")
        if type_filter:
            items = [s for s in items if s.type == type_filter]
        return _json(_responses.build_paginated_submissions(items, page=page, limit=limit))

    def _handle_get_submission(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        uuid_param = match.params["uuid"]
        state, err = self._require_state(uuid_param)
        if err is not None or state is None:
            assert err is not None
            return err
        self._poll_counts[state.uuid] += 1
        state.bump_poll()
        return _json(_responses.build_submission(state))

    def _handle_search_by_sha256(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del request
        sha = match.params["sha256"]
        if sha in self._pending_seeds:
            self._activate_pending_seed(sha)
        results = [s for s in self._states.values() if s.sha256 == sha]
        return _json_list([_responses.build_submission(s) for s in results])

    def _create_submission(
        self,
        request: httpx.Request,
        *,
        kind: Literal["file"],
        seed_filename: str,
        ensure_dynamic: bool,
        ensure_static: bool,
        ensure_cdr: bool,
    ) -> httpx.Response:
        del request
        sha = next(iter(self._pending_seeds.keys()), None)
        if sha is not None:
            state = self._activate_pending_seed(sha)
        else:
            generated_sha = _deterministic_sha256(f"auto::{uuid.uuid4()}")
            state = self._build_state(
                sha256=generated_sha,
                filename=seed_filename,
                kind=kind,
                verdict="unknown",
                advance_after_polls=2,
                indicators=None,
                network_threats=None,
                yara_rules=None,
                iocs=None,
                mitre_techniques=None,
                include_static_report=False,
                include_cdr_report=False,
            )
            self._states[state.uuid] = state
            self._sha_to_uuid[generated_sha] = state.uuid
        if ensure_dynamic:
            state.has_dynamic_report = True
        if ensure_static:
            state.has_static_report = True
        if ensure_cdr:
            state.has_cdr_report = True
        return _json(_responses.build_submission_created(state), status_code=200)

    def _handle_create_file(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del match
        return self._create_submission(
            request,
            kind="file",
            seed_filename="sample.exe",
            ensure_dynamic=True,
            ensure_static=False,
            ensure_cdr=False,
        )

    def _handle_create_static(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del match
        return self._create_submission(
            request,
            kind="file",
            seed_filename="sample.bin",
            ensure_dynamic=False,
            ensure_static=True,
            ensure_cdr=False,
        )

    def _handle_create_cdr(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del match
        return self._create_submission(
            request,
            kind="file",
            seed_filename="sample.docx",
            ensure_dynamic=False,
            ensure_static=False,
            ensure_cdr=True,
        )

    def _handle_create_url(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del match
        try:
            payload = json.loads(request.content.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}
        target_url = str(payload.get("url") or "https://auto.example.com")
        existing_uuid = self._url_to_uuid.get(target_url)
        if existing_uuid:
            state = self._states[existing_uuid]
        else:
            self.register_url_analysis(url=target_url, verdict="unknown")
            state = self._states[self._url_to_uuid[target_url]]
        return _json(_responses.build_submission_created(state), status_code=200)

    def _handle_create_open_in_browser(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        del match
        try:
            payload = json.loads(request.content.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}
        target_url = str(payload.get("url") or "https://auto.example.com")
        existing_uuid = self._url_to_uuid.get(target_url)
        if existing_uuid:
            state = self._states[existing_uuid]
        else:
            self.register_url_analysis(url=target_url, verdict="unknown")
            state = self._states[self._url_to_uuid[target_url]]
        state.has_dynamic_report = True
        return _json(_responses.build_submission_created(state), status_code=200)

    def _handle_get_summary(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json(_responses.build_overview_summary(state))

    def _handle_get_indicators(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        try:
            query = self._query(request)
            page = self._int(query, "page")
            limit = self._int(query, "limit")
        except _BadQueryParam as exc:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {exc.param}",
                "INVALID_QUERY_PARAM",
                {"param": exc.param},
            )
        if limit is not None and (limit < 1 or limit > 100):
            return _error(
                400,
                "Bad Request",
                "limit must be between 1 and 100",
                "INVALID_QUERY_PARAM",
                {"param": "limit"},
            )
        raw_pid = self._first(query, "pid")
        pid_value: int | None = int(raw_pid) if raw_pid is not None else None
        return _json(
            _responses.build_indicators_response(
                state,
                level=self._first(query, "level"),
                category=self._first(query, "category"),
                pid=pid_value,
                attack_code=self._first(query, "attackCode"),
                page=page,
                limit=limit,
            )
        )

    def _handle_get_iocs(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        try:
            query = self._query(request)
            page = self._int(query, "page")
            limit = self._int(query, "limit")
        except _BadQueryParam as exc:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {exc.param}",
                "INVALID_QUERY_PARAM",
                {"param": exc.param},
            )
        return _json(
            _responses.build_iocs_response(
                state,
                type_filter=self._first(query, "type"),
                page=page,
                limit=limit,
            )
        )

    def _handle_get_yara_rules(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        try:
            query = self._query(request)
            page = self._int(query, "page")
            limit = self._int(query, "limit")
        except _BadQueryParam as exc:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {exc.param}",
                "INVALID_QUERY_PARAM",
                {"param": exc.param},
            )
        return _json(
            _responses.build_yara_rules_response(
                state,
                category=self._first(query, "category"),
                page=page,
                limit=limit,
            )
        )

    def _handle_get_extracted_configs(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json(_responses.build_extracted_configs_response(state))

    def _handle_get_artifacts(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json(_responses.build_artifacts_response(state))

    def _handle_get_eml(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json_list(list(_responses.build_eml_analysis(state)))

    def _handle_get_mitre(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json(_responses.build_mitre_response(state))

    def _handle_get_static_scan(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_static(state)
        if guard is not None:
            return guard
        return _json(_responses.build_static_scan_response(state))

    def _handle_get_cdr_report(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_cdr(state)
        if guard is not None:
            return guard
        return _json(_responses.build_cdr_response(state))

    def _handle_get_signature_check(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_static(state)
        if guard is not None:
            return guard
        return _json(_responses.build_signature_check_response(state))

    def _handle_get_processes(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json(_responses.build_processes_response(state))

    def _handle_get_process_tree(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json(_responses.build_process_tree_response(state))

    def _handle_get_behaviours(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        try:
            query = self._query(request)
            os_value = self._first(query, "os")
            if not os_value:
                return _error(
                    400,
                    "Bad Request",
                    "Missing required query parameter: os",
                    "INVALID_QUERY_PARAM",
                    {"param": "os"},
                )
            if os_value not in {"windows", "linux", "android", "macos"}:
                return _error(
                    400,
                    "Bad Request",
                    f"Invalid os value: {os_value}",
                    "INVALID_QUERY_PARAM",
                    {"param": "os"},
                )
            page = self._int(query, "page")
            limit = self._int(query, "limit")
            pid = self._int(query, "pid")
        except _BadQueryParam as exc:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {exc.param}",
                "INVALID_QUERY_PARAM",
                {"param": exc.param},
            )
        if limit is not None and (limit < 1 or limit > 500):
            return _error(
                400,
                "Bad Request",
                "limit must be between 1 and 500",
                "INVALID_QUERY_PARAM",
                {"param": "limit"},
            )
        return _json(
            _responses.build_behaviours_response(
                state,
                os_name=os_value,  # type: ignore[arg-type]
                pid=pid,
                operation=self._first(query, "operation"),
                page=page,
                limit=limit,
            )
        )

    def _handle_get_syscalls(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        try:
            query = self._query(request)
            page = self._int(query, "page")
            limit = self._int(query, "limit")
        except _BadQueryParam as exc:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {exc.param}",
                "INVALID_QUERY_PARAM",
                {"param": exc.param},
            )
        if limit is not None and (limit < 1 or limit > 2000):
            return _error(
                400,
                "Bad Request",
                "limit must be between 1 and 2000",
                "INVALID_QUERY_PARAM",
                {"param": "limit"},
            )
        return _json(_responses.build_syscalls_response(state, page=page, limit=limit))

    def _handle_get_network_summary(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json(_responses.build_network_summary(state))

    def _handle_get_dns(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json_list(list(_responses.build_dns_queries(state)))

    def _handle_get_http(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json_list(list(_responses.build_http_requests(state)))

    def _handle_get_tcp(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json_list(list(_responses.build_tcp_connections(state)))

    def _handle_get_udp(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json_list(list(_responses.build_udp_connections(state)))

    def _handle_get_network_threats(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json_list(list(_responses.build_network_threats(state)))

    def _handle_download_pcap(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _binary(b"FAKE-PCAP-BYTES", "application/vnd.tcpdump.pcap")

    def _handle_download_sample(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        archive = _build_minimal_zip(state.filename, b"FAKE-SAMPLE")
        return _binary(archive, "application/zip")

    def _handle_download_artifact(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        artifact_id = match.params["artifact_id"]
        if artifact_id not in state.artifact_ids:
            return _error(
                404,
                "Not Found",
                "Artifact not found",
                "ARTIFACT_NOT_FOUND",
                {"submissionUuid": state.uuid, "artifactId": artifact_id},
            )
        return _binary(b"FAKE-ARTIFACT-BYTES", "application/octet-stream")

    def _handle_download_yara_rule(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        if not state.yara_rules:
            return httpx.Response(
                202,
                content=json.dumps(
                    {
                        "message": "YARA rule generation in progress",
                        "retryAfter": 5,
                    }
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
            )
        rule_text = "\n".join(f"rule {seed.rule} {{ }}" for seed in state.yara_rules)
        return _binary(rule_text.encode("utf-8"), "text/plain")

    def _handle_download_html(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        html = f"<html><body>Fake report for {state.uuid}</body></html>"
        return _binary(html.encode("utf-8"), "text/html")

    def _handle_download_cdr(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_cdr(state)
        if guard is not None:
            return guard
        return _binary(b"FAKE-SANITIZED-BYTES", "application/octet-stream")

    def _handle_get_url_analysis(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        return _json(_responses.build_url_analysis_response(state))

    def _handle_get_screenshot(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        return _binary(_MIN_PNG, "image/png")

    def _handle_list_media(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json_list(list(_responses.build_media_files(state)))

    def _handle_get_media_file(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        file_id = match.params["file_id"]
        if file_id not in state.media_ids:
            return _error(
                404,
                "Not Found",
                "Media not found",
                "MEDIA_NOT_FOUND",
                {"submissionUuid": state.uuid, "mediaId": file_id},
            )
        return _binary(_MIN_PNG, "image/png")


class _BadQueryParam(Exception):
    """Internal sentinel raised by query helpers to surface 400 responses."""

    def __init__(self, param: str) -> None:
        self.param = param
        super().__init__(param)
