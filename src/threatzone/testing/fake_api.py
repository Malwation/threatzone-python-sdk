"""In-process fake of the Threat.Zone Public API for SDK testing.

Builds an httpx ``MockTransport`` that the SDK clients can use through their
``http_client=`` constructor argument. Tests seed scenarios via
``register_sample`` / ``register_url_analysis`` and the fake hands back
Pydantic-validated JSON responses that exactly mirror the real API contract.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
import zlib
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import BaseModel

from threatzone.types import AiReportPending

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

_MEDIA_SOURCES: frozenset[str] = frozenset({"dynamic", "url_analysis"})

_NETWORK_ATTRIBUTIONS: frozenset[str] = frozenset(
    {"sample", "sample_child", "sensor_only", "windows_background"}
)
_NETWORK_LIST_MAX_LIMIT = 1000
_NETWORK_ENDPOINT_LIMIT = 300
_NETWORK_ENDPOINT_MAX_LIMIT = 500
_NETWORK_HOST_FLOW_LIMIT = 50
_NETWORK_HOST_FLOW_MAX_LIMIT = 200

_BEHAVIOUR_INDEX_KEYS: frozenset[str] = frozenset(
    {
        "pids",
        "parentPids",
        "types",
        "operations",
        "statuses",
        "processNameContains",
        "fromTimestamp",
        "toTimestamp",
        "syscallLineFrom",
        "syscallLineTo",
        "text",
        "sort",
    }
)

_CALLER_WORKSPACE = "test-workspace"
_CALLER_USER_ID = "64a000000000000000000001"
_ANNOTATION_PIN_KINDS: frozenset[str] = frozenset(
    {
        "finding",
        "finding-group",
        "process",
        "endpoint",
        "technique",
        "tactic",
        "events",
        "moment",
        "syscalls",
        "file",
        "indicator",
        "artifacts",
        "mail-attachment",
        "mail-link",
        "view",
        "preview",
        "family",
    }
)
_ANNOTATION_PIN_LIMIT = 200
_ANNOTATION_REF_MAX_LENGTH = 512
_ANNOTATION_LABEL_MAX_LENGTH = 200
_ANNOTATION_NOTE_MAX_LENGTH = 10000

_BEHAVIOUR_FACET_FIELDS: frozenset[str] = frozenset(
    {"operation", "type", "processName", "function", "subject"}
)


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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def _json_payload(payload: dict[str, Any], *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=json.dumps(payload).encode("utf-8"),
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
        safe_browsing: bool = False,
        device_preset_id: str | None = None,
        session_duration_seconds: int | None = None,
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
            safe_browsing=safe_browsing,
            session_device_preset_id=device_preset_id,
            session_device_preset_name=_responses.device_preset_name_for(device_preset_id),
            session_duration_seconds=session_duration_seconds,
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

    def mark_behaviour_index_missing(self, submission_uuid: str) -> None:
        """Answer the behaviour index routes with 409 ``BEHAVIOUR_INDEXING``."""
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        state.behaviour_index_ready = False

    def deny_download_report(self, submission_uuid: str) -> None:
        """Answer the raw behaviour, syscall and HTTPS capture downloads with 403, as a plan
        without the ``downloadReport`` permission does."""
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        state.download_report_allowed = False

    def deny_stix_report(self, submission_uuid: str) -> None:
        """Answer the ``stix`` and ``misp`` IoC exports with 403, as a plan without the
        ``stixReport`` permission does."""
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        state.stix_report_allowed = False

    def register_previous_run(
        self,
        submission_uuid: str,
        *,
        private: bool = False,
        owning_workspace: str | None = None,
        indicators: list[tuple[str, Literal["malicious", "suspicious", "benign"], list[int]]]
        | None = None,
        iocs: list[tuple[str, str]] | None = None,
        mitre_techniques: list[str] | None = None,
        dropped_files: list[tuple[str, str | None]] | None = None,
    ) -> str:
        """Seed an earlier run of the same sample and return its UUID.

        The earlier run has the same SHA256 and type, was created one hour before the
        given submission, and is completed. Fields left as ``None`` copy the values of the
        given submission.
        """
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        index = sum(1 for other in self._states.values() if other.sha256 == state.sha256)
        previous_uuid = _deterministic_uuid(f"previous::{state.uuid}::{index}")
        previous = SubmissionState(
            uuid=previous_uuid,
            sha256=state.sha256,
            type=state.type,
            filename=state.filename,
            level=state.level,
            polls_seen=state.advance_after_polls,
            advance_after_polls=state.advance_after_polls,
            private=private,
            owning_workspace=owning_workspace or state.owning_workspace,
            indicators=(
                [
                    IndicatorSeed(attack_code=ac, level=lvl, pids=list(p))
                    for ac, lvl, p in indicators
                ]
                if indicators is not None
                else list(state.indicators)
            ),
            iocs=(
                [IocSeed(type=t, value=v) for t, v in iocs]
                if iocs is not None
                else list(state.iocs)
            ),
            mitre_techniques=(
                list(mitre_techniques)
                if mitre_techniques is not None
                else list(state.mitre_techniques)
            ),
            dropped_files=(
                list(dropped_files) if dropped_files is not None else list(state.dropped_files)
            ),
            has_static_report=state.has_static_report,
            has_cdr_report=state.has_cdr_report,
            has_dynamic_report=state.has_dynamic_report,
            has_url_analysis_report=state.has_url_analysis_report,
            created_at=state.created_at - timedelta(hours=1),
            updated_at=state.created_at - timedelta(hours=1),
        )
        self._states[previous_uuid] = previous
        return previous_uuid

    def mark_https_pcap_missing(self, submission_uuid: str) -> None:
        """Answer the HTTPS inspection capture download with 404, as a report without the
        capture does."""
        state = self._states.get(submission_uuid)
        if state is None:
            raise KeyError(f"Unknown submission uuid: {submission_uuid}")
        state.https_pcap_available = False

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
            "get_device_presets": self._handle_device_presets,
            "list_network_configs": self._handle_list_network_configs,
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
            "get_artifact_jobs": self._handle_get_artifact_jobs,
            "get_eml_analysis": self._handle_get_eml,
            "get_mitre": self._handle_get_mitre,
            "get_static_scan": self._handle_get_static_scan,
            "get_static_scan_strings": self._handle_get_static_scan_strings,
            "get_static_scan_strings_items": self._handle_get_static_scan_strings_items,
            "get_static_scan_string_facts": self._handle_get_static_scan_string_facts,
            "get_cdr": self._handle_get_cdr_report,
            "get_signature_check": self._handle_get_signature_check,
            "get_processes": self._handle_get_processes,
            "get_process_tree": self._handle_get_process_tree,
            "get_killchain": self._handle_get_killchain,
            "get_behaviours": self._handle_get_behaviours,
            "get_syscalls": self._handle_get_syscalls,
            "get_behaviour_summary": self._handle_get_behaviour_summary,
            "get_behaviour_facets": self._handle_get_behaviour_facets,
            "search_syscalls": self._handle_search_syscalls,
            "download_behaviour": self._handle_download_behaviour,
            "download_syscalls": self._handle_download_syscalls,
            "get_network_summary": self._handle_get_network_summary,
            "get_network_dns": self._handle_get_dns,
            "get_network_http": self._handle_get_http,
            "get_network_tcp": self._handle_get_tcp,
            "get_network_udp": self._handle_get_udp,
            "get_network_threats": self._handle_get_network_threats,
            "get_network_exfil_requests": self._handle_get_network_exfil_requests,
            "get_http_request_packets": self._handle_get_http_request_packets,
            "get_tcp_connection_packets": self._handle_get_tcp_connection_packets,
            "get_udp_connection_packets": self._handle_get_udp_connection_packets,
            "get_network_endpoints": self._handle_get_network_endpoints,
            "get_network_host_flows": self._handle_get_network_host_flows,
            "get_ai_report": self._handle_get_ai_report,
            "regenerate_ai_report": self._handle_regenerate_ai_report,
            "get_verdict": self._handle_get_verdict,
            "get_run": self._handle_get_run,
            "get_annotations": self._handle_get_annotations,
            "pin_evidence": self._handle_pin_evidence,
            "unpin_evidence": self._handle_unpin_evidence,
            "set_note": self._handle_set_note,
            "get_previous_run": self._handle_get_previous_run,
            "compare_runs": self._handle_compare_runs,
            "download_iocs": self._handle_download_iocs,
            "download_pcap": self._handle_download_pcap,
            "download_https_pcap": self._handle_download_https_pcap,
            "download_sample": self._handle_download_sample,
            "download_artifact": self._handle_download_artifact,
            "download_yara_rule": self._handle_download_yara_rule,
            "download_html_report": self._handle_download_html,
            "download_stix_report": self._handle_download_stix,
            "get_pdf_report_status": self._handle_get_pdf_report_status,
            "download_pdf_report": self._handle_download_pdf,
            "download_cdr": self._handle_download_cdr,
            "get_url_analysis": self._handle_get_url_analysis,
            "get_url_analysis_session": self._handle_get_url_analysis_session,
            "get_url_analysis_indicators": self._handle_get_url_analysis_indicators,
            "get_url_analysis_indicator_evidence": (
                self._handle_get_url_analysis_indicator_evidence
            ),
            "get_url_analysis_browser_section": self._handle_get_url_analysis_browser_section,
            "start_url_analysis_session": self._handle_start_url_analysis_session,
            "restart_url_analysis_session": self._handle_restart_url_analysis_session,
            "restart_url_analysis": self._handle_restart_url_analysis,
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

    @staticmethod
    def _float(query: dict[str, list[str]], key: str) -> float | None:
        raw = FakeThreatZoneAPI._first(query, key)
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError as exc:
            raise _BadQueryParam(key) from exc

    @staticmethod
    def _text_list(query: dict[str, list[str]], key: str) -> list[str] | None:
        raw = FakeThreatZoneAPI._first(query, key)
        if raw is None:
            return None
        return [part.strip() for part in raw.split(",") if part.strip()]

    @staticmethod
    def _int_list(query: dict[str, list[str]], key: str) -> list[int] | None:
        parts = FakeThreatZoneAPI._text_list(query, key)
        if parts is None:
            return None
        if not all(part.isdigit() for part in parts):
            raise _BadQueryParam(key)
        return [int(part) for part in parts]

    def _behaviour_filter(self, query: dict[str, list[str]]) -> _responses.BehaviourFilter:
        return _responses.BehaviourFilter(
            event_type=self._first(query, "type"),
            pid=self._int(query, "pid"),
            operation=self._first(query, "operation"),
            process_name=self._first(query, "processName"),
            event_ids=self._int_list(query, "eventIds"),
            pids=self._int_list(query, "pids"),
            parent_pids=self._int_list(query, "parentPids"),
            types=self._text_list(query, "types"),
            operations=self._text_list(query, "operations"),
            statuses=self._text_list(query, "statuses"),
            process_name_contains=self._first(query, "processNameContains"),
            from_timestamp=self._float(query, "fromTimestamp"),
            to_timestamp=self._float(query, "toTimestamp"),
            syscall_line_from=self._int(query, "syscallLineFrom"),
            syscall_line_to=self._int(query, "syscallLineTo"),
            text=self._first(query, "text"),
            fields={
                key[len("field.") :]: values
                for key, values in query.items()
                if key.startswith("field.")
            },
        )

    @staticmethod
    def _behaviour_indexing_error() -> httpx.Response:
        return _error(
            409,
            "Conflict",
            "The behaviour index of this submission is not ready. Retry after 60 seconds.",
            "BEHAVIOUR_INDEXING",
            {"retryAfterSeconds": 60},
        )

    @staticmethod
    def _bad_query_param(param: str, message: str | None = None) -> httpx.Response:
        return _error(
            400,
            "Bad Request",
            message or f"Invalid query parameter: {param}",
            "INVALID_QUERY_PARAM",
            {"param": param},
        )

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

    def _require_url_submission(self, state: SubmissionState) -> httpx.Response | None:
        """Interactive sessions exist only on URL submissions, report or not."""
        if state.type != "url":
            return _error(
                409,
                "Conflict",
                "This submission is not a URL submission, so it has no interactive session.",
                "URL_ANALYSIS_REPORT_UNAVAILABLE",
                {
                    "submissionUuid": state.uuid,
                    "requiredReport": "url_analysis",
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

    def _handle_device_presets(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        del request, match
        return _json_list(list(_responses.build_device_presets()))

    def _handle_list_network_configs(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        del request, match
        return _json(_responses.build_network_configs())

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
        sha = match.params["sha256"]
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
        scope = self._first(query, "scope") or "workspace"
        if scope not in {"workspace", "public"}:
            return self._bad_query_param("scope", "scope must be workspace or public.")
        if sha in self._pending_seeds:
            self._activate_pending_seed(sha)
        results = sorted(
            (s for s in self._states.values() if s.sha256 == sha and _in_search_scope(s, scope)),
            key=lambda s: s.created_at,
            reverse=True,
        )
        start = (page - 1) * limit
        return _json_list(
            [_responses.build_submission_search_row(s) for s in results[start : start + limit]]
        )

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
        self._apply_url_options(state, payload)
        return _json(_responses.build_submission_created(state), status_code=200)

    @staticmethod
    def _apply_url_options(state: SubmissionState, payload: dict[str, Any]) -> None:
        """Record the create-time session options the SDK sent."""
        metafields = payload.get("metafields")
        if isinstance(metafields, dict):
            state.metafields = dict(metafields)
            preset_id = metafields.get("device_preset")
            if isinstance(preset_id, str):
                state.session_device_preset_id = preset_id
                state.session_device_preset_name = _responses.device_preset_name_for(preset_id)
            timeout = metafields.get("timeout")
            if isinstance(timeout, int):
                state.session_duration_seconds = timeout

        configurations = payload.get("configurations")
        if isinstance(configurations, dict):
            network_config = configurations.get("networkConfig")
            if isinstance(network_config, str):
                state.session_network_config_id = network_config
            duration = configurations.get("sessionDurationSeconds")
            if isinstance(duration, int):
                state.session_duration_seconds = duration

        state.safe_browsing = payload.get("safeBrowsing") is True

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

    def _handle_get_artifacts(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        source = self._first(self._query(request), "source")
        if source is not None and source not in _responses.ARTIFACT_SOURCES:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: source={source}",
                "INVALID_QUERY_PARAM",
                {"param": "source"},
            )
        return _json(_responses.build_artifacts_response(state, source=source))

    def _handle_get_artifact_jobs(
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
                "Artifact not found for the given submission.",
                "ARTIFACT_NOT_FOUND",
                {"submissionUuid": state.uuid, "artifactId": artifact_id},
            )
        jobs = _responses.build_artifact_jobs(artifact_id)
        return _json_payload(
            {"items": [job.model_dump(mode="json", by_alias=True) for job in jobs]}
        )

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

    def _handle_get_static_scan_strings(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_static(state)
        if guard is not None:
            return guard
        payload = _responses.build_static_scan_strings(state)
        return _binary(json.dumps(payload).encode("utf-8"), "application/json")

    def _handle_get_static_scan_strings_items(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_static(state)
        if guard is not None:
            return guard
        try:
            query = self._query(request)
            start = self._int(query, "start")
            end = self._int(query, "end")
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        if start is not None and start < 0:
            return self._bad_query_param("start", "start must not be less than 0")
        if end is not None and end < 0:
            return self._bad_query_param("end", "end must not be less than 0")
        window_start = start if start is not None else 0
        if end is not None and end - window_start > _responses.STRINGS_WINDOW_MAX_SPAN:
            return self._bad_query_param(
                "end", f"end - start must not exceed {_responses.STRINGS_WINDOW_MAX_SPAN}"
            )
        search = self._first(query, "search")
        if search is not None and len(search) > _responses.STRINGS_SEARCH_MAX_LENGTH:
            return self._bad_query_param(
                "search",
                f"search must be {_responses.STRINGS_SEARCH_MAX_LENGTH} characters or less",
            )
        return _json(
            _responses.build_static_scan_strings_page(state, start=start, end=end, search=search)
        )

    def _handle_get_static_scan_string_facts(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_static(state)
        if guard is not None:
            return guard
        return _json(_responses.build_static_scan_string_facts(state))

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

    def _handle_get_killchain(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json(_responses.build_killchain_response(state))

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
            page = self._int(query, "page")
            limit = self._int(query, "limit")
            behaviour_filter = self._behaviour_filter(query)
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        if limit is not None and (limit < 1 or limit > 500):
            return self._bad_query_param("limit", "limit must be between 1 and 500")
        uses_index = any(key in query for key in _BEHAVIOUR_INDEX_KEYS) or bool(
            behaviour_filter.fields
        )
        if uses_index and not state.behaviour_index_ready:
            return self._behaviour_indexing_error()
        return _json(
            _responses.build_behaviours_response(
                state,
                behaviour_filter=behaviour_filter,
                uses_index=uses_index,
                sort=self._first(query, "sort"),
                page=page,
                limit=limit,
            )
        )

    def _handle_get_behaviour_summary(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        if not state.behaviour_index_ready:
            return self._behaviour_indexing_error()
        return _json(_responses.build_behaviour_summary(state))

    def _handle_get_behaviour_facets(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        try:
            query = self._query(request)
            first = self._int(query, "first")
            behaviour_filter = self._behaviour_filter(query)
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        facet_field = self._first(query, "field")
        if facet_field not in _BEHAVIOUR_FACET_FIELDS:
            return self._bad_query_param("field")
        if "text" in query:
            return self._bad_query_param("text", "text is not allowed on this route")
        if first is not None and (first < 1 or first > 2000):
            return self._bad_query_param("first", "first must be between 1 and 2000")
        if not state.behaviour_index_ready:
            return self._behaviour_indexing_error()
        return _json(
            _responses.build_behaviour_facets(
                state,
                facet_field=facet_field,
                behaviour_filter=behaviour_filter,
                contains=self._first(query, "contains"),
                first=first,
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

    def _handle_search_syscalls(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        try:
            query = self._query(request)
            pids = self._int_list(query, "pids")
            after_line = self._int(query, "afterLine")
            limit = self._int(query, "limit")
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        text = (self._first(query, "query") or "").strip()
        if not 3 <= len(text) <= 200:
            return self._bad_query_param("query", "query must be 3 to 200 characters")
        failed_only = self._first(query, "failedOnly")
        if failed_only not in (None, "true", "false"):
            return self._bad_query_param("failedOnly", "failedOnly must be true or false")
        if after_line is not None and after_line < 0:
            return self._bad_query_param("afterLine", "afterLine must not be below 0")
        if limit is not None and (limit < 1 or limit > 500):
            return self._bad_query_param("limit", "limit must be between 1 and 500")
        return _json(
            _responses.build_syscall_search_result(
                state,
                query=text,
                pids=pids,
                failed_only=failed_only == "true",
                apis=self._text_list(query, "apis"),
                after_line=after_line or 0,
                limit=limit if limit is not None else 200,
            )
        )

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

    def _handle_get_dns(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return self._network_page(request, list(_responses.build_dns_queries(state)))

    def _handle_get_http(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return self._network_page(request, list(_responses.build_http_requests(state)))

    def _handle_get_tcp(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return self._network_page(request, list(_responses.build_tcp_connections(state)))

    def _handle_get_udp(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return self._network_page(request, list(_responses.build_udp_connections(state)))

    def _handle_get_network_threats(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return self._network_page(request, list(_responses.build_network_threats(state)))

    def _handle_get_network_exfil_requests(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return self._network_page(
            request,
            list(_responses.build_network_exfil_requests(state, limit=None, skip=None)),
        )

    def _network_page(self, request: httpx.Request, rows: list[BaseModel]) -> httpx.Response:
        try:
            query = self._query(request)
            limit = self._int(query, "limit")
            skip = self._int(query, "skip")
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        if limit is not None and not 1 <= limit <= _NETWORK_LIST_MAX_LIMIT:
            return self._bad_query_param("limit")
        if skip is not None and skip < 0:
            return self._bad_query_param("skip")
        start = skip or 0
        response = _json_list(rows[start : start + (limit or _NETWORK_LIST_MAX_LIMIT)])
        response.headers["X-Total-Count"] = str(len(rows))
        return response

    def _require_dynamic_state(
        self, match: RouteMatch
    ) -> tuple[SubmissionState | None, httpx.Response | None]:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            return None, err
        guard = self._require_dynamic(state)
        if guard is not None:
            return None, guard
        return state, None

    @staticmethod
    def _network_row_not_found(row_id: str) -> httpx.Response:
        return _error(
            404,
            "Not Found",
            "No network row with this ID exists on this submission",
            "NETWORK_ROW_NOT_FOUND",
            {"rowId": row_id},
        )

    def _handle_get_http_request_packets(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_dynamic_state(match)
        if state is None:
            assert err is not None
            return err
        packets = _responses.build_http_request_packets(state, match.params["row_id"])
        if packets is None:
            return self._network_row_not_found(match.params["row_id"])
        return _json(packets)

    def _connection_packets(self, match: RouteMatch, protocol: str) -> httpx.Response:
        state, err = self._require_dynamic_state(match)
        if state is None:
            assert err is not None
            return err
        packets = _responses.build_connection_packets(state, protocol, match.params["row_id"])
        if packets is None:
            return self._network_row_not_found(match.params["row_id"])
        return _json(packets)

    def _handle_get_tcp_connection_packets(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        return self._connection_packets(match, "tcp")

    def _handle_get_udp_connection_packets(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        return self._connection_packets(match, "udp")

    def _network_attribution_error(self, query: dict[str, list[str]]) -> httpx.Response | None:
        attribution = self._text_list(query, "attribution")
        if attribution is not None and not set(attribution) <= _NETWORK_ATTRIBUTIONS:
            return self._bad_query_param("attribution")
        return None

    def _handle_get_network_endpoints(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_dynamic_state(match)
        if state is None:
            assert err is not None
            return err
        query = self._query(request)
        try:
            limit = self._int(query, "limit")
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        if limit is not None and not 1 <= limit <= _NETWORK_ENDPOINT_MAX_LIMIT:
            return self._bad_query_param("limit")
        attribution_error = self._network_attribution_error(query)
        if attribution_error is not None:
            return attribution_error
        return _json(
            _responses.build_network_endpoints(state, limit=limit or _NETWORK_ENDPOINT_LIMIT)
        )

    def _handle_get_network_host_flows(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_dynamic_state(match)
        if state is None:
            assert err is not None
            return err
        query = self._query(request)
        try:
            first = self._int(query, "first")
        except _BadQueryParam as exc:
            return self._bad_query_param(exc.param)
        if first is not None and not 1 <= first <= _NETWORK_HOST_FLOW_MAX_LIMIT:
            return self._bad_query_param("first")
        after = self._first(query, "after")
        offset = 0 if after is None else _responses.decode_host_flow_cursor(after)
        if offset is None:
            return self._bad_query_param(
                "after", "after must be the pageInfo.endCursor of a previous page"
            )
        attribution_error = self._network_attribution_error(query)
        if attribution_error is not None:
            return attribution_error
        return _json(
            _responses.build_network_host_flows(
                state,
                match.params["host"],
                first=first or _NETWORK_HOST_FLOW_LIMIT,
                offset=offset,
            )
        )

    def _handle_get_ai_report(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        report = _responses.build_ai_report(state)
        if isinstance(report, AiReportPending):
            return _json(report, status_code=202)
        return _json(report)

    def _handle_regenerate_ai_report(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        if state.current_status() != "completed":
            return _error(
                409,
                "Conflict",
                "The analysis score is not final. Try again after the analysis finishes.",
                "AI_REPORT_NOT_FINALIZED",
                {"submissionUuid": state.uuid},
            )
        state.ai_report_queued = True
        state.ai_report_reason = "regenerate"
        return _json(_responses.build_ai_report_regenerate_result(), status_code=202)

    def _require_visible_state(
        self, uuid_param: str
    ) -> tuple[SubmissionState | None, httpx.Response | None]:
        """Resolve a submission the way the newer routes do: a private submission of another
        workspace returns the same 404 as a missing one."""
        state = self._states.get(uuid_param)
        if state is None or (state.private and state.owning_workspace != _CALLER_WORKSPACE):
            return None, _error(404, "Not Found", "Submission not found", "NOT_FOUND")
        return state, None

    def _handle_get_verdict(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json(_responses.build_verdict(state))

    def _handle_get_run(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _json(_responses.build_run_notes(state))

    def _handle_get_annotations(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        return _json(_responses.build_annotations(state))

    @staticmethod
    def _json_body(request: httpx.Request) -> dict[str, Any] | None:
        try:
            body = json.loads(request.content.decode("utf-8") or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return body if isinstance(body, dict) else None

    @staticmethod
    def _invalid_body(message: str) -> httpx.Response:
        return _error(400, "Bad Request", message, "INVALID_QUERY_PARAM")

    def _handle_pin_evidence(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        body = self._json_body(request)
        if body is None or set(body) - {"kind", "ref", "label"}:
            return self._invalid_body("The body must have only kind, ref and label.")
        kind, ref, label = body.get("kind"), body.get("ref"), body.get("label")
        if not isinstance(kind, str) or kind not in _ANNOTATION_PIN_KINDS:
            return self._invalid_body("kind must be a known pin kind.")
        if not isinstance(ref, str) or not 1 <= len(ref) <= _ANNOTATION_REF_MAX_LENGTH:
            return self._invalid_body("ref must have 1 to 512 characters.")
        if not isinstance(label, str):
            return self._invalid_body("label must be a string.")
        label = label.strip()
        if not 1 <= len(label) <= _ANNOTATION_LABEL_MAX_LENGTH:
            return self._invalid_body("label must have 1 to 200 characters.")
        if any(pin["kind"] == kind and pin["ref"] == ref for pin in state.annotation_pins):
            return _json(_responses.build_annotations(state))
        if len(state.annotation_pins) >= _ANNOTATION_PIN_LIMIT:
            return _error(
                400,
                "Bad Request",
                "The workspace has the maximum number of pins on this submission.",
                "ANNOTATION_PIN_LIMIT_REACHED",
                {"limit": _ANNOTATION_PIN_LIMIT},
            )
        state.annotation_pins.append(
            {
                "id": str(uuid.uuid4()),
                "kind": kind,
                "ref": ref,
                "label": label,
                "createdBy": _CALLER_USER_ID,
                "createdAt": _now_iso(),
            }
        )
        return _json(_responses.build_annotations(state))

    def _handle_unpin_evidence(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        pin_id = match.params["pin_id"]
        try:
            uuid.UUID(pin_id)
        except ValueError:
            return self._bad_query_param("pinId", "pinId must be a UUID.")
        remaining = [pin for pin in state.annotation_pins if pin["id"] != pin_id]
        if len(remaining) == len(state.annotation_pins):
            return _error(
                404,
                "Not Found",
                "The workspace has no pin with this ID on this submission.",
                "ANNOTATION_PIN_NOT_FOUND",
            )
        state.annotation_pins = remaining
        return _json(_responses.build_annotations(state))

    def _handle_set_note(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        body = self._json_body(request)
        if body is None or set(body) != {"text"}:
            return self._invalid_body("The body must have only text.")
        text = body["text"]
        if not isinstance(text, str) or len(text) > _ANNOTATION_NOTE_MAX_LENGTH:
            return self._invalid_body("text must be a string of 10000 characters or fewer.")
        if not text.strip():
            state.annotation_note = None
        else:
            state.annotation_note = {
                "text": text,
                "updatedBy": _CALLER_USER_ID,
                "updatedAt": _now_iso(),
            }
        return _json(_responses.build_annotations(state))

    def _handle_get_previous_run(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        candidates = [
            other
            for other in self._states.values()
            if other.uuid != state.uuid
            and other.sha256 == state.sha256
            and other.type == state.type
            and other.created_at < state.created_at
            and other.owning_workspace == state.owning_workspace
            and (state.owning_workspace == _CALLER_WORKSPACE or not other.private)
        ]
        latest = max(candidates, key=lambda other: other.created_at, default=None)
        return _json(_responses.build_previous_run(latest.uuid if latest else None))

    def _handle_compare_runs(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        other, other_err = self._require_visible_state(match.params["other_uuid"])
        if other_err is not None or other is None:
            assert other_err is not None
            return other_err
        return _json(_responses.build_run_comparison(state, other))

    def _handle_download_iocs(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_visible_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        export_format = self._first(self._query(request), "format")
        if export_format not in _responses.IOC_EXPORT_FORMATS:
            return self._bad_query_param("format", "format must be csv, text, stix or misp.")
        if export_format in {"stix", "misp"} and not state.stix_report_allowed:
            return _error(
                403,
                "Forbidden",
                "The workspace plan does not have the stixReport permission.",
                "FORBIDDEN",
            )
        export = _responses.build_ioc_export(state, export_format)
        return httpx.Response(
            200,
            content=export.content,
            headers={
                "content-type": export.content_type,
                "content-disposition": f'attachment; filename="{export.filename}"',
            },
        )

    def _handle_download_pcap(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        return _binary(b"FAKE-PCAP-BYTES", "application/vnd.tcpdump.pcap")

    def _handle_download_https_pcap(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_download_report(state)
        if guard is not None:
            return guard
        if not state.https_pcap_available:
            return _error(
                404,
                "Not Found",
                "The latest analysis attempt has no HTTPS inspection capture.",
                "NOT_FOUND",
            )
        return _binary(b"FAKE-HTTPS-PCAP-BYTES", "application/vnd.tcpdump.pcap")

    def _require_download_report(self, state: SubmissionState) -> httpx.Response | None:
        guard = self._require_dynamic(state)
        if guard is not None:
            return guard
        if not state.download_report_allowed:
            return _error(
                403,
                "Forbidden",
                "The workspace plan does not have the downloadReport permission.",
                "FORBIDDEN",
            )
        return None

    def _handle_download_behaviour(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_download_report(state)
        if guard is not None:
            return guard
        return _binary(_responses.build_raw_behaviour_file(state), "application/json")

    def _handle_download_syscalls(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_download_report(state)
        if guard is not None:
            return guard
        return _binary(_responses.build_raw_syscall_log(state), "text/plain; charset=utf-8")

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

    def _handle_download_stix(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        bundle = {"type": "bundle", "id": f"bundle--{state.uuid}", "objects": []}
        return _binary(json.dumps(bundle).encode("utf-8"), "application/json")

    def _handle_get_pdf_report_status(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        status = _responses.build_pdf_report_status(state)
        if state.current_status() == "completed":
            state.pdf_report_ready = True
        return _json(status)

    def _handle_download_pdf(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        if state.current_status() != "completed":
            return _error(
                409,
                "Conflict",
                "Please wait for the analysis to finish before generating the PDF report.",
                "CONFLICT",
            )
        if not state.pdf_report_ready:
            state.pdf_report_ready = True
            return httpx.Response(
                202,
                content=json.dumps(
                    {
                        "status": "accepted",
                        "message": "PDF report generation is in progress.",
                        "retryAfter": 3,
                    }
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
            )
        return _binary(b"%PDF-1.4 FAKE-PDF-REPORT", "application/pdf")

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

    def _handle_get_url_analysis_session(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_submission(state)
        if guard is not None:
            return guard
        return _json(_responses.build_url_analysis_session(state))

    def _handle_get_url_analysis_indicators(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        return _json(_responses.build_url_analysis_indicators(state))

    def _handle_get_url_analysis_indicator_evidence(
        self, request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        indicator_id = match.params["indicator_id"]
        reference_id = match.params["reference_id"]
        query = self._query(request)
        job_id = self._first(query, "jobId")
        scored_at = self._first(query, "scoredAt")
        invalid_param = _invalid_url_evidence_param(indicator_id, reference_id, job_id, scored_at)
        if invalid_param is not None:
            return _error(
                400,
                "Bad Request",
                f"Invalid query parameter: {invalid_param}",
                "INVALID_QUERY_PARAM",
                {"param": invalid_param},
            )
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        snapshot = _responses.build_url_analysis_indicators(state).snapshot
        ref_available = (
            _responses.url_score_evidence_ref_available(state, indicator_id, reference_id)
            if snapshot is not None
            else None
        )
        if snapshot is None or ref_available is None:
            return _error(
                404,
                "Not Found",
                "The indicator or the evidence reference does not exist in the current score "
                "explanation of this submission.",
                "URL_SCORE_EVIDENCE_NOT_FOUND",
            )
        if not ref_available or (job_id, scored_at) != (snapshot.job_id, snapshot.scored_at):
            return _json_payload({"state": "unavailable", "text": None, "truncated": False})
        return _json(
            _responses.build_url_analysis_indicator_evidence(state, indicator_id, reference_id)
        )

    def _handle_get_url_analysis_browser_section(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        section = match.params["section"]
        if section not in _responses.URL_BROWSER_PUBLIC_SECTIONS:
            return _error(
                404,
                "Not Found",
                "Unknown browser section. Use one of: "
                + ", ".join(_responses.URL_BROWSER_PUBLIC_SECTIONS)
                + ".",
                "URL_BROWSER_SECTION_NOT_FOUND",
            )
        if state.current_status() != "completed":
            return _error(
                404,
                "Not Found",
                "The browser section is not available for the current run.",
                "URL_BROWSER_SECTION_UNAVAILABLE",
                {"submissionUuid": state.uuid, "section": section},
            )
        return _json(_responses.build_url_analysis_browser_section(state, section))

    def _handle_start_url_analysis_session(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_submission(state)
        if guard is not None:
            return guard
        state.session_started = True
        return _json(_responses.build_message("Interactive browser session start initiated"))

    def _handle_restart_url_analysis_session(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_submission(state)
        if guard is not None:
            return guard
        state.session_started = True
        state.session_restarts += 1
        return _json(_responses.build_message("Interactive browser session restart initiated"))

    def _handle_restart_url_analysis(
        self, _request: httpx.Request, match: RouteMatch
    ) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        state.report_restarts += 1
        state.polls_seen = 0
        return _json(_responses.build_message("URL report restart initiated successfully"))

    def _handle_get_screenshot(self, _request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        guard = self._require_url_analysis(state)
        if guard is not None:
            return guard
        return _binary(_MIN_PNG, "image/png")

    def _handle_list_media(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        source, source_err = self._resolve_media_source(request, state)
        if source_err is not None:
            return source_err
        del source
        return _json_list(list(_responses.build_media_files(state)))

    def _resolve_media_source(
        self, request: httpx.Request, state: SubmissionState
    ) -> tuple[str | None, httpx.Response | None]:
        """Validate the `source` query param against the submission's reports."""
        requested = self._first(self._query(request), "source")
        if requested is not None and requested not in _MEDIA_SOURCES:
            return None, _error(
                400,
                "Bad Request",
                "source is neither dynamic nor url_analysis",
                "INVALID_QUERY_PARAM",
                {"param": "source"},
            )

        if state.has_dynamic_report:
            available = "dynamic"
        elif state.has_url_analysis_report:
            available = "url_analysis"
        else:
            return None, _error(
                409,
                "Conflict",
                "The submission has no media-bearing report",
                "MEDIA_NOT_FOUND",
                {"submissionUuid": state.uuid},
            )

        if requested is not None and requested != available:
            return None, _error(
                409,
                "Conflict",
                f"The submission has no {requested} media",
                "MEDIA_NOT_FOUND",
                {"submissionUuid": state.uuid, "source": requested},
            )
        return available, None

    def _handle_get_media_file(self, request: httpx.Request, match: RouteMatch) -> httpx.Response:
        state, err = self._require_state(match.params["uuid"])
        if err is not None or state is None:
            assert err is not None
            return err
        source, source_err = self._resolve_media_source(request, state)
        if source_err is not None:
            return source_err
        del source
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


_URL_EVIDENCE_ID_MAX_LENGTH = 256
_URL_SCORED_AT_MAX_LENGTH = 40
_MONGO_ID = re.compile(r"^[0-9a-fA-F]{24}$")
_ISO_8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$")


def _in_search_scope(state: SubmissionState, scope: str) -> bool:
    if scope == "public":
        return not state.private
    return state.type == "file" and (
        state.owning_workspace == _CALLER_WORKSPACE or not state.private
    )


def _invalid_url_evidence_param(
    indicator_id: str, reference_id: str, job_id: str | None, scored_at: str | None
) -> str | None:
    """Return the first parameter that the evidence route rejects, or None."""
    if not indicator_id or len(indicator_id) > _URL_EVIDENCE_ID_MAX_LENGTH:
        return "indicatorId"
    if not reference_id or len(reference_id) > _URL_EVIDENCE_ID_MAX_LENGTH:
        return "referenceId"
    if job_id is None or not _MONGO_ID.match(job_id):
        return "jobId"
    if (
        scored_at is None
        or len(scored_at) > _URL_SCORED_AT_MAX_LENGTH
        or not _ISO_8601.match(scored_at)
    ):
        return "scoredAt"
    return None


class _BadQueryParam(Exception):
    """Internal sentinel raised by query helpers to surface 400 responses."""

    def __init__(self, param: str) -> None:
        self.param = param
        super().__init__(param)
