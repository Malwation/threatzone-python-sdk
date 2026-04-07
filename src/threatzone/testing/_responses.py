"""Response builders for the in-process fake Threat.Zone API.

Each builder constructs a Pydantic model instance from a ``SubmissionState``
via ``model_validate`` with camelCase alias dicts, and returns it.
``fake_api.py`` then serialises the instance via
``model_dump(mode='json', by_alias=True)`` so the wire contract automatically
tracks the SDK types.

Rationale: using ``model_validate`` with alias dicts sidesteps the missing
pydantic mypy plugin — strict mypy only sees ``Dict[str, Any]`` → ``Model``,
and pydantic enforces the contract at runtime.
"""

from __future__ import annotations

from typing import Any

from threatzone.types import (
    ArtifactsResponse,
    BehavioursResponse,
    CdrResponse,
    Connection,
    DnsQuery,
    EmlAnalysis,
    EnvironmentOption,
    ExtractedConfigsResponse,
    HttpRequest,
    IndicatorsResponse,
    IoCsResponse,
    MediaFile,
    MetafieldOption,
    Metafields,
    MitreResponse,
    NetworkSummary,
    NetworkThreat,
    PaginatedSubmissions,
    ProcessesResponse,
    ProcessTreeResponse,
    SignatureCheckResponse,
    StaticScanResponse,
    Submission,
    SubmissionCreated,
    SubmissionListItem,
    SyscallsResponse,
    UrlAnalysisResponse,
    UserInfo,
    YaraRulesResponse,
)
from threatzone.types.behaviours import BehaviourOs
from threatzone.types.indicators import OverviewSummary
from threatzone.types.network import ThreatAppProto, ThreatSeverity

from .state import IndicatorSeed, NetworkThreatSeed, SubmissionState


def _hashes_for(state: SubmissionState) -> dict[str, str]:
    return {
        "md5": "0" * 32,
        "sha1": "0" * 40,
        "sha256": state.sha256,
    }


def _file_info_for(state: SubmissionState) -> dict[str, Any]:
    return {
        "name": state.filename,
        "size": 1024,
        "extension": state.filename.rsplit(".", 1)[-1] if "." in state.filename else "bin",
        "mimetype": "application/octet-stream",
        "isMimetypeChecked": True,
        "entrypoint": None,
        "source": {"type": "upload", "url": None},
    }


def _report_statuses(state: SubmissionState) -> list[dict[str, Any]]:
    statuses: list[dict[str, Any]] = []
    for report_type in state.report_types():
        raw_status = state.report_status_for(report_type)
        level: str | None = state.level if raw_status == "completed" else None
        statuses.append(
            {
                "type": report_type,
                "status": raw_status,
                "level": level,
                "score": None,
                "format": None,
                "operatingSystem": None,
            }
        )
    return statuses


def _indicator_level_counts(indicators: list[IndicatorSeed]) -> dict[str, int]:
    counts: dict[str, int] = {"malicious": 0, "suspicious": 0, "benign": 0}
    for ind in indicators:
        counts[ind.level] += 1
    return counts


def _indicator_rollup(state: SubmissionState) -> dict[str, Any]:
    return {
        "levels": _indicator_level_counts(state.indicators),
        "artifactCount": len(state.artifact_ids),
    }


def _submission_overview(state: SubmissionState) -> dict[str, Any]:
    status = state.current_status()
    report_types = state.report_types()
    completed = len(report_types) if status == "completed" else 0
    total = max(len(report_types), 1)
    return {
        "status": status,
        "jobs": {"completed": completed, "total": total},
    }


def _submission_payload(state: SubmissionState) -> dict[str, Any]:
    return {
        "uuid": state.uuid,
        "type": state.type,
        "filename": state.filename if state.type == "file" else None,
        "url": state.url if state.type == "url" else None,
        "hashes": _hashes_for(state) if state.type == "file" else None,
        "file": _file_info_for(state) if state.type == "file" else None,
        "level": state.level,
        "private": state.private,
        "tags": [{"type": "family", "value": "test"}],
        "reports": _report_statuses(state),
        "overview": _submission_overview(state),
        "indicators": _indicator_rollup(state),
        "mitreTechniques": list(state.mitre_techniques),
        "createdAt": state.created_at.isoformat(),
        "updatedAt": state.updated_at.isoformat(),
    }


def build_submission(state: SubmissionState) -> Submission:
    """Build the full ``Submission`` detail response for a state."""
    return Submission.model_validate(_submission_payload(state))


def _submission_list_item_payload(state: SubmissionState) -> dict[str, Any]:
    return {
        "uuid": state.uuid,
        "filename": state.filename if state.type == "file" else None,
        "sha256": state.sha256 if state.type == "file" else None,
        "level": state.level,
        "type": state.type,
        "private": state.private,
        "tags": [{"type": "family", "value": "test"}],
        "reports": _report_statuses(state),
        "mimetype": "application/octet-stream" if state.type == "file" else None,
        "size": 1024 if state.type == "file" else None,
        "overview": _submission_overview(state),
        "indicators": _indicator_rollup(state),
        "createdAt": state.created_at.isoformat(),
    }


def build_submission_list_item(state: SubmissionState) -> SubmissionListItem:
    """Build a ``SubmissionListItem`` for the paginated list endpoint."""
    return SubmissionListItem.model_validate(_submission_list_item_payload(state))


def build_paginated_submissions(
    items: list[SubmissionState],
    *,
    page: int,
    limit: int,
) -> PaginatedSubmissions:
    """Build a ``PaginatedSubmissions`` envelope from a list of states."""
    total = len(items)
    start = (page - 1) * limit
    end = start + limit
    sliced = items[start:end]
    total_pages = (total + limit - 1) // limit if limit > 0 else 0
    payload: dict[str, Any] = {
        "items": [_submission_list_item_payload(s) for s in sliced],
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": total_pages,
    }
    return PaginatedSubmissions.model_validate(payload)


def build_submission_created(state: SubmissionState) -> SubmissionCreated:
    """Build the ``SubmissionCreated`` POST response for a state."""
    return SubmissionCreated.model_validate(
        {
            "uuid": state.uuid,
            "message": "Submission created",
            "sha256": state.sha256 if state.type == "file" else None,
        }
    )


def build_overview_summary(state: SubmissionState) -> OverviewSummary:
    """Build the ``OverviewSummary`` aggregate counts response."""
    network: dict[str, int] | None = None
    if state.has_dynamic_report:
        network = {
            "dnsCount": 2,
            "httpCount": 1,
            "tcpCount": 3,
            "udpCount": 1,
            "threatCount": len(state.network_threats),
        }
    payload: dict[str, Any] = {
        "indicators": {
            "total": len(state.indicators),
            "levels": _indicator_level_counts(state.indicators),
        },
        "behaviorEventCount": len(state.indicators) * 4,
        "syscallCount": len(state.indicators) * 8,
        "iocCount": len(state.iocs),
        "yaraRuleCount": len(state.yara_rules),
        "configCount": 0,
        "artifactCount": len(state.artifact_ids),
        "mitreTechniqueCount": len(state.mitre_techniques),
        "network": network,
    }
    return OverviewSummary.model_validate(payload)


def build_indicators_response(
    state: SubmissionState,
    *,
    level: str | None,
    category: str | None,
    pid: int | None,
    attack_code: str | None,
    page: int | None,
    limit: int | None,
) -> IndicatorsResponse:
    """Build the paginated indicators response, applying query filters."""
    items: list[dict[str, Any]] = []
    for idx, seed in enumerate(state.indicators):
        if level and seed.level != level:
            continue
        if attack_code and seed.attack_code != attack_code:
            continue
        if pid is not None and pid not in seed.pids:
            continue
        if category and category != "default":
            continue
        items.append(
            {
                "id": f"ind-{idx}",
                "name": f"Indicator {seed.attack_code}",
                "description": f"Triggered MITRE technique {seed.attack_code}",
                "category": "default",
                "level": seed.level,
                "score": 80 if seed.level == "malicious" else 50,
                "pids": list(seed.pids),
                "attackCodes": [seed.attack_code],
                "eventIds": [100 + idx],
                "syscallLineNumbers": [200 + idx],
                "author": "system",
            }
        )
    total = len(items)
    if page is not None and limit is not None:
        start = (page - 1) * limit
        items = items[start : start + limit]
    counts = _indicator_level_counts(state.indicators)
    return IndicatorsResponse.model_validate({"items": items, "total": total, "levels": counts})


def build_iocs_response(
    state: SubmissionState,
    *,
    type_filter: str | None,
    page: int | None,
    limit: int | None,
) -> IoCsResponse:
    """Build the paginated IoC list response."""
    items: list[dict[str, Any]] = []
    for seed in state.iocs:
        if type_filter and seed.type != type_filter:
            continue
        items.append(
            {
                "type": seed.type,
                "value": seed.value,
                "artifacts": [state.artifact_ids[0]] if state.artifact_ids else [],
            }
        )
    total = len(items)
    if page is not None and limit is not None:
        start = (page - 1) * limit
        items = items[start : start + limit]
    return IoCsResponse.model_validate({"items": items, "total": total})


def build_yara_rules_response(
    state: SubmissionState,
    *,
    category: str | None,
    page: int | None,
    limit: int | None,
) -> YaraRulesResponse:
    """Build the paginated YARA rules response."""
    items: list[dict[str, Any]] = []
    for seed in state.yara_rules:
        if category and seed.category != category:
            continue
        items.append(
            {
                "rule": seed.rule,
                "category": seed.category,
                "artifacts": [state.artifact_ids[0]] if state.artifact_ids else [],
            }
        )
    total = len(items)
    if page is not None and limit is not None:
        start = (page - 1) * limit
        items = items[start : start + limit]
    return YaraRulesResponse.model_validate({"items": items, "total": total})


def build_extracted_configs_response(state: SubmissionState) -> ExtractedConfigsResponse:
    """Build the extracted configurations response."""
    items: list[dict[str, Any]] = []
    if state.level == "malicious":
        items.append(
            {
                "family": "TestFamily",
                "config": {"campaign": "fake", "version": "1.0"},
                "c2s": ["malware-c2.example.com"],
                "artifacts": [state.artifact_ids[0]] if state.artifact_ids else [],
            }
        )
    return ExtractedConfigsResponse.model_validate({"items": items, "total": len(items)})


def build_artifacts_response(state: SubmissionState) -> ArtifactsResponse:
    """Build the artifacts response."""
    items: list[dict[str, Any]] = []
    for idx, artifact_id in enumerate(state.artifact_ids):
        items.append(
            {
                "id": artifact_id,
                "filename": f"artifact-{idx}.bin",
                "size": 2048,
                "type": "dropped_file",
                "source": "dynamic_analysis",
                "hashes": {
                    "md5": "1" * 32,
                    "sha1": "1" * 40,
                    "sha256": f"{idx:064x}",
                },
                "tags": ["test"],
            }
        )
    return ArtifactsResponse.model_validate({"items": items, "total": len(items)})


def build_eml_analysis(state: SubmissionState) -> list[EmlAnalysis]:
    """Build the EML analysis response (empty by default)."""
    if not state.extra.get("eml"):
        return []
    payload: dict[str, Any] = {
        "headers": {
            "message_id": "<test@example.com>",
            "subject": "Test phishing",
            "date": "2024-01-01T00:00:00Z",
            "from_email": "attacker@example.com",
            "to_emails": ["victim@example.com"],
            "cc_emails": [],
            "bcc_emails": [],
        },
        "other_headers": {},
        "attachments": [],
        "qr_results": [],
        "artifact": state.artifact_ids[0] if state.artifact_ids else "artifact-0",
    }
    return [EmlAnalysis.model_validate(payload)]


def build_mitre_response(state: SubmissionState) -> MitreResponse:
    """Build the MITRE techniques response."""
    return MitreResponse.model_validate(
        {"techniques": list(state.mitre_techniques), "total": len(state.mitre_techniques)}
    )


def build_static_scan_response(state: SubmissionState) -> StaticScanResponse:
    """Build the static scan results envelope."""
    artifact = state.artifact_ids[0] if state.artifact_ids else "artifact-0"
    items: list[dict[str, Any]] = [
        {
            "artifact": artifact,
            "status": "completed",
            "data": {"verdict": state.level},
            "lastErrorMessage": None,
            "engineVersion": "1.0.0",
        }
    ]
    return StaticScanResponse.model_validate({"items": items, "total": len(items)})


def build_cdr_response(state: SubmissionState) -> CdrResponse:
    """Build the CDR results envelope."""
    artifact = state.artifact_ids[0] if state.artifact_ids else "artifact-0"
    items: list[dict[str, Any]] = [
        {
            "artifact": artifact,
            "status": "completed",
            "data": {"sanitized": True},
            "lastErrorMessage": None,
            "engineVersion": "1.0.0",
        }
    ]
    return CdrResponse.model_validate({"items": items, "total": len(items)})


def build_signature_check_response(state: SubmissionState) -> SignatureCheckResponse:
    """Build the signature check results envelope."""
    artifact = state.artifact_ids[0] if state.artifact_ids else "artifact-0"
    items: list[dict[str, Any]] = [
        {
            "artifact": artifact,
            "data": {"signed": False, "verdict": "unsigned"},
        }
    ]
    return SignatureCheckResponse.model_validate({"items": items, "total": len(items)})


def build_processes_response(state: SubmissionState) -> ProcessesResponse:
    """Build the dynamic processes response."""
    items: list[dict[str, Any]] = []
    if state.has_dynamic_report:
        items.append(
            {
                "pid": 1508,
                "ppid": 1,
                "tid": 1508,
                "name": "malware.exe",
                "cmd": "C:\\Users\\test\\malware.exe",
                "cwd": "C:\\Users\\test",
                "network": {
                    "items": [{"ip": "192.0.2.10", "port": 443, "protocol": "tcp"}],
                    "count": 1,
                },
                "events": {
                    "items": [
                        {
                            "type": "file",
                            "path": "C:\\Users\\test\\dropped.exe",
                            "mode": "write",
                        }
                    ],
                    "count": 1,
                },
            }
        )
    return ProcessesResponse.model_validate({"items": items, "total": len(items)})


def build_process_tree_response(state: SubmissionState) -> ProcessTreeResponse:
    """Build the dynamic process tree response."""
    nodes: list[dict[str, Any]] = []
    if state.has_dynamic_report:
        nodes.append(
            {
                "pid": 1508,
                "ppid": 1,
                "tid": 1508,
                "name": "malware.exe",
                "cmd": "C:\\Users\\test\\malware.exe",
                "children": [],
            }
        )
    return ProcessTreeResponse.model_validate({"nodes": nodes})


def build_behaviours_response(
    state: SubmissionState,
    *,
    os_name: BehaviourOs,
    pid: int | None,
    operation: str | None,
    page: int | None,
    limit: int | None,
) -> BehavioursResponse:
    """Build the OS-specific behaviour events response."""
    events: list[dict[str, Any]] = []
    if state.has_dynamic_report:
        events.append(
            {
                "type": "file",
                "pid": 1508,
                "ppid": 1,
                "processName": "malware.exe",
                "operation": "write",
                "eventId": 1,
                "eventCount": 1,
                "syscallLineNumber": 10,
                "timestamp": 1700000000,
                "details": {"path": "C:\\Users\\test\\dropped.exe"},
            }
        )
    if pid is not None:
        events = [e for e in events if e["pid"] == pid]
    if operation:
        events = [e for e in events if e["operation"] == operation]
    total = len(events)
    if page is not None and limit is not None:
        start = (page - 1) * limit
        events = events[start : start + limit]
    return BehavioursResponse.model_validate({"items": events, "total": total, "os": os_name})


def build_syscalls_response(
    state: SubmissionState,
    *,
    page: int | None,
    limit: int | None,
) -> SyscallsResponse:
    """Build the raw syscall log lines response."""
    lines: list[str] = []
    if state.has_dynamic_report:
        lines = [f"syscall {i}: NtReadFile" for i in range(8)]
    total = len(lines)
    if page is not None and limit is not None:
        start = (page - 1) * limit
        lines = lines[start : start + limit]
    return SyscallsResponse.model_validate({"items": lines, "total": total})


def build_network_summary(state: SubmissionState) -> NetworkSummary:
    """Build the network activity summary response."""
    return NetworkSummary.model_validate(
        {
            "dnsCount": 2,
            "httpCount": 1,
            "tcpCount": 3,
            "udpCount": 1,
            "threatCount": len(state.network_threats),
            "pcapAvailable": state.has_dynamic_report,
        }
    )


def build_dns_queries(state: SubmissionState) -> list[DnsQuery]:
    """Build the captured DNS queries response."""
    if not state.has_dynamic_report:
        return []
    items: list[dict[str, Any]] = [
        {
            "id": "dns-1",
            "host": "malware-c2.example.com",
            "type": "A",
            "status": "NOERROR",
            "records": ["192.0.2.10"],
            "timeshift": 0.5,
        },
        {
            "id": "dns-2",
            "host": "benign.example.com",
            "type": "A",
            "status": "NOERROR",
            "records": ["198.51.100.1"],
            "timeshift": 1.0,
        },
    ]
    return [DnsQuery.model_validate(item) for item in items]


def build_http_requests(state: SubmissionState) -> list[HttpRequest]:
    """Build the captured HTTP requests response (slim shape)."""
    if not state.has_dynamic_report:
        return []
    items: list[dict[str, Any]] = [
        {
            "id": "http-1",
            "host": "malware-c2.example.com",
            "ip": "192.0.2.10",
            "port": 443,
            "country": "US",
        }
    ]
    return [HttpRequest.model_validate(item) for item in items]


def _build_connection_payload(proto: str, identifier: str, ip: str, port: int) -> dict[str, Any]:
    return {
        "id": identifier,
        "protocol": proto,
        "destinationIp": ip,
        "destinationPort": port,
        "domain": None,
        "asn": "AS64500",
        "country": "US",
        "packets": {"sent": 10, "received": 20, "empty": False},
        "timeshift": 0.5,
    }


def build_tcp_connections(state: SubmissionState) -> list[Connection]:
    """Build the TCP connections response."""
    if not state.has_dynamic_report:
        return []
    payloads = [
        _build_connection_payload("tcp", "tcp-1", "192.0.2.10", 443),
        _build_connection_payload("tcp", "tcp-2", "192.0.2.11", 80),
        _build_connection_payload("tcp", "tcp-3", "192.0.2.12", 8080),
    ]
    return [Connection.model_validate(p) for p in payloads]


def build_udp_connections(state: SubmissionState) -> list[Connection]:
    """Build the UDP connections response."""
    if not state.has_dynamic_report:
        return []
    payloads = [_build_connection_payload("udp", "udp-1", "192.0.2.13", 53)]
    return [Connection.model_validate(p) for p in payloads]


def build_network_threats(state: SubmissionState) -> list[NetworkThreat]:
    """Build the Suricata network threats response."""
    return [
        NetworkThreat.model_validate(_network_threat_payload(seed))
        for seed in state.network_threats
    ]


def _network_threat_payload(seed: NetworkThreatSeed) -> dict[str, Any]:
    severity: ThreatSeverity = seed.severity
    app_proto: ThreatAppProto = seed.app_proto
    return {
        "signature": seed.signature,
        "description": seed.signature,
        "severity": severity,
        "protocol": "TCP",
        "appProto": app_proto,
        "destinationIp": "192.0.2.10",
        "destinationPort": 443,
        "timeshift": 0.5,
        "metadata": {"category": ["test"]},
        "details": {"sid": 1},
        "tls": None,
    }


def build_url_analysis_response(state: SubmissionState) -> UrlAnalysisResponse:
    """Build the URL analysis report response."""
    target_url = state.url or "https://example.com"
    payload: dict[str, Any] = {
        "level": state.level,
        "status": state.current_status(),
        "generalInfo": {
            "url": target_url,
            "domain": _domain_from_url(target_url),
            "websiteTitle": "Test Page",
        },
        "screenshot": {"available": state.screenshot_available},
        "ipInfo": {
            "ip": "192.0.2.20",
            "asn": "AS64501",
            "city": "Test City",
            "country": "US",
            "isp": "Test ISP",
            "organization": "Test Org",
            "threatStatus": {
                "verdict": state.level,
                "title": "IP verdict",
                "description": state.threat_analysis_summary or "Test verdict",
            },
        },
        "dnsRecords": [{"type": "A", "records": ["192.0.2.20"]}],
        "whois": {
            "domainName": _domain_from_url(target_url),
            "domainId": None,
            "nameServers": ["ns1.example.com"],
            "creationDate": "2020-01-01",
            "updatedDate": "2024-01-01",
            "expirationDate": "2025-01-01",
            "registrar": "Test Registrar",
            "registrarIanaId": None,
            "email": None,
            "phone": None,
        },
        "sslCertificate": None,
        "responseHeaders": {"server": "fake"},
        "extractedFile": None,
        "threatAnalysis": {
            "overview": [
                {
                    "source": "fake",
                    "title": "Fake source",
                    "description": state.threat_analysis_summary or "Test verdict",
                    "verdict": state.level,
                }
            ],
            "blacklist": state.level == "malicious",
            "threatDetails": [],
        },
        "pages": [state.final_url] if state.final_url else [target_url],
    }
    return UrlAnalysisResponse.model_validate(payload)


def _domain_from_url(url: str) -> str:
    stripped = url.split("://", 1)[-1]
    return stripped.split("/", 1)[0]


def build_media_files(state: SubmissionState) -> list[MediaFile]:
    """Build the list of available media files for a submission."""
    return [
        MediaFile.model_validate(
            {
                "id": mid,
                "name": f"{mid}.png",
                "contentType": "image/png",
                "size": 68,
            }
        )
        for mid in state.media_ids
    ]


def build_user_info() -> UserInfo:
    """Build a stable ``UserInfo`` payload for the /me endpoint."""
    payload: dict[str, Any] = {
        "userInfo": {
            "email": "test@example.com",
            "fullName": "Test User",
            "workspace": {
                "name": "Test Workspace",
                "alias": "test-workspace",
                "private": False,
                "type": "organization",
            },
            "limitsCount": {
                "apiRequestCount": 0,
                "dailySubmissionCount": 0,
                "concurrentSubmissionCount": 0,
            },
        },
        "plan": {
            "planName": "Enterprise",
            "startTime": "2024-01-01T00:00:00Z",
            "endTime": "2099-01-01T00:00:00Z",
            "subsTime": "monthly",
            "fileLimits": {
                "extensions": ["exe", "dll", "pdf"],
                "fileSize": "100MB",
            },
            "submissionLimits": {
                "apiLimit": 1000,
                "dailyLimit": 100,
                "concurrentLimit": 10,
            },
        },
        "modules": [
            {
                "moduleId": "dynamic",
                "moduleName": "Dynamic Analysis",
                "startTime": "2024-01-01T00:00:00Z",
                "endTime": "2099-01-01T00:00:00Z",
            }
        ],
    }
    return UserInfo.model_validate(payload)


def build_metafields() -> Metafields:
    """Build a stable Metafields payload for /config/metafields."""
    sandbox_options: list[dict[str, Any]] = [
        {
            "key": "timeout",
            "label": "Timeout",
            "description": "Analysis timeout in seconds",
            "type": "number",
            "default": 120,
            "options": None,
        },
        {
            "key": "internet_connection",
            "label": "Internet Connection",
            "description": "Allow internet connection",
            "type": "boolean",
            "default": True,
            "options": None,
        },
    ]
    static_options: list[dict[str, Any]] = [
        {
            "key": "deep_scan",
            "label": "Deep Scan",
            "description": "Enable deep static scan",
            "type": "boolean",
            "default": False,
            "options": None,
        }
    ]
    return Metafields.model_validate(
        {
            "sandbox": sandbox_options,
            "static": static_options,
            "cdr": [],
            "url": [],
            "open_in_browser": [],
        }
    )


def build_metafields_for(scan_type: str) -> list[MetafieldOption]:
    """Build the metafields for a single scan type."""
    metafields = build_metafields()
    mapping: dict[str, list[MetafieldOption]] = {
        "sandbox": metafields.sandbox,
        "static": metafields.static,
        "cdr": metafields.cdr,
        "url": metafields.url,
        "open_in_browser": metafields.open_in_browser,
    }
    return mapping.get(scan_type, [])


def build_environments() -> list[EnvironmentOption]:
    """Build the available sandbox environments."""
    items: list[dict[str, Any]] = [
        {"key": "w10_64", "name": "Windows 10 x64", "platform": "windows", "default": True},
        {"key": "w11_64", "name": "Windows 11 x64", "platform": "windows", "default": False},
        {"key": "ub22", "name": "Ubuntu 22.04", "platform": "linux", "default": False},
    ]
    return [EnvironmentOption.model_validate(item) for item in items]
