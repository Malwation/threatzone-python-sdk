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

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any

from threatzone.types import (
    AiReport,
    AiReportPending,
    AiReportRegenerateResult,
    Annotations,
    ArtifactJob,
    ArtifactsResponse,
    BehaviourFacets,
    BehaviourMatches,
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
    IndicatorsResponse,
    IoCsResponse,
    Killchain,
    MediaFile,
    Message,
    MetafieldOption,
    Metafields,
    MitreResponse,
    NetworkConfigListResponse,
    NetworkEndpoints,
    NetworkExfilRequest,
    NetworkFlowPackets,
    NetworkHostFlows,
    NetworkHttpPackets,
    NetworkSummary,
    NetworkThreat,
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
    SubmissionListItem,
    SyscallSearchResult,
    SyscallsResponse,
    UrlAnalysisBrowserSection,
    UrlAnalysisIndicatorEvidence,
    UrlAnalysisIndicators,
    UrlAnalysisResponse,
    UrlAnalysisSession,
    UserInfo,
    Verdict,
    YaraRulesResponse,
)
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
    extension = state.filename.rsplit(".", 1)[-1] if "." in state.filename else "bin"
    return {
        "name": state.filename,
        "size": 1024,
        "extension": extension,
        "mimetype": "application/octet-stream",
        "isMimetypeChecked": True,
        "declaredExtension": extension,
        "realExtension": extension,
        "isMimetypeMismatched": False,
        "entrypoint": None,
        "source": {"type": "upload", "url": None},
    }


_FAKE_REPORT_DURATION_SECONDS = 42.7
_TAGS: list[dict[str, Any]] = [
    {"type": "family", "value": "test", "origin": "config_extractor", "author": "system"}
]


def _report_statuses(state: SubmissionState) -> list[dict[str, Any]]:
    statuses: list[dict[str, Any]] = []
    for report_type in state.report_types():
        raw_status = state.report_status_for(report_type)
        completed = raw_status == "completed"
        level: str | None = state.level if completed else None
        statuses.append(
            {
                "type": report_type,
                "status": raw_status,
                "level": level,
                "score": None,
                "duration": _FAKE_REPORT_DURATION_SECONDS if completed else None,
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
    total = max(len(report_types), 1)
    finished = total if status == "completed" else 0
    return {
        "status": status,
        "jobs": {
            "total": total,
            "succeeded": finished,
            "failed": 0,
            "skipped": 0,
            "finished": finished,
        },
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
        "tags": [dict(tag) for tag in _TAGS],
        "reports": _report_statuses(state),
        "overview": _submission_overview(state),
        "indicators": _indicator_rollup(state),
        "mitreTechniques": list(state.mitre_techniques),
        "createdAt": state.created_at.isoformat(),
        "updatedAt": state.updated_at.isoformat(),
    }


def _file_history(state: SubmissionState) -> dict[str, Any] | None:
    if len(state.filename_history) < 2:
        return None
    return {
        "filenames": list(state.filename_history),
        "lastReceivedAt": int(state.created_at.timestamp() * 1000),
    }


def _live_score_breakdown(state: SubmissionState) -> dict[str, Any] | None:
    if state.type != "file" or state.current_status() != "completed":
        return None
    return state.score_breakdown


def _submission_detail_payload(state: SubmissionState) -> dict[str, Any]:
    payload = _submission_payload(state)
    reports: list[dict[str, Any]] = payload["reports"]
    for report in reports:
        report["metafields"] = state.report_metafields.get(report["type"])
    durations = [r["duration"] for r in reports if r["duration"] is not None]
    payload["overview"]["duration"] = max(durations) if durations else None
    if payload["file"] is not None:
        payload["file"]["history"] = _file_history(state)
    breakdown = _live_score_breakdown(state)
    payload["scoreBreakdown"] = breakdown
    payload["score"] = breakdown["score"] if breakdown is not None else None
    return payload


def build_submission(state: SubmissionState) -> Submission:
    """Build the ``GET /submissions/{uuid}`` detail response for a state."""
    return Submission.model_validate(_submission_detail_payload(state))


def build_submission_search_row(state: SubmissionState) -> Submission:
    """Build one ``GET /submissions/search/sha256/{sha256}`` row.

    The real API sends the detail-only fields (``scoreBreakdown``,
    ``file.history``, ``reports[].metafields``, ``overview.duration``) only on
    the detail route.
    """
    return Submission.model_validate(_submission_payload(state))


def _submission_list_item_payload(state: SubmissionState) -> dict[str, Any]:
    return {
        "uuid": state.uuid,
        "filename": state.filename if state.type == "file" else None,
        "sha256": state.sha256 if state.type == "file" else None,
        "level": state.level,
        "type": state.type,
        "private": state.private,
        "tags": [dict(tag) for tag in _TAGS],
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
                "category": ["default"],
                "level": seed.level,
                "score": _indicator_score(seed),
                "pids": list(seed.pids),
                "attackCodes": [seed.attack_code],
                "eventIds": [100 + idx],
                "syscallLineNumbers": [200 + idx],
                "author": "system",
                "whyMatched": f"The sample used MITRE technique {seed.attack_code}.",
                "inVerdictChain": seed.level == "malicious",
                "pidGens": [1 for _ in seed.pids],
                "ruleSource": f"behavior:{seed.attack_code}",
                "tOffsetS": 1.5 + idx,
                "occurrences": 1,
                "related": [
                    {
                        "eventId": 100 + idx,
                        "signalId": f"sig-{idx:04d}",
                        "text": f"Process {seed.pids[0]} used {seed.attack_code}",
                        "tOffsetS": 1.5 + idx,
                        "actor": {"image": "malware.exe", "pid": seed.pids[0]},
                    }
                ]
                if seed.pids
                else [],
                "actor": {
                    "image": "malware.exe",
                    "pid": seed.pids[0],
                    "pidGen": 1,
                    "lineage": "explorer.exe > malware.exe",
                }
                if seed.pids
                else None,
            }
        )
    total = len(items)
    page_number = page if page is not None else 1
    page_limit = limit if limit is not None else 20
    start = (page_number - 1) * page_limit
    items = items[start : start + page_limit]
    counts = _indicator_level_counts(state.indicators)
    return IndicatorsResponse.model_validate(
        {
            "items": items,
            "total": total,
            "page": page_number,
            "limit": page_limit,
            "totalPages": (total + page_limit - 1) // page_limit if page_limit > 0 else 0,
            "levels": counts,
        }
    )


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
        if type_filter and seed.type.lower() != type_filter:
            continue
        items.append(
            {
                "type": seed.type.lower(),
                "value": seed.value,
                "artifacts": [state.artifact_ids[0]] if state.artifact_ids else [],
                "rawType": seed.type,
            }
        )
    total = len(items)
    page_number = page if page is not None else 1
    page_limit = limit if limit is not None else 20
    start = (page_number - 1) * page_limit
    items = items[start : start + page_limit]
    return IoCsResponse.model_validate(
        {
            "items": items,
            "total": total,
            "page": page_number,
            "limit": page_limit,
            "totalPages": (total + page_limit - 1) // page_limit if page_limit > 0 else 0,
        }
    )


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
    page_number = page if page is not None else 1
    page_limit = limit if limit is not None else 20
    start = (page_number - 1) * page_limit
    items = items[start : start + page_limit]
    return YaraRulesResponse.model_validate(
        {
            "items": items,
            "total": total,
            "page": page_number,
            "limit": page_limit,
            "totalPages": (total + page_limit - 1) // page_limit if page_limit > 0 else 0,
        }
    )


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


ARTIFACT_SOURCES: frozenset[str] = frozenset(
    {
        "dynamic_report",
        "static_report",
        "url_report",
        "unpacker",
        "config_extractor",
        "yara_generator",
        "user_upload",
        "manual",
    }
)


def build_artifacts_response(
    state: SubmissionState, *, source: str | None = None
) -> ArtifactsResponse:
    """Build the artifacts response, applying the ``source`` filter."""
    items: list[dict[str, Any]] = []
    for idx, artifact_id in enumerate(state.artifact_ids):
        if source is not None and source != "dynamic_report":
            continue
        items.append(
            {
                "id": artifact_id,
                "filename": f"artifact-{idx}.bin",
                "size": 2048,
                "type": "dropped_file",
                "source": "dynamic_report",
                "hashes": {
                    "md5": "1" * 32,
                    "sha1": "1" * 40,
                    "sha256": f"{idx:064x}",
                },
                "tags": ["test"],
                "processAttribution": None,
                "analysisStatus": "analyzed",
                "analysisTrigger": "auto",
                "analysisReason": None,
                "downloadLink": (
                    f"/public-api/submissions/{state.uuid}/download/artifact/{artifact_id}"
                ),
            }
        )
    return ArtifactsResponse.model_validate({"items": items, "total": len(items)})


def build_artifact_jobs() -> list[ArtifactJob]:
    """Build the engine jobs of one artifact, oldest first. Every artifact has the same jobs."""
    return [
        ArtifactJob.model_validate(
            {"engineType": "static_scan", "status": "success", "errorCode": None}
        ),
        ArtifactJob.model_validate(
            {"engineType": "config_extractor", "status": "skipped", "errorCode": "JOB_SKIPPED"}
        ),
    ]


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


_MITRE_CATALOG: dict[str, tuple[str, list[str]]] = {
    "T1055": ("Process Injection", ["TA0004", "TA0005"]),
    "T1059": ("Command and Scripting Interpreter", ["TA0002"]),
    "T1059.001": ("PowerShell", ["TA0002"]),
    "T1071": ("Application Layer Protocol", ["TA0011"]),
    "T1112": ("Modify Registry", ["TA0005"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
}


def _indicator_score(seed: IndicatorSeed) -> int:
    return 80 if seed.level == "malicious" else 50


def _mitre_items(state: SubmissionState) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for technique_id in sorted(set(state.mitre_techniques)):
        catalog_entry = _MITRE_CATALOG.get(technique_id)
        if catalog_entry is None:
            continue
        name, tactic_ids = catalog_entry
        carriers = [
            (idx, seed)
            for idx, seed in enumerate(state.indicators)
            if seed.attack_code == technique_id
        ]
        items.append(
            {
                "techniqueId": technique_id,
                "name": name,
                "tacticIds": tactic_ids,
                "score": max((_indicator_score(seed) for _, seed in carriers), default=0),
                "scoreMaximum": 100,
                "inVerdictChain": any(seed.level == "malicious" for _, seed in carriers),
                "indicatorIds": [f"ind-{idx}" for idx, _ in carriers],
            }
        )
    return items


def build_mitre_response(state: SubmissionState) -> MitreResponse:
    """Build the MITRE techniques response. ``items`` holds the seeded techniques that are in
    the small catalog of the fake, as a server leaves out codes that are not in its catalog."""
    return MitreResponse.model_validate(
        {
            "techniques": list(state.mitre_techniques),
            "total": len(state.mitre_techniques),
            "items": _mitre_items(state),
        }
    )


def build_static_scan_response(state: SubmissionState) -> StaticScanResponse:
    """Build the per-format static analysis report singleton."""
    return StaticScanResponse.model_validate(
        {
            "submission": state.uuid,
            "status": "completed",
            "reportFormat": "exe",
            "level": state.level,
            "score": 92.0,
            "fileInfo": {
                "md5": "0" * 32,
                "sha1": "0" * 40,
                "sha256": state.sha256,
                "ssdeep": "3:aaaa:aaaa",
                "mime_type": "application/x-dosexec",
                "file_type": "PE32",
                "entropy": 7.1,
                "filesize": "1.00 MB",
                "realFilename": None,
                "realSha256": None,
            },
            "strings": {"totalCount": 1234},
            "dieResults": [{"name": "PE", "string": "PE32", "type": "exe", "version": None}],
            "analysisTime": "00:00:02",
            "metafields": None,
            "imports": [{"library": "kernel32.dll", "functions": ["VirtualAlloc"]}],
            "peExeSections": [{"name": ".text", "entropy": 6.5}],
        }
    )


def build_static_scan_strings(state: SubmissionState) -> dict[str, Any]:
    """Build the canned extracted-strings JSON payload streamed by the fake."""
    return {
        "submission": state.uuid,
        "totalCount": 2,
        "strings": ["VirtualAlloc", "kernel32.dll"],
    }


_FAKE_BOT_TOKEN_URL = (
    "https://api.telegram.org/bot123456789:AAFabcdefghijklmnopqrstuvwxyz012345/sendMessage"
)

_FAKE_STRING_ITEMS: tuple[dict[str, Any], ...] = (
    {"value": "IsDebuggerPresent", "from_source": "ascii", "blacklist": True, "hint": "anti-debug"},
    {"value": "kernel32.dll", "from_source": "ascii", "blacklist": False, "hint": None},
    {"value": "VirtualAlloc", "from_source": "ascii", "blacklist": False, "hint": None},
    {
        "value": f'url = "{_FAKE_BOT_TOKEN_URL}"',
        "from_source": "utf16",
        "blacklist": False,
        "hint": None,
    },
    {
        "value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "from_source": "ascii",
        "blacklist": True,
        "hint": "persistence",
    },
)

STRINGS_WINDOW_MAX_SPAN = 1000
STRINGS_SEARCH_MAX_LENGTH = 200


def build_static_scan_string_facts(state: SubmissionState) -> StringFacts:
    """Build the string facts: observables (full secret values) and facts."""
    del state
    return StringFacts.model_validate(
        {
            "observables": [
                {
                    "kind": "bot-token",
                    "value": _FAKE_BOT_TOKEN_URL,
                    "count": 1,
                    "display": _FAKE_BOT_TOKEN_URL,
                    "host": "api.telegram.org",
                    "detail": "Telegram",
                    "source": _FAKE_STRING_ITEMS[3]["value"],
                    "secret": True,
                },
                {
                    "kind": "registry",
                    "value": _FAKE_STRING_ITEMS[4]["value"],
                    "count": 1,
                    "display": _FAKE_STRING_ITEMS[4]["value"],
                    "host": None,
                    "detail": None,
                    "source": _FAKE_STRING_ITEMS[4]["value"],
                    "secret": False,
                },
            ],
            "facts": [
                {
                    "code": "anti-debug",
                    "value": "Debugger checks",
                    "capability": "anti-analysis",
                    "matches": ["IsDebuggerPresent"],
                    "count": 1,
                    "names": [],
                },
                {
                    "code": "run-key",
                    "value": "Run key persistence",
                    "capability": "persistence",
                    "matches": [_FAKE_STRING_ITEMS[4]["value"]],
                    "count": 1,
                    "names": [],
                },
            ],
            "total": len(_FAKE_STRING_ITEMS),
            "truncated": False,
        }
    )


def build_static_scan_strings_page(
    state: SubmissionState,
    *,
    start: int | None,
    end: int | None,
    search: str | None,
) -> StringsPage:
    """Apply the API window rule: filter by ``search`` first, then slice ``start:end``."""
    needle = (search or "").strip().lower()
    matched = [item for item in _FAKE_STRING_ITEMS if needle in str(item["value"]).lower()]
    window_start = start if start is not None else 0
    window_limit = window_start + STRINGS_WINDOW_MAX_SPAN
    window_end = max(window_start, min(end if end is not None else window_limit, window_limit))
    return StringsPage.model_validate(
        {
            "items": matched[window_start:window_end],
            "itemsCount": len(matched),
            "start": window_start,
            "end": window_end,
            "downloadLink": f"/public-api/submissions/{state.uuid}/static-scan/strings",
        }
    )


def build_cdr_response(state: SubmissionState) -> CdrResponse:
    """Build the per-submission CDR transformation result."""
    return CdrResponse.model_validate(
        {
            "submission": state.uuid,
            "status": "completed",
            "sanitized": ["doc.pdf"],
            "removed": ["macro1"],
            "sanitizedFileInfo": {
                "description": "Sanitized",
                "fileType": "PDF",
                "fileSize": 1024,
                "sha256": "ab" * 32,
                "name": "doc.pdf",
                "details": [
                    {
                        "name": "Macros",
                        "action": "removed",
                        "data": ["AutoOpen"],
                        "count": 1,
                        "sha256": None,
                        "description": "VBA macros",
                        "fileName": None,
                        "details": [],
                    },
                    {
                        "name": "Archive member",
                        "action": "sanitized",
                        "data": None,
                        "count": 1,
                        "sha256": ["cd" * 32],
                        "description": "Inner document",
                        "fileName": "invoice.docx",
                        "details": [
                            {
                                "name": "External links",
                                "action": "removed",
                                "data": ["https://example.invalid/payload"],
                                "count": 1,
                                "sha256": None,
                                "description": None,
                                "fileName": None,
                                "details": [],
                            }
                        ],
                    },
                ],
            },
            "elapsedTime": "00:00:43",
            "metafields": None,
        }
    )


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
                "pidGen": 0,
                "origin": "sample",
                "tid": 1508,
                "name": "malware.exe",
                "cmd": "C:\\Users\\test\\malware.exe",
                "cwd": "C:\\Users\\test",
                "image": "C:\\Users\\test\\malware.exe",
                "method": "NtCreateUserProcess",
                "timestamp": 1700000000.25,
                "exitTimestamp": None,
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
                "pidGen": 0,
                "origin": "sample",
                "tid": 1508,
                "name": "malware.exe",
                "cmd": "C:\\Users\\test\\malware.exe",
                "cwd": "C:\\Users\\test",
                "children": [],
            }
        )
    return ProcessTreeResponse.model_validate({"nodes": nodes})


def build_killchain_response(state: SubmissionState) -> Killchain:
    """Build the kill chain response of a dynamic report.

    The dropped file links to the first stored artifact. The memory dump has no stored
    artifact, so its ``artifactId`` and analysis fields are null.
    """
    artifact_id = state.artifact_ids[0] if state.artifact_ids else None
    return Killchain.model_validate(
        {
            "dumpCollectorActive": True,
            "artifactInventoryCoverage": {
                "sourceStatus": "available",
                "sourceError": None,
                "counts": [
                    {"name": "event_file_count", "value": 1},
                    {"name": "sidecar_count", "value": 1},
                ],
                "unretainedRowsOmitted": 0,
            },
            "createdProcesses": [
                {
                    "pid": 1508,
                    "pidGen": 0,
                    "origin": "sample",
                    "ppid": 1,
                    "tid": 1508,
                    "processName": "malware.exe",
                    "image": "C:\\Users\\test\\malware.exe",
                    "cmd": "C:\\Users\\test\\malware.exe",
                    "method": "NtCreateUserProcess",
                    "workDir": "C:\\Users\\test",
                    "timestamp": 1700000000.25,
                    "exitTimestamp": None,
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
                    "network": {
                        "items": [{"ip": "192.0.2.10", "port": 443, "protocol": "tcp"}],
                        "count": 1,
                    },
                }
            ],
            "droppedFiles": [
                {
                    "pid": 1508,
                    "pidGen": 0,
                    "processName": "malware.exe",
                    "executablePath": "C:\\Users\\test\\malware.exe",
                    "files": [
                        {
                            "path": "C:\\Users\\test\\dropped.exe",
                            "sha256": f"{0:064x}",
                            "fileSize": 2048,
                            "timestamp": 1700000001.5,
                            "artifactId": artifact_id,
                            "analysisStatus": "analyzed" if artifact_id else None,
                            "analysisReason": None,
                            "rawPath": "\\Device\\HarddiskVolume3\\Users\\test\\dropped.exe",
                            "pathAuthority": "verified_volume_map",
                            "pathAuthorityReason": None,
                            "sourceActorBound": True,
                            "captureClosed": True,
                            "retention": "retained",
                            "retentionDetail": None,
                            "pidGen": 0,
                            "eventSeq": 42,
                        }
                    ],
                }
            ],
            "memDumps": [
                {
                    "pid": 1508,
                    "processName": "malware.exe",
                    "executablePath": "C:\\Users\\test\\malware.exe",
                    "regions": [
                        {
                            "offsetStart": "0x400000",
                            "offsetEnd": "0x401000",
                            "dumps": [
                                {
                                    "path": "C:\\dumps\\1508_0x400000.dmp",
                                    "sha256": None,
                                    "fileSize": 4096,
                                    "timestamp": 1700000002.0,
                                    "artifactId": None,
                                    "analysisStatus": None,
                                    "analysisReason": None,
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


@dataclass(frozen=True)
class BehaviourFilter:
    """The behaviour filters of one fake request, parsed from the query string."""

    event_type: str | None = None
    pid: int | None = None
    operation: str | None = None
    process_name: str | None = None
    event_ids: list[int] | None = None
    pids: list[int] | None = None
    parent_pids: list[int] | None = None
    types: list[str] | None = None
    operations: list[str] | None = None
    statuses: list[str] | None = None
    process_name_contains: str | None = None
    from_timestamp: float | None = None
    to_timestamp: float | None = None
    syscall_line_from: int | None = None
    syscall_line_to: int | None = None
    text: str | None = None
    fields: dict[str, list[str]] = field(default_factory=dict)

    def matches(self, event: dict[str, Any]) -> bool:
        """Apply every set filter. The values of one list match as any of."""
        details: dict[str, Any] = event["details"]
        timestamp = float(event["timestamp"])
        line = event["syscallLineNumber"]
        process_name = str(event["processName"]).lower()
        checks = [
            self.event_type is None or event["type"] == self.event_type,
            self.pid is None or event["pid"] == self.pid,
            self.operation is None or event["operation"] == self.operation,
            self.process_name is None or event["processName"] == self.process_name,
            self.event_ids is None or event["eventId"] in self.event_ids,
            self.pids is None or event["pid"] in self.pids,
            self.parent_pids is None or event["ppid"] in self.parent_pids,
            self.types is None or event["type"] in self.types,
            self.operations is None
            or event["operation"].lower() in {op.lower() for op in self.operations},
            self.statuses is None or details.get("status") in self.statuses,
            self.process_name_contains is None
            or self.process_name_contains.lower() in process_name,
            self.from_timestamp is None or (timestamp > 0 and timestamp >= self.from_timestamp),
            self.to_timestamp is None or (timestamp > 0 and timestamp <= self.to_timestamp),
            self.syscall_line_from is None or (line is not None and line >= self.syscall_line_from),
            self.syscall_line_to is None or (line is not None and line <= self.syscall_line_to),
            self.text is None or self.text.lower() in _behaviour_search_text(event),
        ]
        checks.extend(
            any(value.lower() in str(details.get(key, "")).lower() for value in values)
            for key, values in self.fields.items()
        )
        return all(checks)


def _behaviour_search_text(event: dict[str, Any]) -> str:
    parts = [
        str(event["processName"]),
        str(event["pid"]),
        str(event["ppid"]),
        str(event["operation"]),
        str(event["timestamp"]),
        *(str(value) for value in event["details"].values()),
    ]
    return " ".join(parts).lower()


_RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"


def _behaviour_events(state: SubmissionState) -> list[dict[str, Any]]:
    if not state.has_dynamic_report:
        return []
    return [
        {
            "type": "file",
            "pid": 1508,
            "ppid": 1,
            "pidGen": 0,
            "processName": "malware.exe",
            "operation": "write",
            "eventId": 1,
            "eventCount": 1,
            "syscallLineNumber": 10,
            "timestamp": 1700000000,
            "subject": "C:\\Users\\test\\dropped.exe",
            "details": {"path": "C:\\Users\\test\\dropped.exe", "status": "success"},
        },
        {
            "type": "registry",
            "pid": 2044,
            "ppid": 1508,
            "pidGen": 0,
            "processName": "cmd.exe",
            "operation": "RegSetValue",
            "eventId": 2,
            "eventCount": 1,
            "syscallLineNumber": 12,
            "timestamp": 1700000001.5,
            "subject": _RUN_KEY,
            "details": {"key": _RUN_KEY, "value": "dropped.exe", "status": "success"},
        },
    ]


def build_behaviours_response(
    state: SubmissionState,
    *,
    behaviour_filter: BehaviourFilter,
    uses_index: bool,
    sort: str | None,
    page: int | None,
    limit: int | None,
) -> BehavioursResponse:
    """Build the paginated behaviour events response."""
    events = [event for event in _behaviour_events(state) if behaviour_filter.matches(event)]
    if sort == "time":
        events.sort(key=lambda event: float(event["timestamp"]))
    total = len(events)
    page_number = page if page is not None else 1
    page_limit = limit if limit is not None else 100
    start = (page_number - 1) * page_limit
    events = events[start : start + page_limit]
    payload: dict[str, Any] = {
        "items": events,
        "total": total,
        "page": page_number,
        "limit": page_limit,
        "totalPages": (total + page_limit - 1) // page_limit,
    }
    if uses_index:
        payload["sortedBy"] = "time" if sort == "time" else "eventId"
        payload["manyProcessesMatch"] = False
    return BehavioursResponse.model_validate(payload)


def _value_counts(values: list[str]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"value": value, "count": count} for value, count in ranked]


def build_behaviour_summary(state: SubmissionState) -> BehaviourSummary:
    """Build the behaviour index counts response."""
    events = _behaviour_events(state)
    timestamps = [float(event["timestamp"]) for event in events]
    by_process: dict[int, dict[str, Any]] = {}
    for event in events:
        row = by_process.setdefault(
            event["pid"],
            {
                "processId": event["pid"],
                "processName": event["processName"],
                "count": 0,
                "firstTimestamp": float(event["timestamp"]),
                "lastTimestamp": float(event["timestamp"]),
            },
        )
        row["count"] += 1
        row["lastTimestamp"] = float(event["timestamp"])
    return BehaviourSummary.model_validate(
        {
            "totalCount": len(events),
            "firstTimestamp": min(timestamps) if timestamps else None,
            "lastTimestamp": max(timestamps) if timestamps else None,
            "byType": _value_counts([event["type"] for event in events]),
            "byOperation": _value_counts([event["operation"] for event in events]),
            "byProcess": sorted(by_process.values(), key=lambda row: -int(row["count"])),
            "exits": [],
        }
    )


def build_behaviour_facets(
    state: SubmissionState,
    *,
    facet_field: str,
    behaviour_filter: BehaviourFilter,
    contains: str | None,
    first: int | None,
) -> BehaviourFacets:
    """Build the value counts of one behaviour field."""
    events = [event for event in _behaviour_events(state) if behaviour_filter.matches(event)]
    values: list[str] = []
    for event in events:
        value = (
            event["details"].get("function")
            if facet_field == "function"
            else event.get(facet_field)
        )
        if isinstance(value, str) and (contains is None or contains.lower() in value.lower()):
            values.append(value)
    counts = _value_counts(values)[: first if first is not None else 200]
    return BehaviourFacets.model_validate(
        {"items": counts, "complete": True, "scannedRows": len(events)}
    )


def _syscall_lines(state: SubmissionState) -> list[str]:
    if not state.has_dynamic_report:
        return []
    read = "ntdll!NtReadFile(FileHandle=0x1c4, Status=0x0) // Process Name:malware.exe PID:1508 TID:1600"
    create = (
        'ntdll!NtCreateFile(ObjectAttributes="C:\\Users\\test\\dropped.exe", '
        "Status=0xC0000034) // Process Name:cmd.exe PID:2044 TID:2050"
    )
    return [read if index % 2 == 0 else create for index in range(12)]


def build_behaviour_matches(state: SubmissionState, texts: list[str]) -> BehaviourMatches:
    """Count the events whose subject contains each text, without case. A repeated text gives
    one entry; texts that differ only in case get the same counts."""
    events = _behaviour_events(state)
    if not events:
        return BehaviourMatches.model_validate({"items": []})
    items: list[dict[str, Any]] = []
    for text in dict.fromkeys(texts):
        needle = text.lower()
        matched = [
            event
            for event in events
            if isinstance(event.get("subject"), str) and needle in event["subject"].lower()
        ]
        items.append(
            {
                "needle": text,
                "count": len(matched),
                "firstEventId": min((event["eventId"] for event in matched), default=None),
                "samples": list(dict.fromkeys(event["subject"] for event in matched))[:3],
                "complete": True,
                "scannedRows": len(events),
            }
        )
    return BehaviourMatches.model_validate({"items": items})


def build_artifact_yara_rule(state: SubmissionState, artifact_id: str) -> bytes:
    """Build the generated YARA rule text of one artifact."""
    rule_name = re.sub(r"[^A-Za-z0-9_]", "_", f"artifact_{artifact_id}")
    return (
        f"rule {rule_name} {{\n"
        f'  meta:\n    submission = "{state.uuid}"\n'
        f'  strings:\n    $a = "FAKE-ARTIFACT-BYTES"\n'
        "  condition:\n    $a\n}\n"
    ).encode()


def build_syscalls_response(
    state: SubmissionState,
    *,
    page: int | None,
    limit: int | None,
) -> SyscallsResponse:
    """Build the raw syscall log lines response."""
    lines = _syscall_lines(state)
    total = len(lines)
    page_number = page if page is not None else 1
    page_limit = limit if limit is not None else 500
    start = (page_number - 1) * page_limit
    lines = lines[start : start + page_limit]
    return SyscallsResponse.model_validate(
        {
            "items": lines,
            "total": total,
            "page": page_number,
            "limit": page_limit,
            "totalPages": (total + page_limit - 1) // page_limit,
            "firstLine": start + 1 if lines else None,
        }
    )


def build_raw_behaviour_file(state: SubmissionState) -> bytes:
    """Build the raw ``behaviour.json`` file of the fake run."""
    return json.dumps(_behaviour_events(state)).encode("utf-8")


def build_raw_syscall_log(state: SubmissionState) -> bytes:
    """Build the raw ``syscalls.txt`` file of the fake run."""
    return "\n".join(_syscall_lines(state)).encode("utf-8")


_SYSCALL_STATUS = re.compile(r"(?:Status|NtStatus|ExitStatus|ErrorStatus)=(0x[0-9a-fA-F]+)")
_SYSCALL_PID = re.compile(r"(?:^|\s)PID:(\d+)")


def _syscall_line_matches(
    raw: str,
    *,
    query: str,
    pids: list[int] | None,
    failed_only: bool,
    apis: list[str] | None,
) -> bool:
    if query.lower() not in raw.lower():
        return False
    if pids is not None:
        _, _, trailer = raw.partition("//")
        pid_match = _SYSCALL_PID.search(trailer)
        if pid_match is None or int(pid_match.group(1)) not in pids:
            return False
    if failed_only:
        status = _SYSCALL_STATUS.search(raw)
        if status is None or int(status.group(1), 16) < 0x80000000:
            return False
    if apis is not None:
        call = raw.split("(", 1)[0]
        if call not in apis and call.rsplit("!", 1)[-1] not in apis:
            return False
    return True


def build_syscall_search_result(
    state: SubmissionState,
    *,
    query: str,
    pids: list[int] | None,
    failed_only: bool,
    apis: list[str] | None,
    after_line: int,
    limit: int,
) -> SyscallSearchResult:
    """Build one page of syscall search hits. The fake never reaches a scan limit."""
    lines = _syscall_lines(state)
    total = len(lines)
    hits: list[dict[str, Any]] = []
    last_line = total
    for number in range(after_line + 1, total + 1):
        raw = lines[number - 1]
        if _syscall_line_matches(raw, query=query, pids=pids, failed_only=failed_only, apis=apis):
            hits.append({"line": number, "raw": raw})
            if len(hits) >= limit:
                last_line = number
                break
    done = last_line >= total
    return SyscallSearchResult.model_validate(
        {
            "lines": hits,
            "nextFromLine": None if done else max(last_line, after_line),
            "scannedTo": last_line,
            "totalCount": total,
            "done": done,
            "truncated": False,
            "busy": False,
        }
    )


def _sample_source_counts(count: int) -> dict[str, int]:
    return {"sample": count, "sampleChild": 0, "sensorOnly": 0, "windowsBackground": 0}


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
            "exfilRequestCount": len(_exfil_request_payloads(state)),
            "httpsPcapAvailable": state.has_dynamic_report and state.https_pcap_available,
            "hasHttpsInspection": state.https_pcap_available,
            "unattributedPcapAvailable": False,
            "attributionCounts": {
                "dns": _sample_source_counts(2),
                "http": _sample_source_counts(1),
                "tcp": _sample_source_counts(3),
                "udp": _sample_source_counts(1),
                "threats": _sample_source_counts(len(state.network_threats)),
            },
            "unattributedCounts": None,
            "submissionOnlyAlerts": None,
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


_LOCAL_IP = "10.0.2.15"
_C2_HOST = "malware-c2.example.com"
_C2_IP = "192.0.2.10"


def _build_connection_payload(proto: str, identifier: str, ip: str, port: int) -> dict[str, Any]:
    is_c2 = ip == _C2_IP
    return {
        "id": identifier,
        "protocol": proto,
        "sourceIp": _LOCAL_IP,
        "sourcePort": 49712,
        "destinationIp": ip,
        "destinationPort": port,
        "domain": _C2_HOST if is_c2 else None,
        "ptrDomain": "server-10.hosting.example.net" if is_c2 else None,
        "asn": "AS64500",
        "country": "US",
        "packets": {"sent": 10, "received": 20, "empty": False},
        "appProto": "tls" if port == 443 else None,
        "hostname": _C2_HOST if is_c2 else None,
        "pktsToServer": 10,
        "pktsToClient": 20,
        "bytesToServer": 1832,
        "bytesToClient": 6120,
        "packetsTotal": 30,
        "packetsOmitted": 0,
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


_THREAT_SEVERITY_LEVELS: dict[str, int] = {"high": 1, "low": 2}


def _network_threat_payload(seed: NetworkThreatSeed) -> dict[str, Any]:
    severity: ThreatSeverity = seed.severity
    app_proto: ThreatAppProto = seed.app_proto
    return {
        "signature": seed.signature,
        "description": seed.signature,
        "severity": severity,
        "severityLevel": _THREAT_SEVERITY_LEVELS[seed.severity],
        "protocol": "TCP",
        "appProto": app_proto,
        "sourceIp": _LOCAL_IP,
        "sourcePort": 49712,
        "destinationIp": _C2_IP,
        "destinationPort": 443,
        "timeshift": 0.5,
        "metadata": {"category": ["test"]},
        "details": {"sid": 1},
        "tls": None,
        "capture": "decrypted_https" if app_proto == "TLS" else None,
    }


def _exfil_request_payloads(state: SubmissionState) -> list[dict[str, Any]]:
    if not state.has_dynamic_report or state.level != "malicious":
        return []
    return [
        {
            "api": "telegram_bot",
            "kind": "send_file",
            "host": "api.telegram.org",
            "method": "POST",
            "apiMethod": "sendDocument",
            "targetId": "123456789",
            "maskedTarget": "/bot123456789:FAKE-TOKEN-FOR-TESTS/sendDocument",
            "requestBytes": 1051,
            "replyStatus": None,
            "requestCount": 1,
            "capture": "decrypted_https",
            "firstSeen": "2026-10-08T15:12:46.875Z",
            "score": 80,
            "tier": "Malicious",
            "processId": None,
            "processImage": None,
            "text": "A file was uploaded to the Telegram bot 123456789.",
        }
    ]


def build_network_exfil_requests(
    state: SubmissionState,
    *,
    limit: int | None,
    skip: int | None,
) -> list[NetworkExfilRequest]:
    """Build the chat bot and webhook requests response."""
    payloads = _exfil_request_payloads(state)[skip or 0 :]
    if limit is not None:
        payloads = payloads[:limit]
    return [NetworkExfilRequest.model_validate(item) for item in payloads]


def _packet_data(payload: bytes) -> dict[str, Any]:
    return {
        "trimmed": False,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "md5": None,
        "sha1": None,
        "ssdeep": None,
        "data": base64.b64encode(payload).decode("ascii"),
    }


def build_http_request_packets(
    state: SubmissionState, request_id: str
) -> NetworkHttpPackets | None:
    """Build the request and response pairs of one HTTP row, or ``None`` for an unknown ID."""
    if request_id not in {row.id for row in build_http_requests(state)}:
        return None
    return NetworkHttpPackets.model_validate(
        {
            "items": [
                {
                    "timeshift": 0.75,
                    "url": f"http://{_C2_HOST}/gate.php",
                    "method": "POST",
                    "destinationIp": _C2_IP,
                    "destinationPort": 443,
                    "portKnown": True,
                    "headers": {"Host": _C2_HOST, "Content-Type": "text/plain"},
                    "body": _packet_data(b"bot=fake&token=FAKE-TOKEN-FOR-TESTS"),
                    "response": {
                        "timeshift": 0.9,
                        "destinationIp": _LOCAL_IP,
                        "destinationPort": 49712,
                        "headers": {"Content-Type": "text/html"},
                        "statusCode": 200,
                        "body": None,
                    },
                }
            ],
            "truncated": False,
            "sourceScope": None,
        }
    )


def build_connection_packets(
    state: SubmissionState, protocol: str, connection_id: str
) -> NetworkFlowPackets | None:
    """Build the packets of one TCP or UDP row, or ``None`` when the row is not on the list."""
    rows = build_tcp_connections(state) if protocol == "tcp" else build_udp_connections(state)
    row = next((item for item in rows if item.id == connection_id), None)
    if row is None:
        return None
    return NetworkFlowPackets.model_validate(
        {
            "protocol": protocol,
            "sourceIp": row.source_ip,
            "sourcePort": row.source_port,
            "destinationIp": row.destination_ip,
            "destinationPort": row.destination_port,
            "items": [
                {"type": "send", "data": _packet_data(b"\x16\x03\x01\x00\x01")},
                {"type": "receive", "data": None},
            ],
            "truncated": False,
            "sourceScope": None,
        }
    )


def _endpoint_row(
    key: str,
    *,
    ips: list[str],
    ports: list[int],
    protocols: list[str],
    timeshift: float,
    request_count: int = 1,
    alert_count: int = 0,
    max_alert_severity: str | None = None,
) -> dict[str, Any]:
    is_address = key in ips
    return {
        "key": key,
        "host": None if is_address else key,
        "ips": ips,
        "ports": ports,
        "protocols": protocols,
        "source": "sample",
        "firstTimeshift": timeshift,
        "lastTimeshift": timeshift,
        "requestCount": request_count,
        "alertCount": alert_count,
        "maxAlertSeverity": max_alert_severity,
        "processIds": [],
        "attributionNote": None,
    }


def _endpoint_rows(state: SubmissionState) -> list[dict[str, Any]]:
    if not state.has_dynamic_report:
        return []
    severities = sorted(_THREAT_SEVERITY_LEVELS[seed.severity] for seed in state.network_threats)
    rows = [
        _endpoint_row(
            _C2_HOST,
            ips=[_C2_IP],
            ports=[443],
            protocols=["DNS", "HTTP", "TCP"],
            timeshift=0.5,
            request_count=3,
            alert_count=len(severities),
            max_alert_severity=str(severities[0]) if severities else None,
        ),
        _endpoint_row(
            "benign.example.com", ips=["198.51.100.1"], ports=[], protocols=["DNS"], timeshift=1.0
        ),
    ]
    for connection in [*build_tcp_connections(state), *build_udp_connections(state)]:
        if connection.destination_ip != _C2_IP:
            rows.append(
                _endpoint_row(
                    connection.destination_ip,
                    ips=[connection.destination_ip],
                    ports=[connection.destination_port],
                    protocols=[connection.protocol.upper()],
                    timeshift=connection.timeshift,
                )
            )
    return rows


def build_network_endpoints(state: SubmissionState, *, limit: int) -> NetworkEndpoints:
    """Build the endpoints of the network map, sample endpoints first."""
    rows = _endpoint_rows(state)
    return NetworkEndpoints.model_validate(
        {"items": rows[:limit], "total": len(rows), "truncated": len(rows) > limit}
    )


def _host_flow_payloads(state: SubmissionState, host: str) -> list[dict[str, Any]]:
    key = host.lower()
    empty_http: dict[str, Any] = {"methods": [], "samplePaths": []}
    if key == _C2_HOST:
        return [
            {
                "protocol": "TCP",
                "remoteIp": _C2_IP,
                "remotePort": 443,
                "localPort": 49712,
                "count": 1,
                "bytesSent": 1832,
                "bytesReceived": 6120,
                "firstTimeshift": 0.5,
                "lastTimeshift": 0.5,
                "processIds": [],
                **empty_http,
            },
            {
                "protocol": "HTTP",
                "remoteIp": _C2_IP,
                "remotePort": 443,
                "localPort": None,
                "count": 1,
                "bytesSent": None,
                "bytesReceived": None,
                "firstTimeshift": 0.75,
                "lastTimeshift": 0.75,
                "processIds": [],
                "methods": [{"method": "POST", "count": 1}],
                "samplePaths": [f"http://{_C2_HOST}/gate.php"],
            },
            {
                "protocol": "DNS",
                "remoteIp": None,
                "remotePort": None,
                "localPort": None,
                "count": 1,
                "bytesSent": None,
                "bytesReceived": None,
                "firstTimeshift": 0.5,
                "lastTimeshift": 0.5,
                "processIds": [],
                **empty_http,
            },
        ]
    endpoint = next((row for row in _endpoint_rows(state) if row["key"] == key), None)
    if endpoint is None:
        return []
    protocol = endpoint["protocols"][0]
    is_flow = protocol in ("TCP", "UDP")
    return [
        {
            "protocol": protocol,
            "remoteIp": endpoint["ips"][0] if protocol != "DNS" else None,
            "remotePort": endpoint["ports"][0] if endpoint["ports"] else None,
            "localPort": 49712 if is_flow else None,
            "count": 1,
            "bytesSent": 1832 if is_flow else None,
            "bytesReceived": 6120 if is_flow else None,
            "firstTimeshift": endpoint["firstTimeshift"],
            "lastTimeshift": endpoint["lastTimeshift"],
            "processIds": [],
            **empty_http,
        }
    ]


def _host_alert_payloads(state: SubmissionState, host: str) -> list[dict[str, Any]]:
    if host.lower() != _C2_HOST:
        return []
    groups: dict[tuple[str, int], int] = {}
    for seed in state.network_threats:
        group = (seed.signature, _THREAT_SEVERITY_LEVELS[seed.severity])
        groups[group] = groups.get(group, 0) + 1
    ordered = sorted(groups.items(), key=lambda item: item[0][1])
    return [
        {"signature": signature, "severity": severity, "count": count, "firstTimeshift": 0.5}
        for (signature, severity), count in ordered
    ]


def build_network_host_flows(
    state: SubmissionState, host: str, *, first: int, offset: int
) -> NetworkHostFlows:
    """Build one page of the flows of one endpoint. ``offset`` is the decoded cursor."""
    flows = _host_flow_payloads(state, host)
    page = flows[offset : offset + first]
    end = offset + len(page)
    totals = {"dnsQueries": 0, "httpRequests": 0, "tcpFlows": 0, "udpFlows": 0}
    total_keys = {"DNS": "dnsQueries", "HTTP": "httpRequests", "TCP": "tcpFlows", "UDP": "udpFlows"}
    for flow in flows:
        totals[total_keys[flow["protocol"]]] += flow["count"]
    return NetworkHostFlows.model_validate(
        {
            "flows": page,
            "totals": totals,
            "alerts": _host_alert_payloads(state, host),
            "pageInfo": {
                "endCursor": encode_host_flow_cursor(end) if page else None,
                "hasNextPage": end < len(flows),
            },
            "truncated": False,
        }
    )


def encode_host_flow_cursor(offset: int) -> str:
    """Encode a host flow page offset as an opaque cursor."""
    return base64.urlsafe_b64encode(f"hf:{offset}".encode()).decode("ascii").rstrip("=")


def decode_host_flow_cursor(cursor: str) -> int | None:
    """Decode a cursor of ``encode_host_flow_cursor()``. ``None`` when it is not valid."""
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    prefix, _, value = text.partition(":")
    if prefix != "hf" or not value.isdigit():
        return None
    return int(value)


def build_pdf_report_status(state: SubmissionState) -> PdfReportStatus:
    """Build the PDF report status response."""
    if state.current_status() != "completed":
        return PdfReportStatus.model_validate(
            {
                "status": "analysis_in_progress",
                "message": "Please wait for the analysis to finish before generating the PDF report.",
            }
        )
    if not state.pdf_report_ready:
        return PdfReportStatus.model_validate({"status": "queued", "retryAfterSeconds": 3})
    return PdfReportStatus.model_validate({"status": "ready"})


_AI_VERDICTS: dict[str, str] = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "benign": "benign",
    "unknown": "inconclusive",
}


def build_ai_report(state: SubmissionState) -> AiReport | AiReportPending:
    """Build the AI report: pending until the analysis completes.

    After ``regenerate_ai_report()`` the next read answers ``queued`` once, and
    the read after that returns the report with ``reason == "regenerate"``.
    """
    if state.current_status() != "completed":
        return AiReportPending.model_validate({"status": "waiting_for_analysis"})
    if state.ai_report_queued:
        state.ai_report_queued = False
        return AiReportPending.model_validate({"status": "queued"})
    verdict = _AI_VERDICTS[state.level]
    evidence = {"source": "submission", "ref": state.uuid, "label": "Submission"}
    return AiReport.model_validate(
        {
            "jobId": None,
            "status": "completed",
            "verdict": verdict,
            "confidence": "high",
            "agreesWithEngine": True,
            "family": None,
            "familyStatus": "none",
            "report": {
                "summary": {
                    "verdict": verdict,
                    "confidence": "high",
                    "text": f"The fake AI report for {state.filename}.",
                    "engineVerdict": state.level,
                    "agreesWithEngine": True,
                    "disagreementReason": None,
                },
                "classification": {
                    "family": {"name": None, "status": "none", "evidence": []},
                    "category": "other",
                    "impersonatedBrand": None,
                },
                "iocs": [
                    {
                        "value": seed.value,
                        "kind": seed.type,
                        "status": "confirmed",
                        "reason": "The IoC engine extracted the value.",
                        "evidence": [{"source": "ioc", "ref": seed.value, "label": "IoC"}],
                    }
                    for seed in state.iocs
                ],
                "techniques": [
                    {
                        "id": technique,
                        "name": technique,
                        "tactic": "Execution",
                        "origin": "engine",
                        "confidence": "high",
                        "evidence": [evidence],
                    }
                    for technique in state.mitre_techniques
                ],
                "attackFlow": {
                    "nodes": [
                        {
                            "id": "n1",
                            "kind": "process",
                            "label": state.filename,
                            "phase": "execution",
                            "evidence": evidence,
                        }
                    ],
                    "edges": [],
                },
                "narrative": [
                    {
                        "phase": "execution",
                        "text": f"{state.filename} started.",
                        "evidence": [evidence],
                    }
                ],
                "screenshots": [],
                "engineAgreement": [
                    {"engine": "dynamic", "reported": state.level, "agrees": True, "note": None}
                ],
                "recommendations": [{"kind": "hunting", "text": "Search for the file hash."}],
                "iocReview": None,
            },
            "updatedAt": state.updated_at.isoformat(),
            "reason": state.ai_report_reason,
            "error": None,
            "analysisFinalized": True,
        }
    )


def build_ai_report_regenerate_result() -> AiReportRegenerateResult:
    """Build the 202 answer of the AI report regenerate route."""
    return AiReportRegenerateResult.model_validate(
        {"status": "queued", "message": "AI report regeneration queued"}
    )


def _next_ai_report_quota_reset() -> datetime:
    tomorrow = datetime.now(timezone.utc).date() + timedelta(days=1)
    return datetime.combine(tomorrow, time.min, tzinfo=timezone.utc)


def build_url_analysis_response(state: SubmissionState) -> UrlAnalysisResponse:
    """Build the URL analysis report response."""
    target_url = state.url or "https://example.com"
    payload: dict[str, Any] = {
        "level": state.level,
        "status": state.current_status(),
        "jobId": url_analysis_job_id(state),
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
        "threatScore": _THREAT_SCORE_BY_LEVEL[state.level],
        "riskLevel": _RISK_LEVEL_BY_LEVEL[state.level],
        "privacyScore": 35,
        "privacyRiskLevel": "Medium",
        "privacyBreakdown": [
            {
                "factor": "trackers",
                "label": "Third-party trackers",
                "delta": 20,
                "detail": "5 trackers",
            }
        ],
        "verdictProvenance": {
            "rawVerdict": state.level,
            "quorumApplied": False,
            "allowlistApplied": False,
            "collectionState": "ok",
            "pass": "final" if state.current_status() == "completed" else "provisional",
        },
        "impersonationTarget": (
            {
                "brandName": "PayPal",
                "canonicalDomain": "paypal.com",
                "signals": ["favicon_match"],
                "confidence": "high",
            }
            if state.level == "malicious"
            else None
        ),
        "completeness": {
            "measuredSources": ["dns", "tls", "intel"],
            "skippedSources": [] if state.session_active() else ["browser"],
            "unavailableSources": [],
            "browserCollection": "complete" if state.session_active() else None,
        },
        "intelDetections": (
            [
                {
                    "source": "urlhaus",
                    "detectionType": "malware_url",
                    "severity": "high",
                    "details": state.threat_analysis_summary or "listed",
                }
            ]
            if state.level == "malicious"
            else []
        ),
        "metafields": dict(state.metafields) or None,
        "scoredAt": state.updated_at.isoformat(),
    }
    return UrlAnalysisResponse.model_validate(payload)


_THREAT_SCORE_BY_LEVEL: dict[str, int] = {
    "unknown": 0,
    "benign": 5,
    "suspicious": 45,
    "malicious": 88,
}

_RISK_LEVEL_BY_LEVEL: dict[str, str] = {
    "unknown": "Unknown",
    "benign": "Low",
    "suspicious": "Medium",
    "malicious": "Critical",
}


def build_url_analysis_session(state: SubmissionState) -> UrlAnalysisSession:
    """Build the interactive browser session state for a URL submission."""
    active = state.session_active()
    started_at = int(state.created_at.timestamp() * 1000)
    duration = state.session_duration_seconds or 120
    payload: dict[str, Any] = {
        "state": "running" if active else "unavailable",
        "collectionStatus": "collecting" if active else "unavailable",
        "recordingStatus": "recording" if active else "unavailable",
        "queuePosition": None,
        "vncAvailable": active,
        "reportAvailable": state.current_status() == "completed",
        "startedAt": started_at if active else None,
        "readyAt": started_at + 4000 if active else None,
        "expiresAt": started_at + duration * 1000 if active else None,
        "finishedAt": None,
        "failureCode": None,
        "extensionsUsed": 0,
        "extensionsMax": 3,
        "sessionConfig": (
            {
                "deviceProfileId": device_preset_base_key_for(state.session_device_preset_id),
                "networkConfigId": state.session_network_config_id,
                "networkConfigSource": "submit" if state.session_network_config_id else None,
                "networkConfigName": _network_config_name(state.session_network_config_id),
                "sessionDurationSeconds": state.session_duration_seconds,
                "devicePresetId": state.session_device_preset_id,
                "devicePresetName": state.session_device_preset_name,
            }
            if active
            else None
        ),
        "link": (f"wss://fake.threat.zone/vnc/{state.uuid}?token=fake-session-token")
        if active
        else None,
        "expired": not active,
    }
    return UrlAnalysisSession.model_validate(payload)


def _network_config_name(config_id: str | None) -> str | None:
    if config_id is None:
        return None
    for item in build_network_configs().items:
        if item.id == config_id:
            return item.name
    return None


URL_SCORE_EVIDENCE_TEXT_LIMIT = 8192
URL_BROWSER_PUBLIC_SECTIONS: tuple[str, ...] = ("overview", "findings", "tls", "network-summary")
_URL_BROWSER_NETWORK_SUMMARY_FIELDS: tuple[str, ...] = ("redirects", "domainTable", "ipTable")
FAKE_BROWSER_COOKIE_VALUE = "fake-session-cookie-value"
FAKE_BROWSER_BODY_TEXT = "<html>fake response body</html>"


def url_analysis_job_id(state: SubmissionState) -> str:
    """Return the job ID of the current URL analysis run. A restart starts a new run."""
    seed = f"url-job::{state.uuid}::{state.report_restarts}"
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:24]


def url_analysis_scored_at(state: SubmissionState) -> str:
    """Return the scoring time of the current run as the API writes it."""
    return state.updated_at.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _browser_manifest_hash(state: SubmissionState) -> str:
    return _deterministic_hex(f"url-browser::{url_analysis_job_id(state)}")


def _deterministic_hex(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _url_score_evidence_values(state: SubmissionState) -> dict[tuple[str, str], dict[str, Any]]:
    target_url = state.url or "https://example.com"
    values: dict[tuple[str, str], dict[str, Any]] = {
        ("domain-age", "whois"): {
            "domainName": _domain_from_url(target_url),
            "registrar": "Test Registrar",
            "creationDate": "2020-01-01",
        },
    }
    if state.level == "malicious":
        values[("intel-hit", "intel-urlhaus")] = {
            "source": "urlhaus",
            "detectionType": "malware_url",
            "severity": "high",
        }
    return values


def _url_score_indicators(state: SubmissionState) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = [
        {
            "id": "domain-age",
            "ruleId": "whois.domain_age",
            "source": "whois",
            "family": "reputation",
            "title": "Domain age",
            "reason": "The domain was registered before the analysis.",
            "availability": "measured",
            "confidence": "high",
            "originalRuleScore": 1,
            "weightedPoints": 5,
            "disposition": "contributing",
            "suppressedBy": None,
            "evidenceRefs": [{"kind": "report", "id": "whois", "available": True}],
        }
    ]
    if state.level == "malicious":
        indicators.append(
            {
                "id": "intel-hit",
                "ruleId": "intel.urlhaus",
                "source": "intel",
                "family": "intel",
                "title": "Threat intelligence hit",
                "reason": "URLhaus lists the URL.",
                "availability": "measured",
                "confidence": "high",
                "originalRuleScore": 8,
                "weightedPoints": 83,
                "disposition": "contributing",
                "suppressedBy": None,
                "evidenceRefs": [
                    {"kind": "intel", "id": "intel-urlhaus", "available": True},
                    {"kind": "network", "id": "net-0", "available": False},
                ],
            }
        )
    return indicators


def build_url_analysis_indicators(state: SubmissionState) -> UrlAnalysisIndicators:
    """Build the URL score explanation. A run that is not complete reports ``pending``."""
    if state.current_status() != "completed":
        return UrlAnalysisIndicators.model_validate(
            {"state": "pending", "unavailableReason": None, "snapshot": None}
        )
    score = _THREAT_SCORE_BY_LEVEL[state.level]
    job_id = url_analysis_job_id(state)
    payload: dict[str, Any] = {
        "state": "available",
        "unavailableReason": None,
        "snapshot": {
            "schemaVersion": 1,
            "scoringVersion": "url-score-v3",
            "jobId": job_id,
            "pass": "final",
            "scoredAt": url_analysis_scored_at(state),
            "browserSnapshot": {"jobId": job_id, "manifestHash": _browser_manifest_hash(state)},
            "threatScore": score,
            "verdict": state.level,
            "indicators": _url_score_indicators(state),
            "aggregation": {
                "highPoints": score,
                "heuristicPoints": 0,
                "reputationCredits": [],
                "creditScope": "heuristic",
                "effectiveCredit": 0,
                "scoreBeforeClamp": score,
                "scoreAfterClamp": score,
                "roundingAdjustment": 0,
                "impersonationFloorAdjustment": 0,
            },
            "verdictAdjustments": [],
        },
    }
    return UrlAnalysisIndicators.model_validate(payload)


def url_score_evidence_ref_available(
    state: SubmissionState, indicator_id: str, reference_id: str
) -> bool | None:
    """Return the ``available`` flag of the reference, or None when the reference is unknown."""
    for indicator in _url_score_indicators(state):
        if indicator["id"] != indicator_id:
            continue
        for ref in indicator["evidenceRefs"]:
            if ref["id"] == reference_id:
                return bool(ref["available"])
    return None


def build_url_analysis_indicator_evidence(
    state: SubmissionState, indicator_id: str, reference_id: str
) -> UrlAnalysisIndicatorEvidence:
    """Build one evidence item as pretty-printed JSON, cut at the API text limit."""
    value = _url_score_evidence_values(state).get((indicator_id, reference_id))
    if value is None:
        return UrlAnalysisIndicatorEvidence.model_validate(
            {"state": "unavailable", "text": None, "truncated": False}
        )
    text = json.dumps(value, indent=2)
    return UrlAnalysisIndicatorEvidence.model_validate(
        {
            "state": "available",
            "text": text[:URL_SCORE_EVIDENCE_TEXT_LIMIT],
            "truncated": len(text) > URL_SCORE_EVIDENCE_TEXT_LIMIT,
        }
    )


def _url_browser_stored_sections(state: SubmissionState) -> dict[str, dict[str, Any]]:
    target_url = state.final_url or state.url or "https://example.com"
    domain = _domain_from_url(target_url)
    return {
        "overview": {
            "finalUrl": target_url,
            "pageTitle": "Test Page",
            "stats": {"requests": 3, "domains": 1},
            "technologies": [],
        },
        "findings": {"securityFindings": [], "jsFindings": [], "browserChecks": []},
        "tls": {"tls": {"protocol": "TLS 1.3", "issuer": "Fake CA", "sanList": [domain]}},
        "network-summary": {
            "redirects": [
                {
                    "fromUrl": f"http://{domain}/",
                    "toUrl": target_url,
                    "status": 301,
                    "method": "GET",
                }
            ],
            "domainTable": [
                {
                    "domain": domain,
                    "requests": 3,
                    "bytes": 1200,
                    "ips": ["192.0.2.20"],
                    "isThirdParty": False,
                    "isTracker": False,
                }
            ],
            "ipTable": [
                {
                    "ip": "192.0.2.20",
                    "requests": 3,
                    "bytes": 1200,
                    "domains": [domain],
                    "country": None,
                    "countryCode": None,
                    "org": None,
                }
            ],
            "entries": [
                {
                    "url": target_url,
                    "responseBody": FAKE_BROWSER_BODY_TEXT,
                    "requestHeaders": {"cookie": f"sid={FAKE_BROWSER_COOKIE_VALUE}"},
                }
            ],
            "cookies": [{"name": "sid", "value": FAKE_BROWSER_COOKIE_VALUE}],
        },
    }


def build_url_analysis_browser_section(
    state: SubmissionState, section: str
) -> UrlAnalysisBrowserSection:
    """Build one approved browser section. ``network-summary`` keeps only the summary tables."""
    data = _url_browser_stored_sections(state)[section]
    if section == "network-summary":
        data = {
            field_name: data.get(field_name, [])
            for field_name in _URL_BROWSER_NETWORK_SUMMARY_FIELDS
        }
    return UrlAnalysisBrowserSection.model_validate(
        {
            "section": section,
            "jobId": url_analysis_job_id(state),
            "revision": _browser_manifest_hash(state),
            "updatedAt": int(state.updated_at.timestamp() * 1000),
            "data": data,
        }
    )


def build_message(text: str) -> Message:
    """Build a one-line acknowledgement returned by an action endpoint."""
    return Message.model_validate({"message": text})


DEVICE_PRESETS: list[dict[str, Any]] = [
    {
        "id": "68b0000000000000000000a2",
        "name": "Desktop",
        "category": "desktop",
        "baseKey": "desktop-chrome",
        "default": True,
    },
    {
        "id": "68b0000000000000000000a1",
        "name": "iPhone 15 Pro",
        "category": "mobile",
        "baseKey": "iphone-15-pro",
        "default": False,
    },
]


def build_device_presets() -> list[DevicePresetOption]:
    """Build the device-preset catalog served by /config/device-presets."""
    return [DevicePresetOption.model_validate(item) for item in DEVICE_PRESETS]


def device_preset_name_for(preset_id: str | None) -> str | None:
    """Resolve a device-preset id to its display name."""
    return _device_preset_field(preset_id, "name")


def device_preset_base_key_for(preset_id: str | None) -> str | None:
    """Resolve a device-preset id to the base browser profile it derives from."""
    return _device_preset_field(preset_id, "baseKey")


def _device_preset_field(preset_id: str | None, key: str) -> str | None:
    if preset_id is None:
        return None
    for item in DEVICE_PRESETS:
        if item["id"] == preset_id:
            return str(item[key])
    return None


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
                "kind": "screenshot",
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
                "aiReportCount": 0,
                "aiReportResetsAt": _next_ai_report_quota_reset().isoformat(),
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
                "aiReportLimit": 20,
            },
            "permissions": {
                "downloadSample": True,
                "htmlReport": True,
                "stixReport": True,
                "pdfReport": True,
                "downloadReport": True,
                "aiReport": True,
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
            "active": True,
            "accessible": True,
            "options": None,
        },
        {
            "key": "internet_connection",
            "label": "Internet Connection",
            "description": "Allow internet connection",
            "type": "boolean",
            "default": True,
            "active": True,
            "accessible": True,
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
            "active": True,
            "accessible": True,
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
        {
            "key": "w10_64",
            "name": "Windows 10 x64",
            "platform": "windows",
            "default": True,
            "active": True,
            "accessible": True,
        },
        {
            "key": "w11_64",
            "name": "Windows 11 x64",
            "platform": "windows",
            "default": False,
            "active": True,
            "accessible": True,
        },
        {
            "key": "ub22",
            "name": "Ubuntu 22.04",
            "platform": "linux",
            "default": False,
            "active": True,
            "accessible": True,
        },
    ]
    return [EnvironmentOption.model_validate(item) for item in items]


def build_network_configs() -> NetworkConfigListResponse:
    """Build the workspace's available network configurations."""
    return NetworkConfigListResponse.model_validate(
        {
            "items": [
                {
                    "id": "cfg1",
                    "name": "Corp Proxy",
                    "type": "proxy",
                    "protocol": "socks5",
                    "host": "1.2.3.4",
                    "port": 1080,
                    "username": "u",
                    "hasConfigFile": False,
                    "createdAt": "2026-06-01T00:00:00.000Z",
                    "updatedAt": "2026-06-01T00:00:00.000Z",
                }
            ]
        }
    )


_TIER_BY_LEVEL: dict[str, str] = {
    "malicious": "Malicious",
    "suspicious": "Suspicious",
    "benign": "Benign",
    "unknown": "Not Measured",
}
_SCORE_BY_LEVEL: dict[str, int] = {"malicious": 92, "suspicious": 45, "benign": 5, "unknown": 0}


def build_verdict(state: SubmissionState) -> Verdict:
    """Build the Windows V2 verdict narrative and story of a dynamic report."""
    tier = _TIER_BY_LEVEL[state.level]
    score = _SCORE_BY_LEVEL[state.level]
    headline = f"{tier} ({score}/100): the sample connected to a remote host."
    return Verdict.model_validate(
        {
            "format": "windows-v2-worker-1",
            "score": score,
            "tier": tier,
            "summary": headline,
            "narrative": {
                "headline": headline,
                "sequence": [
                    {
                        "seq": 3,
                        "tOffsetS": 1.2,
                        "pid": 1508,
                        "image": "malware.exe",
                        "text": "Connected to 192.0.2.10:443.",
                    }
                ],
                "decisive": [
                    {"source": "policy:win.network.c2_policy", "text": "Remote connection."}
                ],
                "tierReason": "Owner policy floor.",
                "notObserved": ["no persistence request"],
                "wouldRaise": ["an upload of collected data"],
                "wouldLower": [],
                "coverageNote": None,
                "text": headline,
            },
            "story": {
                "summary": ["malware.exe connected to 192.0.2.10:443."],
                "truncated": False,
                "headline": {
                    "text": "malware.exe connected to a remote host",
                    "parts": [{"type": "process", "value": "malware.exe"}],
                },
                "steps": [
                    {
                        "tOffsetS": 1.5,
                        "process": {"image": "malware.exe", "pid": 1508},
                        "category": "network",
                        "text": "Connected to 192.0.2.10:443.",
                        "count": 3,
                        "evidenceSeqs": [12, 13],
                        "key": True,
                        "parts": [
                            {"type": "text", "value": "Connected to "},
                            {"type": "constant", "value": "192.0.2.10:443"},
                        ],
                        "command": "C:\\Users\\test\\malware.exe --connect 192.0.2.10",
                    }
                ],
            },
        }
    )


def build_run_notes(state: SubmissionState) -> RunNotes:
    """Build the run notes of a dynamic report. The Java output is the full stored text."""
    return RunNotes.model_validate(
        {
            "javaOutput": {
                "summary": "The Java program stopped with an uncaught exception: no config",
                "error": "java.lang.IllegalStateException: no config",
                "cause": None,
                "text": (
                    "Starting loader\nbot token 123456:ABCDEF\n"
                    'Exception in thread "main" java.lang.IllegalStateException: no config\n'
                ),
                "size": 96,
                "truncated": False,
            },
            "analysisCutShort": {
                "basis": "unfinished_download",
                "endedAtS": 540,
                "requestedWindowS": 540,
                "text": "The analysis window ended while the sample was still downloading.",
                "transfer": {
                    "url": "cdn.example.com/payload.bin",
                    "receivedBytes": 1048576,
                    "declaredBytes": 4194304,
                },
            },
            "networkNotes": ["The sandbox network refused 3 outgoing mail connections."],
            "submissionHints": [],
            "runNotes": [
                {
                    "code": "sample_exited_early",
                    "text": "The submitted program exited on its own 1.1 s after it started.",
                }
            ],
            "isDumpCollectorActivated": bool(state.metafields.get("dump_collector", False)),
        }
    )


def build_annotations(state: SubmissionState) -> Annotations:
    """Build the annotations view of the caller workspace."""
    return Annotations.model_validate(
        {
            "submissionUuid": state.uuid,
            "pins": [dict(pin) for pin in state.annotation_pins],
            "note": dict(state.annotation_note) if state.annotation_note is not None else None,
        }
    )


def build_previous_run(previous_run_uuid: str | None) -> PreviousRun:
    """Build the previous-run lookup result."""
    return PreviousRun.model_validate({"previousRunUuid": previous_run_uuid})


_COMPARE_LIST_CAP = 200
_LEVEL_RANK: dict[str, int] = {"benign": 1, "suspicious": 2, "malicious": 3}


def _compare_detections(state: SubmissionState) -> dict[str, dict[str, str]]:
    detections: dict[str, dict[str, str]] = {}
    for seed in state.indicators:
        title = f"Indicator {seed.attack_code}"
        current = detections.get(title)
        if current is None or _LEVEL_RANK[seed.level] > _LEVEL_RANK[current["level"]]:
            detections[title] = {"title": title, "level": seed.level}
    return detections


def _compare_techniques(state: SubmissionState) -> dict[str, str]:
    if not state.has_dynamic_report:
        return {}
    return {code.upper(): code.upper() for code in state.mitre_techniques}


def _compare_iocs(state: SubmissionState) -> dict[str, dict[str, str]]:
    return {
        f"{seed.type.lower()}:{seed.value.lower()}": {
            "value": seed.value,
            "category": seed.type.lower(),
        }
        for seed in state.iocs
    }


def _compare_dropped_files(state: SubmissionState) -> dict[str, dict[str, str | None]]:
    if not state.has_dynamic_report:
        return {}
    return {
        (sha256 or path.lower()): {"path": path, "sha256": sha256}
        for path, sha256 in state.dropped_files
    }


def _diff(current: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    added = [value for key, value in current.items() if key not in other]
    removed = [value for key, value in other.items() if key not in current]
    return {
        "added": added[:_COMPARE_LIST_CAP],
        "removed": removed[:_COMPARE_LIST_CAP],
        "addedTotal": len(added),
        "removedTotal": len(removed),
    }


def build_run_comparison(state: SubmissionState, other: SubmissionState) -> RunComparison:
    """Build the difference between two runs, keyed as the real API keys them."""
    return RunComparison.model_validate(
        {
            "submissionUuid": state.uuid,
            "otherSubmissionUuid": other.uuid,
            "detections": _diff(_compare_detections(state), _compare_detections(other)),
            "techniques": _diff(_compare_techniques(state), _compare_techniques(other)),
            "iocs": _diff(_compare_iocs(state), _compare_iocs(other)),
            "droppedFiles": _diff(_compare_dropped_files(state), _compare_dropped_files(other)),
        }
    )


IOC_EXPORT_FORMATS: frozenset[str] = frozenset({"csv", "text", "stix", "misp"})
_IOC_EXPORT_TYPES: tuple[str, ...] = ("ip", "domain", "url", "sha256")


@dataclass(frozen=True)
class IocExportFile:
    """One IoC export file of the fake download route."""

    content: bytes
    content_type: str
    filename: str


def _ioc_export_rows(state: SubmissionState) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for seed in state.iocs:
        ioc_type = seed.type.lower()
        row = (ioc_type, seed.value)
        if ioc_type in _IOC_EXPORT_TYPES and row not in rows:
            rows.append(row)
    return rows


def _defang(ioc_type: str, value: str) -> str:
    if ioc_type == "sha256":
        return value
    return value.replace("http", "hxxp", 1).replace(".", "[.]")


def build_ioc_export(state: SubmissionState, export_format: str) -> IocExportFile:
    """Build the IoC export file in one of the four formats."""
    rows = _ioc_export_rows(state)
    if export_format == "csv":
        lines = ["type,value,defanged,sources"]
        lines += [f"{kind},{value},{_defang(kind, value)},dynamic" for kind, value in rows]
        return IocExportFile(
            content=("\n".join(lines) + "\n").encode("utf-8"),
            content_type="text/csv; charset=utf-8",
            filename=f"threatzone_iocs_{state.uuid}.csv",
        )
    if export_format == "text":
        text = "".join(f"{_defang(kind, value)}\n" for kind, value in rows)
        return IocExportFile(
            content=text.encode("utf-8"),
            content_type="text/plain; charset=utf-8",
            filename=f"threatzone_iocs_{state.uuid}.txt",
        )
    if export_format == "stix":
        bundle = {
            "type": "bundle",
            "id": f"bundle--{state.uuid}",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{_deterministic_hex(f'{state.uuid}:{kind}:{value}')[:32]}",
                    "pattern_type": "stix",
                    "pattern": f"[{kind}:value = '{value}']",
                }
                for kind, value in rows
            ],
        }
        return IocExportFile(
            content=json.dumps(bundle).encode("utf-8"),
            content_type="application/json",
            filename=f"threatzone_iocs_stix-2.1_{state.uuid}.json",
        )
    event = {
        "Event": {
            "uuid": state.uuid,
            "info": f"Threat.Zone IoCs of {state.uuid}",
            "Attribute": [
                {"type": "ip-dst" if kind == "ip" else kind, "value": value} for kind, value in rows
            ],
        }
    }
    return IocExportFile(
        content=json.dumps(event).encode("utf-8"),
        content_type="application/json",
        filename=f"threatzone_iocs_misp_{state.uuid}.json",
    )
