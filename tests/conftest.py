"""Pytest fixtures for Threat.Zone Python SDK tests.

These fixtures hold *canonical* JSON payloads matching the Threat.Zone Public API
DTOs as of Phase 3 of the public-api rework. Every payload is what the SDK is
expected to receive on the wire.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def api_key() -> str:
    return "arrakis_2042"


@pytest.fixture
def base_url() -> str:
    return "https://test.threat.zone"


@pytest.fixture
def submission_uuid() -> str:
    return "11111111-2222-3333-4444-555555555555"


ResponseFactory = Callable[..., httpx.Response]


@pytest.fixture
def mock_response() -> ResponseFactory:
    """Helper for building httpx.Response instances in tests."""

    def _create(
        status_code: int = 200,
        json_data: Any = None,
        content: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        if json_data is not None:
            content = json.dumps(json_data).encode()
            headers = {**(headers or {}), "content-type": "application/json"}
        return httpx.Response(status_code=status_code, content=content, headers=headers or {})

    return _create


# ---------------------------------------------------------------------------
# /me payload (matches src/threatzone/types/me.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_user_info() -> dict[str, Any]:
    return {
        "userInfo": {
            "email": "feyd@harkonnen.com",
            "fullName": "Feyd Rautha",
            "workspace": {
                "name": "Harkonnens",
                "alias": "spice-maniacs",
                "private": False,
                "type": "personal",
            },
            "limitsCount": {
                "apiRequestCount": 50,
                "dailySubmissionCount": 10,
                "concurrentSubmissionCount": 2,
                "aiReportCount": 3,
                "aiReportResetsAt": "2026-10-15T00:00:00.000Z",
            },
        },
        "plan": {
            "planName": "Professional",
            "startTime": "2024-01-01",
            "endTime": "2024-12-31",
            "subsTime": "yearly",
            "fileLimits": {
                "extensions": [".exe", ".dll", ".pdf"],
                "fileSize": "100 MB",
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
                "stixReport": False,
                "pdfReport": True,
                "downloadReport": False,
                "aiReport": True,
            },
        },
        "modules": [
            {
                "moduleId": "mod-1",
                "moduleName": "cdr",
                "startTime": "2024-01-01",
                "endTime": "Unlimited",
            }
        ],
    }


# ---------------------------------------------------------------------------
# /config payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_environments() -> list[dict[str, Any]]:
    return [
        {
            "key": "w10_x64",
            "name": "Windows 10 64-bit",
            "platform": "windows",
            "default": True,
            "active": True,
            "accessible": True,
        },
        {
            "key": "w11_x64",
            "name": "Windows 11 64-bit",
            "platform": "windows",
            "default": False,
            "active": True,
            "accessible": True,
        },
        {
            "key": "ubuntu_22",
            "name": "Ubuntu 22.04",
            "platform": "linux",
            "default": False,
            "active": True,
            "accessible": True,
        },
    ]


@pytest.fixture
def sample_network_config() -> dict[str, Any]:
    return {
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


@pytest.fixture
def sample_metafields() -> dict[str, list[dict[str, Any]]]:
    return {
        "sandbox": [
            {
                "key": "timeout",
                "label": "Timeout",
                "description": "Analysis timeout in seconds",
                "type": "select",
                "default": 120,
                "active": True,
                "accessible": True,
                "options": [
                    {"value": 60, "label": "60 Seconds", "accessible": True},
                    {"value": 120, "label": "120 Seconds", "accessible": True},
                    {"value": 300, "label": "300 Seconds", "accessible": False},
                ],
            }
        ],
        "static": [],
        "cdr": [],
        "url": [],
        "open_in_browser": [
            {
                "key": "timeout",
                "label": "Browser Timeout",
                "description": "Browser execution timeout in seconds",
                "type": "number",
                "default": 120,
                "active": True,
                "accessible": True,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Submissions payloads (matches src/threatzone/types/submissions.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_submission_created() -> dict[str, Any]:
    return {
        "uuid": "sub-new-123",
        "message": "Submission created successfully",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }


@pytest.fixture
def sample_report_status_completed() -> dict[str, Any]:
    return {
        "type": "dynamic",
        "status": "completed",
        "level": "malicious",
        "score": 95,
        "format": "v2",
        "duration": 0.2,
        "operatingSystem": {"name": "Windows 10", "platform": "windows"},
    }


@pytest.fixture
def sample_report_status_in_progress() -> dict[str, Any]:
    return {
        "type": "dynamic",
        "status": "in_progress",
        "level": None,
        "score": None,
        "duration": None,
    }


@pytest.fixture
def sample_submission_overview() -> dict[str, Any]:
    return {
        "status": "completed",
        "jobs": {"total": 3, "succeeded": 2, "failed": 0, "skipped": 1, "finished": 3},
    }


@pytest.fixture
def sample_indicators_rollup() -> dict[str, Any]:
    return {
        "levels": {"malicious": 5, "suspicious": 3, "benign": 2},
        "artifactCount": 7,
    }


@pytest.fixture
def sample_submission_list_item(
    sample_report_status_completed: dict[str, Any],
    sample_submission_overview: dict[str, Any],
    sample_indicators_rollup: dict[str, Any],
) -> dict[str, Any]:
    return {
        "uuid": "sub-789",
        "filename": "test.exe",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "level": "malicious",
        "type": "file",
        "private": False,
        "tags": [{"type": "malware", "value": "trojan"}],
        "reports": [sample_report_status_completed],
        "mimetype": "application/octet-stream",
        "size": 1024,
        "overview": sample_submission_overview,
        "indicators": sample_indicators_rollup,
        "createdAt": "2024-01-15T10:30:00Z",
    }


@pytest.fixture
def sample_paginated_submissions(
    sample_submission_list_item: dict[str, Any],
) -> dict[str, Any]:
    return {
        "items": [sample_submission_list_item],
        "total": 1,
        "page": 1,
        "limit": 20,
        "totalPages": 1,
    }


@pytest.fixture
def sample_submission(
    sample_report_status_completed: dict[str, Any],
    sample_submission_overview: dict[str, Any],
    sample_indicators_rollup: dict[str, Any],
) -> dict[str, Any]:
    static_completed = {
        "type": "static",
        "status": "completed",
        "level": "suspicious",
        "score": 70,
    }
    return {
        "uuid": "sub-789",
        "type": "file",
        "filename": "test.exe",
        "url": None,
        "hashes": {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "file": {
            "name": "test.exe",
            "size": 1024,
            "extension": ".exe",
            "mimetype": "application/octet-stream",
            "isMimetypeChecked": True,
            "entrypoint": None,
            "source": {"type": "upload", "url": None},
        },
        "level": "malicious",
        "score": 78.5,
        "family": "Sheetrat",
        "private": False,
        "tags": [{"type": "malware", "value": "trojan"}],
        "reports": [sample_report_status_completed, static_completed],
        "overview": sample_submission_overview,
        "indicators": sample_indicators_rollup,
        "mitreTechniques": ["T1547.001", "T1071.001"],
        "createdAt": "2024-01-15T10:30:00Z",
        "updatedAt": "2024-01-15T11:00:00Z",
    }


@pytest.fixture
def sample_score_breakdown() -> dict[str, Any]:
    return {
        "decidingLayer": "indicator_mean",
        "verdict": "Malicious",
        "score": 78.5,
        "cap": 95,
        "contributors": [
            {
                "source": "dynamic_scan",
                "indicatorId": "ransomware-shadow-copy-delete",
                "title": "Deletes volume shadow copies",
                "points": 95,
                "level": "malicious",
            },
            {
                "source": "static_scan",
                "indicatorId": None,
                "title": "Packed executable",
                "points": 62.5,
                "level": "suspicious",
            },
        ],
        "whatWouldChange": [
            "One malicious finding removes the benign findings from the mean score.",
        ],
    }


@pytest.fixture
def sample_submission_detail(
    sample_submission: dict[str, Any],
    sample_score_breakdown: dict[str, Any],
) -> dict[str, Any]:
    reports = [dict(report) for report in sample_submission["reports"]]
    reports[0]["metafields"] = {"Work Path": "Desktop", "Enable Memory Dumps": "Enabled"}
    reports[1]["metafields"] = None
    return {
        **sample_submission,
        "file": {
            **sample_submission["file"],
            "history": {
                "filenames": ["test.exe", "invoice.exe"],
                "lastReceivedAt": 1718447400000,
            },
        },
        "tags": [
            {"type": "malware", "value": "trojan", "origin": "yara", "author": "system"},
            {"type": "campaign", "value": "q3", "origin": None, "author": "user"},
        ],
        "reports": reports,
        "overview": {**sample_submission["overview"], "duration": 42.7},
        "scoreBreakdown": sample_score_breakdown,
    }


# ---------------------------------------------------------------------------
# Indicators surface payloads (matches src/threatzone/types/indicators.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_indicator_levels() -> dict[str, int]:
    return {"malicious": 5, "suspicious": 3, "benign": 2}


@pytest.fixture
def sample_indicator() -> dict[str, Any]:
    return {
        "id": "ind-1",
        "name": "Creates persistence",
        "description": "Creates registry key for persistence",
        "category": ["evasion", "persistence"],
        "level": "malicious",
        "score": 80,
        "pids": [1234, 5678],
        "attackCodes": ["T1547.001"],
        "eventIds": [42, 43],
        "syscallLineNumbers": [12, 100],
        "author": "system",
    }


@pytest.fixture
def sample_indicator_v2(sample_indicator: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_indicator,
        "summary": "word.exe hollowed svchost.exe and resumed it.",
        "scoreMaximum": 100,
        "pidGens": [1, 2],
        "ruleSource": "behavior:process_hollowing",
        "whatHappened": "word.exe started svchost.exe suspended and replaced its memory.",
        "whyItMatters": "Malware uses process hollowing to run code in a trusted process.",
        "whyThisTier": "The write and the resume came from the same process.",
        "notObserved": ["No network connection from svchost.exe"],
        "outcome": "svchost.exe ran the injected code.",
        "scoreNote": "Score: base 90 x confidence 1.05 = 95 (cap 95).",
        "scoreFactors": ["base 90", "confidence 1.05"],
        "scoreResult": 95,
        "scoreCap": 95,
        "related": [
            {
                "eventId": 1024,
                "signalId": "sig-0012",
                "text": "word.exe wrote C:\\Users\\analyst\\AppData\\Local\\Temp\\a.dll",
                "tOffsetS": 4.2,
                "actor": {"image": "word.exe", "pid": 3448},
            },
            {
                "eventId": None,
                "signalId": "sig-0013",
                "text": "svchost.exe resumed",
                "tOffsetS": None,
                "actor": None,
            },
        ],
        "actor": {
            "image": "word.exe",
            "pid": 3448,
            "pidGen": 1,
            "lineage": "explorer.exe > word.exe",
        },
        "target": {"kind": "process", "value": "svchost.exe"},
        "tOffsetS": 4.2,
        "spanS": 1.5,
        "occurrences": 3,
    }


@pytest.fixture
def sample_overview_indicator(sample_indicator: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_indicator,
        "id": "",
        "category": ["dynamic_scan"],
        "findingSource": "dynamic_scan",
        "artifacts": ["507f1f77bcf86cd799439015"],
        "dynamicIndicatorId": "507f1f77bcf86cd799439011",
    }


@pytest.fixture
def sample_indicators_response(
    sample_indicator: dict[str, Any],
    sample_indicator_levels: dict[str, int],
) -> dict[str, Any]:
    return {
        "items": [sample_indicator],
        "total": 1,
        "page": 1,
        "limit": 20,
        "totalPages": 1,
        "levels": sample_indicator_levels,
    }


@pytest.fixture
def sample_ioc() -> dict[str, Any]:
    return {
        "type": "domain",
        "value": "malware.example.com",
        "artifacts": ["art-1"],
    }


@pytest.fixture
def sample_iocs_response(sample_ioc: dict[str, Any]) -> dict[str, Any]:
    return {"items": [sample_ioc], "total": 1, "page": 1, "limit": 20, "totalPages": 1}


@pytest.fixture
def sample_yara_rule() -> dict[str, Any]:
    return {
        "rule": "Trojan_Generic",
        "category": "malicious",
        "artifacts": ["art-1", "art-2"],
    }


@pytest.fixture
def sample_yara_rules_response(sample_yara_rule: dict[str, Any]) -> dict[str, Any]:
    return {"items": [sample_yara_rule], "total": 1, "page": 1, "limit": 20, "totalPages": 1}


@pytest.fixture
def sample_extracted_config() -> dict[str, Any]:
    return {
        "family": "AgentTesla",
        "config": {"c2": "http://evil.com", "version": "1.0"},
        "c2s": ["http://evil.com"],
        "artifacts": ["art-1"],
    }


@pytest.fixture
def sample_extracted_configs_response(
    sample_extracted_config: dict[str, Any],
) -> dict[str, Any]:
    return {"items": [sample_extracted_config], "total": 1}


@pytest.fixture
def sample_artifact() -> dict[str, Any]:
    return {
        "id": "art-1",
        "filename": "dropped.dll",
        "size": 2048,
        "type": "sample",
        "source": "memory",
        "hashes": {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        },
        "tags": ["dropper"],
    }


@pytest.fixture
def sample_artifacts_response(sample_artifact: dict[str, Any]) -> dict[str, Any]:
    return {"items": [sample_artifact], "total": 1}


@pytest.fixture
def sample_artifact_v2(sample_artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_artifact,
        "id": "507f1f77bcf86cd799439015",
        "source": "dynamic_report",
        "processAttribution": None,
        "analysisStatus": "skipped",
        "analysisTrigger": "auto",
        "analysisReason": "Artifact exceeds the maximum file size supported for engine analysis.",
        "downloadLink": (
            "/public-api/submissions/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            "/download/artifact/507f1f77bcf86cd799439015"
        ),
    }


@pytest.fixture
def sample_artifact_jobs_response() -> dict[str, Any]:
    return {
        "items": [
            {"engineType": "static_scan", "status": "success", "errorCode": None},
            {"engineType": "ioc_extractor", "status": "failed", "errorCode": "JOB_DEAD_LETTERED"},
            {"engineType": "config_extractor", "status": "skipped", "errorCode": "JOB_SKIPPED"},
        ]
    }


@pytest.fixture
def all_artifact_types() -> list[str]:
    return [
        "sample",
        "compressed_file_entry",
        "malware_config",
        "memory_dump",
        "file_dump",
        "pcap",
        "deobfuscated_code",
        "process_dump",
        "unpacked_file",
        "yara_rule",
        "unknown",
        "dropped_file",
        "downloaded_file",
        "screenshot",
    ]


@pytest.fixture
def sample_overview_summary() -> dict[str, Any]:
    return {
        "score": 84.0,
        "family": "Sheetrat",
        "indicators": {
            "total": 10,
            "levels": {"malicious": 5, "suspicious": 3, "benign": 2},
        },
        "behaviorEventCount": 200,
        "syscallCount": 1500,
        "iocCount": 25,
        "yaraRuleCount": 5,
        "configCount": 2,
        "artifactCount": 7,
        "mitreTechniqueCount": 4,
        "network": {
            "dnsCount": 15,
            "httpCount": 42,
            "tcpCount": 30,
            "udpCount": 5,
            "threatCount": 3,
        },
    }


# ---------------------------------------------------------------------------
# Network payloads (matches src/threatzone/types/network.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_network_summary() -> dict[str, Any]:
    return {
        "dnsCount": 15,
        "httpCount": 42,
        "tcpCount": 30,
        "udpCount": 5,
        "threatCount": 3,
        "pcapAvailable": True,
    }


@pytest.fixture
def sample_dns_query() -> dict[str, Any]:
    return {
        "id": "dns-1",
        "host": "malware.example.com",
        "type": "A",
        "status": "NOERROR",
        "records": ["192.168.1.100"],
        "timeshift": 1.234,
    }


@pytest.fixture
def sample_dns_queries(sample_dns_query: dict[str, Any]) -> list[dict[str, Any]]:
    return [sample_dns_query, {**sample_dns_query, "id": "dns-2", "host": "c2.example.com"}]


@pytest.fixture
def sample_http_request() -> dict[str, Any]:
    return {
        "id": "http-1",
        "host": "malware.example.com",
        "ip": "192.168.1.100",
        "port": 80,
        "country": "US",
    }


@pytest.fixture
def sample_http_requests(sample_http_request: dict[str, Any]) -> list[dict[str, Any]]:
    return [sample_http_request]


@pytest.fixture
def sample_tcp_connection() -> dict[str, Any]:
    return {
        "id": "tcp-1",
        "protocol": "tcp",
        "destinationIp": "8.8.8.8",
        "destinationPort": 443,
        "domain": "dns.google",
        "asn": "AS15169",
        "country": "US",
        "packets": {"sent": 10, "received": 12, "empty": False},
        "timeshift": 0.5,
    }


@pytest.fixture
def sample_tcp_connections(sample_tcp_connection: dict[str, Any]) -> list[dict[str, Any]]:
    return [sample_tcp_connection]


@pytest.fixture
def sample_udp_connection() -> dict[str, Any]:
    return {
        "id": "udp-1",
        "protocol": "udp",
        "destinationIp": "8.8.4.4",
        "destinationPort": 53,
        "domain": "dns.google",
        "asn": "AS15169",
        "country": "US",
        "packets": {"sent": 1, "received": 1, "empty": False},
        "timeshift": 0.1,
    }


@pytest.fixture
def sample_udp_connections(sample_udp_connection: dict[str, Any]) -> list[dict[str, Any]]:
    return [sample_udp_connection]


@pytest.fixture
def sample_network_threat() -> dict[str, Any]:
    return {
        "signature": "ET MALWARE Trojan Communication",
        "description": "Suricata alert",
        "severity": "high",
        "protocol": "TCP",
        "appProto": "TLS",
        "destinationIp": "1.2.3.4",
        "destinationPort": 443,
        "timeshift": 2.5,
        "metadata": {"created_at": ["2024-01-15"]},
        "details": {"sid": 2024001, "rev": 3},
        "tls": {
            "version": "TLS 1.2",
            "sni": "evil.com",
            "ja3Hash": "abc123",
            "ja3sHash": "def456",
            "ja3String": "771,4865-4866-4867",
            "ja3sString": "771,4865",
        },
    }


@pytest.fixture
def sample_network_threats(sample_network_threat: dict[str, Any]) -> list[dict[str, Any]]:
    return [sample_network_threat]


def _source_counts(sample: int) -> dict[str, int]:
    return {"sample": sample, "sampleChild": 1, "sensorOnly": 0, "windowsBackground": 2}


@pytest.fixture
def sample_network_summary_full(sample_network_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_network_summary,
        "httpsPcapAvailable": True,
        "hasHttpsInspection": True,
        "unattributedPcapAvailable": False,
        "attributionCounts": {
            "dns": _source_counts(15),
            "http": _source_counts(42),
            "tcp": _source_counts(30),
            "udp": _source_counts(5),
            "threats": _source_counts(3),
        },
        "unattributedCounts": {"dns": 2, "http": 1, "tcp": 3, "udp": 0, "threats": 1},
        "submissionOnlyAlerts": {
            "scope": "submission_unattributed",
            "source": "pinned_offline_eve",
            "total": 3,
            "omitted": 2,
            "rows": [
                {
                    "lineNumber": 812,
                    "sid": 2034567,
                    "signature": "ET MALWARE Cobalt Strike Beacon",
                    "severity": 1,
                    "protocol": "TCP",
                    "sourceIp": "192.0.2.86",
                    "destinationIp": "192.0.2.10",
                }
            ],
        },
    }


@pytest.fixture
def sample_tcp_connection_full(sample_tcp_connection: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_tcp_connection,
        "sourceIp": "192.0.2.86",
        "sourcePort": 49712,
        "ptrDomain": "server-10.hosting.example.net",
        "appProto": "tls",
        "hostname": "dns.google",
        "pktsToServer": 14,
        "pktsToClient": 11,
        "bytesToServer": 1832,
        "bytesToClient": 6120,
        "packetsTotal": 25,
        "packetsOmitted": 0,
    }


@pytest.fixture
def sample_network_threat_full(sample_network_threat: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_network_threat,
        "severityLevel": 1,
        "sourceIp": "192.0.2.86",
        "sourcePort": 49712,
    }


@pytest.fixture
def sample_http_request_packets() -> dict[str, Any]:
    return {
        "items": [
            {
                "timeshift": 3.21,
                "url": "http://malware-c2.example.com/gate.php",
                "method": "POST",
                "destinationIp": "192.0.2.10",
                "destinationPort": 80,
                "portKnown": True,
                "headers": {"Host": "malware-c2.example.com"},
                "body": {
                    "trimmed": False,
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "md5": None,
                    "sha1": None,
                    "ssdeep": None,
                    "data": "dGVzdA==",
                },
                "response": {
                    "timeshift": 3.42,
                    "destinationIp": "192.0.2.86",
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


@pytest.fixture
def sample_tcp_connection_packets() -> dict[str, Any]:
    return {
        "protocol": "tcp",
        "sourceIp": "192.0.2.86",
        "sourcePort": 49712,
        "destinationIp": "192.0.2.10",
        "destinationPort": 443,
        "items": [
            {
                "type": "send",
                "data": {
                    "trimmed": True,
                    "sha256": None,
                    "md5": None,
                    "sha1": None,
                    "ssdeep": None,
                    "data": "FgMBAAE=",
                },
            },
            {"type": "receive", "data": None},
        ],
        "truncated": True,
        "sourceScope": "sample_attributed",
    }


@pytest.fixture
def sample_network_endpoints() -> dict[str, Any]:
    return {
        "items": [
            {
                "key": "malware-c2.example.com",
                "host": "malware-c2.example.com",
                "ips": ["192.0.2.10"],
                "ports": [443],
                "protocols": ["DNS", "TLS"],
                "source": "sample",
                "firstTimeshift": 1.25,
                "lastTimeshift": 12.5,
                "requestCount": 14,
                "alertCount": 1,
                "maxAlertSeverity": "1",
                "processIds": [1924],
                "attributionNote": None,
            }
        ],
        "total": 42,
        "truncated": False,
    }


@pytest.fixture
def sample_network_host_flows() -> dict[str, Any]:
    return {
        "flows": [
            {
                "protocol": "HTTP",
                "remoteIp": "192.0.2.10",
                "remotePort": 80,
                "localPort": None,
                "count": 3,
                "bytesSent": None,
                "bytesReceived": None,
                "firstTimeshift": 3.21,
                "lastTimeshift": 9.5,
                "processIds": [1924],
                "methods": [{"method": "POST", "count": 3}],
                "samplePaths": ["http://malware-c2.example.com/gate.php"],
            }
        ],
        "totals": {"dnsQueries": 2, "httpRequests": 3, "tcpFlows": 2, "udpFlows": 0},
        "alerts": [
            {
                "signature": "ET MALWARE Test beacon",
                "severity": 1,
                "count": 3,
                "firstTimeshift": 2.5,
            }
        ],
        "pageInfo": {"endCursor": "aGYxOjI", "hasNextPage": True},
        "truncated": False,
    }


# ---------------------------------------------------------------------------
# Processes payloads (matches src/threatzone/types/processes.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_process() -> dict[str, Any]:
    return {
        "pid": 1234,
        "ppid": 1,
        "tid": 1234,
        "name": "evil.exe",
        "cmd": "C:\\evil.exe --bad",
        "cwd": "C:\\Users\\victim",
        "network": {
            "items": [{"ip": "1.2.3.4", "port": 443, "protocol": "tcp"}],
            "count": 1,
        },
        "events": {
            "items": [{"type": "file", "path": "C:\\evil.dll", "mode": "create"}],
            "count": 1,
        },
    }


@pytest.fixture
def sample_processes_response(sample_process: dict[str, Any]) -> dict[str, Any]:
    return {"items": [sample_process], "total": 1}


@pytest.fixture
def sample_process_tree_response() -> dict[str, Any]:
    return {
        "nodes": [
            {
                "pid": 1234,
                "ppid": 1,
                "tid": 1234,
                "name": "evil.exe",
                "cmd": "C:\\evil.exe",
                "children": [
                    {
                        "pid": 5678,
                        "ppid": 1234,
                        "tid": 5678,
                        "name": "child.exe",
                        "cmd": "child.exe arg",
                        "children": [],
                    }
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# Kill chain payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_killchain() -> dict[str, Any]:
    """A Windows V2 kill chain, as in the public API docs."""
    return {
        "dumpCollectorActive": True,
        "artifactInventoryCoverage": {
            "sourceStatus": "available",
            "sourceError": None,
            "counts": [
                {"name": "event_file_count", "value": 3},
                {"name": "sidecar_count", "value": 2},
            ],
            "unretainedRowsOmitted": 0,
        },
        "createdProcesses": [
            {
                "pid": 1508,
                "pidGen": 4,
                "origin": "sample",
                "ppid": 800,
                "tid": 4120,
                "processName": "payload.exe",
                "image": "C:\\Users\\analyst\\Desktop\\payload.exe",
                "cmd": "payload.exe --install",
                "method": "NtCreateUserProcess",
                "workDir": "C:\\Users\\Public",
                "timestamp": 1790376279.55,
                "exitTimestamp": 1790376284.1,
                "events": {
                    "items": [
                        {
                            "type": "file",
                            "path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\payload.dll",
                            "mode": "create",
                        }
                    ],
                    "count": 87,
                },
                "network": {
                    "items": [{"ip": "192.0.2.10", "port": 443, "protocol": "tcp"}],
                    "count": 12,
                },
            }
        ],
        "droppedFiles": [
            {
                "pid": 1508,
                "pidGen": 4,
                "processName": "payload.exe",
                "executablePath": "C:\\Users\\analyst\\Desktop\\payload.exe",
                "files": [
                    {
                        "path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\payload.dll",
                        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                        "fileSize": 24576,
                        "timestamp": 1790376280.2,
                        "artifactId": "65f0aa000000000000000001",
                        "analysisStatus": "analyzed",
                        "analysisReason": None,
                        "rawPath": (
                            "\\Device\\HarddiskVolume3\\Users\\analyst\\AppData\\Local\\Temp"
                            "\\payload.dll"
                        ),
                        "pathAuthority": "verified_volume_map",
                        "pathAuthorityReason": None,
                        "sourceActorBound": True,
                        "captureClosed": True,
                        "retention": "retained",
                        "retentionDetail": None,
                        "pidGen": 4,
                        "eventSeq": 1182,
                    }
                ],
            }
        ],
        "memDumps": [
            {
                "pid": 2244,
                "processName": "rundll32.exe",
                "executablePath": "C:\\Windows\\System32\\rundll32.exe",
                "regions": [
                    {
                        "offsetStart": "0x400000",
                        "offsetEnd": "0x401000",
                        "dumps": [
                            {
                                "path": "C:\\dumps\\2244_0x400000.dmp",
                                "sha256": (
                                    "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
                                ),
                                "fileSize": 4096,
                                "timestamp": 1790376281,
                                "artifactId": "65f0aa000000000000000002",
                                "analysisStatus": "not_analyzed",
                                "analysisReason": None,
                            }
                        ],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def sample_killchain_v1() -> dict[str, Any]:
    """A kill chain of an old V1 report: no times, no V2 file fields, no inventory."""
    return {
        "dumpCollectorActive": False,
        "createdProcesses": [
            {
                "pid": 1234,
                "ppid": 1,
                "events": {"items": [], "count": 0},
                "network": {"items": [], "count": 0},
            }
        ],
        "droppedFiles": [
            {
                "pid": 1234,
                "processName": "evil.exe",
                "executablePath": "C:\\evil.exe",
                "files": [{"path": "C:\\evil.dll"}],
            }
        ],
        "memDumps": [],
    }


# ---------------------------------------------------------------------------
# Behaviours / syscalls payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_behaviour_event() -> dict[str, Any]:
    return {
        "type": "file",
        "pid": 1234,
        "ppid": 1,
        "processName": "evil.exe",
        "operation": "create",
        "eventId": 42,
        "eventCount": 1,
        "syscallLineNumber": 100,
        "timestamp": 1700000000,
        "details": {"path": "C:\\evil.dll", "size": 4096},
    }


@pytest.fixture
def sample_behaviours_response(
    sample_behaviour_event: dict[str, Any],
) -> dict[str, Any]:
    return {
        "items": [sample_behaviour_event],
        "total": 1,
        "page": 1,
        "limit": 100,
        "totalPages": 1,
    }


@pytest.fixture
def sample_syscalls_response() -> dict[str, Any]:
    return {
        "items": ["00:00:01 NtCreateFile()", "00:00:02 NtWriteFile()"],
        "total": 2,
    }


@pytest.fixture
def sample_windows_v2_process(sample_process: dict[str, Any]) -> dict[str, Any]:
    return {
        **sample_process,
        "pidGen": 4,
        "origin": "sample",
        "image": "C:\\Users\\victim\\evil.exe",
        "method": "NtCreateUserProcess",
        "timestamp": 1790376279.55,
        "exitTimestamp": 1790376284.1,
    }


@pytest.fixture
def sample_indexed_behaviours_response(
    sample_behaviour_event: dict[str, Any],
) -> dict[str, Any]:
    return {
        "items": [
            {
                **sample_behaviour_event,
                "pidGen": 0,
                "subject": "C:\\evil.dll",
                "details": {"path": "C:\\evil.dll", "status": "success"},
            }
        ],
        "total": 1,
        "page": 1,
        "limit": 100,
        "totalPages": 1,
        "sortedBy": "time",
        "manyProcessesMatch": False,
    }


@pytest.fixture
def sample_behaviour_summary_response() -> dict[str, Any]:
    return {
        "totalCount": 1337,
        "firstTimestamp": 1712345678.901,
        "lastTimestamp": 1712345790.5,
        "byType": [{"value": "registry", "count": 900}, {"value": "file", "count": 437}],
        "byOperation": [{"value": "RegSetValue", "count": 42}],
        "byProcess": [
            {
                "processId": 1508,
                "processName": "payload.exe",
                "count": 420,
                "firstTimestamp": 1712345678.901,
                "lastTimestamp": None,
            }
        ],
        "exits": [{"processId": 1508, "eventId": 2048, "status": None}],
    }


@pytest.fixture
def sample_behaviour_facets_response() -> dict[str, Any]:
    return {
        "items": [{"value": "RegSetValue", "count": 42}, {"value": "WriteFile", "count": 7}],
        "complete": False,
        "scannedRows": 250000,
    }


@pytest.fixture
def sample_syscall_search_response() -> dict[str, Any]:
    return {
        "lines": [
            {
                "line": 3000,
                "raw": "ntdll!NtCreateFile(FileHandle=0x0, Status=0xC0000034) "
                "// Process Name:a.exe PID:3568 TID:4100",
            }
        ],
        "nextFromLine": 3000,
        "scannedTo": 3000,
        "totalCount": 1500000,
        "done": False,
        "truncated": False,
        "busy": False,
    }


# ---------------------------------------------------------------------------
# CDR / static-scan / signature-check payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_cdr_response() -> dict[str, Any]:
    return {
        "submission": "uuid-1",
        "status": "completed",
        "sanitized": ["doc.pdf"],
        "removed": ["macro1"],
        "sanitizedFileInfo": {
            "description": "Sanitized",
            "fileType": "PDF",
            "fileSize": 1024,
            "sha256": "ab" * 32,
            "name": "doc.pdf",
            "details": [{"name": "macro", "action": "removed", "data": None}],
        },
        "elapsedTime": "00:00:43",
        "metafields": None,
    }


@pytest.fixture
def sample_static_scan_response() -> dict[str, Any]:
    return {
        "submission": "uuid-1",
        "status": "completed",
        "reportFormat": "exe",
        "level": "malicious",
        "score": 92.0,
        "fileInfo": {
            "md5": "a" * 32,
            "sha1": "b" * 40,
            "sha256": "c" * 64,
            "ssdeep": "x",
            "mime_type": "application/x-dosexec",
            "file_type": "PE32",
            "entropy": 7.1,
            "filesize": "1.00 MB",
        },
        "strings": {"totalCount": 1234},
        "dieResults": [{"name": "PE", "string": "PE32", "type": "exe", "version": None}],
        "analysisTime": "00:00:02",
        "metafields": None,
        "imports": [{"library": "kernel32.dll", "functions": ["VirtualAlloc"]}],
        "peExeSections": [{"name": ".text", "entropy": 6.5}],
    }


@pytest.fixture
def sample_cdr_nested_response(sample_cdr_response: dict[str, Any]) -> dict[str, Any]:
    sample_cdr_response["sanitizedFileInfo"]["details"] = [
        {
            "name": "Archive member",
            "action": "sanitized",
            "data": None,
            "count": 2,
            "sha256": ["cd" * 32],
            "description": "Inner document",
            "fileName": "invoice.docx",
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
                }
            ],
        }
    ]
    return sample_cdr_response


@pytest.fixture
def sample_static_scan_onenote_response() -> dict[str, Any]:
    return {
        "submission": "uuid-1",
        "status": "completed",
        "reportFormat": "onenote",
        "level": "malicious",
        "score": 88.0,
        "fileInfo": {
            "md5": "a" * 32,
            "sha1": "b" * 40,
            "sha256": "c" * 64,
            "ssdeep": "x",
            "mime_type": "application/onenote",
            "file_type": "OneNote",
            "entropy": 5.2,
            "filesize": "204800",
            "realFilename": "notepad.exe",
            "realSha256": "d" * 64,
        },
        "strings": {"totalCount": 12},
        "dieResults": [],
        "analysisTime": "00:00:03",
        "metafields": None,
        "oneNoteEmbeddedFiles": [
            {
                "name": "click_me.exe",
                "size": 204800,
                "type": "PE32",
                "md5": "1" * 32,
                "sha1": "2" * 40,
                "sha256": "3" * 64,
                "artifactId": "art-9",
                "downloadLink": "/public-api/submissions/uuid-1/download/artifact/art-9",
                "displayName": "click_me.exe",
                "mimeType": "application/x-dosexec",
                "extension": ".exe",
                "identity": "{3F5A2B10-6C1D-4E7A-9B8C-0D1E2F3A4B5C}",
                "filesize": "204800",
                "entropy": 7.42,
                "lastModifiedTime": "2024-01-01T00:00:00Z",
                "embeddedFileName": "click_me.exe",
                "sourceFilepath": "C:\\Users\\analyst\\Desktop\\click_me.exe",
            }
        ],
        "oneNoteMetadata": {"author": "analyst"},
    }


_SAMPLE_BOT_TOKEN_URL = (
    "https://api.telegram.org/bot123456789:AAFabcdefghijklmnopqrstuvwxyz012345/sendMessage"
)


@pytest.fixture
def sample_string_facts() -> dict[str, Any]:
    return {
        "observables": [
            {
                "kind": "bot-token",
                "value": _SAMPLE_BOT_TOKEN_URL,
                "count": 2,
                "display": _SAMPLE_BOT_TOKEN_URL,
                "host": "api.telegram.org",
                "detail": "Telegram",
                "source": f'url = "{_SAMPLE_BOT_TOKEN_URL}"',
                "secret": True,
            },
            {
                "kind": "ip",
                "value": "192.0.2.10",
                "count": 1,
                "display": "192.0.2.10",
                "host": "192.0.2.10",
                "detail": None,
                "source": "connect 192.0.2.10",
                "secret": False,
            },
        ],
        "facts": [
            {
                "code": "anti-debug",
                "value": "Debugger checks",
                "capability": "anti-analysis",
                "matches": ["return kernel32.IsDebuggerPresent() != 0"],
                "count": 1,
                "names": [],
            }
        ],
        "total": 1423,
        "truncated": False,
    }


@pytest.fixture
def sample_strings_page() -> dict[str, Any]:
    return {
        "items": [
            {
                "value": "IsDebuggerPresent",
                "from_source": "ascii",
                "blacklist": True,
                "hint": "anti-debug",
            },
            {"value": "kernel32.dll", "from_source": "utf16", "blacklist": False, "hint": None},
        ],
        "itemsCount": 1423,
        "start": 0,
        "end": 2,
        "downloadLink": "/public-api/submissions/uuid-1/static-scan/strings",
    }


@pytest.fixture
def sample_signature_check_response() -> dict[str, Any]:
    return {
        "items": [
            {
                "artifact": "art-1",
                "data": {"signed": True, "signer": "Microsoft Corporation"},
            }
        ],
        "total": 1,
    }


# ---------------------------------------------------------------------------
# EML / MITRE / URL analysis payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_eml_analysis() -> dict[str, Any]:
    return {
        "headers": {
            "message_id": "<msg@example>",
            "subject": "Hello",
            "date": "2024-01-15",
            "from_email": "alice@example.com",
            "to_emails": ["bob@example.com"],
            "cc_emails": [],
            "bcc_emails": [],
        },
        "other_headers": {"X-Mailer": "Outlook"},
        "attachments": [
            {
                "filename": "doc.pdf",
                "size": 1024,
                "extension": ".pdf",
                "mime_type": "application/pdf",
                "hash": {"md5": "abcd", "sha1": "efgh", "sha256": "ijkl"},
            }
        ],
        "qr_results": [{"data": "https://qr.example.com", "filename": "qr.png"}],
        "artifact": "art-1",
    }


@pytest.fixture
def sample_eml_analysis_list(sample_eml_analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [sample_eml_analysis]


@pytest.fixture
def sample_mitre_response() -> dict[str, Any]:
    return {
        "techniques": ["T1547.001", "T1071.001"],
        "total": 2,
    }


@pytest.fixture
def sample_mitre_response_with_items() -> dict[str, Any]:
    return {
        "techniques": ["T1055", "T1547.001", "T9999"],
        "total": 3,
        "items": [
            {
                "techniqueId": "T1055",
                "name": "Process Injection",
                "tacticIds": ["TA0004", "TA0005"],
                "score": 85,
                "scoreMaximum": 100,
                "inVerdictChain": True,
                "indicatorIds": ["665f1c2e9b1d4a0012ab34cd", "665f1c2e9b1d4a0012ab34ce"],
            },
            {
                "techniqueId": "T1547.001",
                "name": "Registry Run Keys / Startup Folder",
                "tacticIds": ["TA0003", "TA0004"],
                "score": 40.5,
                "scoreMaximum": 100,
                "inVerdictChain": False,
                "indicatorIds": ["665f1c2e9b1d4a0012ab34cf"],
            },
        ],
    }


@pytest.fixture
def sample_url_analysis_response() -> dict[str, Any]:
    return {
        "level": "malicious",
        "status": "completed",
        "generalInfo": {
            "url": "https://evil.com/login",
            "domain": "evil.com",
            "websiteTitle": "Login",
        },
        "screenshot": {"available": True},
        "ipInfo": {
            "ip": "1.2.3.4",
            "asn": "AS12345",
            "city": "Atlantis",
            "country": "US",
            "isp": "EvilNet",
            "organization": "Evil Inc",
            "threatStatus": {
                "verdict": "malicious",
                "title": "Phishing",
                "description": "Known phishing host",
            },
        },
        "dnsRecords": [{"type": "A", "records": ["1.2.3.4"]}],
        "whois": {
            "domainName": "evil.com",
            "domainId": "EVIL_42",
            "nameServers": ["ns1.evil.com"],
            "creationDate": "2020-01-01",
            "updatedDate": "2024-01-01",
            "expirationDate": "2030-01-01",
            "registrar": "EvilRegistrar",
            "registrarIanaId": "9999",
            "email": "abuse@evil.com",
            "phone": "+1-555-0100",
        },
        "sslCertificate": {
            "subject": "CN=evil.com",
            "issuer": "Evil CA",
            "renewedAt": 1700000000,
            "expiresAt": 1900000000,
            "serialNumber": "01:02:03",
            "fingerprint": "ab:cd:ef",
        },
        "responseHeaders": {"Server": "nginx"},
        "extractedFile": {
            "uuid": "extracted-1",
            "threatStatus": {
                "verdict": "suspicious",
                "title": "PE",
                "description": "Suspicious dropper",
            },
        },
        "threatAnalysis": {
            "overview": [
                {
                    "source": "intel-1",
                    "title": "Phishing kit",
                    "description": "matched",
                    "verdict": "malicious",
                }
            ],
            "blacklist": True,
            "threatDetails": [{"source": "intel-1", "details": {"family": "EvilKit"}}],
        },
        "pages": ["https://evil.com/login"],
        "threatScore": 72,
        "riskLevel": "High",
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
            "rawVerdict": "malicious",
            "quorumApplied": False,
            "allowlistApplied": False,
            "collectionState": "ok",
            "pass": "final",
        },
        "impersonationTarget": {
            "brandName": "PayPal",
            "canonicalDomain": "paypal.com",
            "signals": ["favicon_match"],
            "confidence": "high",
        },
        "completeness": {
            "measuredSources": ["dns", "tls", "intel"],
            "skippedSources": ["browser"],
            "unavailableSources": [],
            "browserCollection": "partial",
        },
        "intelDetections": [
            {
                "source": "urlhaus",
                "detectionType": "malware_url",
                "severity": "high",
                "details": "listed",
            }
        ],
        "metafields": {"timeout": 240, "record_session": True},
        "scoredAt": "2026-08-27T10:00:00.000Z",
    }


@pytest.fixture
def url_analysis_session_payload() -> dict[str, Any]:
    return {
        "state": "running",
        "collectionStatus": "collecting",
        "recordingStatus": "recording",
        "queuePosition": None,
        "vncAvailable": True,
        "reportAvailable": False,
        "startedAt": 1756288800000,
        "readyAt": 1756288805000,
        "expiresAt": 1756288920000,
        "finishedAt": None,
        "failureCode": None,
        "extensionsUsed": 0,
        "extensionsMax": 3,
        "sessionConfig": {
            "deviceProfileId": "iphone-15-pro",
            "networkConfigId": None,
            "sessionDurationSeconds": 240,
            "devicePresetId": "68b0000000000000000000a1",
            "devicePresetName": "iPhone 15 Pro",
        },
        "link": "wss://gateway.example/?token=abc",
        "expired": False,
    }


@pytest.fixture
def url_analysis_indicators_payload() -> dict[str, Any]:
    return {
        "state": "available",
        "unavailableReason": None,
        "snapshot": {
            "schemaVersion": 1,
            "scoringVersion": "url-score-v3",
            "jobId": "6710a3f2c1d2e3f4a5b6c7d8",
            "pass": "final",
            "scoredAt": "2026-10-01T09:30:00.000Z",
            "browserSnapshot": {
                "jobId": "6710a3f2c1d2e3f4a5b6c7d8",
                "manifestHash": "9f2c4a6e8b0d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a",
            },
            "threatScore": 20,
            "verdict": "suspicious",
            "indicators": [
                {
                    "id": "domain-age",
                    "ruleId": "whois.domain_age",
                    "source": "whois",
                    "family": "reputation",
                    "title": "Domain registered recently",
                    "reason": "The domain was registered 3 days before the analysis.",
                    "availability": "measured",
                    "confidence": "high",
                    "originalRuleScore": 2,
                    "weightedPoints": 20,
                    "disposition": "contributing",
                    "suppressedBy": None,
                    "evidenceRefs": [{"kind": "report", "id": "whois", "available": True}],
                }
            ],
            "aggregation": {
                "highPoints": 20,
                "heuristicPoints": 0,
                "reputationCredits": [
                    {
                        "ruleId": "tranco.top_rank",
                        "eligible": False,
                        "nominalPoints": 10,
                        "reason": "The domain is not in a top-ranked list.",
                    }
                ],
                "creditScope": "heuristic",
                "effectiveCredit": 0,
                "scoreBeforeClamp": 20,
                "scoreAfterClamp": 20,
                "roundingAdjustment": 0,
                "impersonationFloorAdjustment": 0,
            },
            "verdictAdjustments": [
                {
                    "ruleId": "quorum",
                    "from": "malicious",
                    "to": "suspicious",
                    "reason": "Only one source reported the URL.",
                }
            ],
        },
    }


@pytest.fixture
def url_analysis_evidence_payload() -> dict[str, Any]:
    return {
        "state": "available",
        "text": '{\n  "domainName": "example.com"\n}',
        "truncated": False,
    }


@pytest.fixture
def url_analysis_browser_section_payload() -> dict[str, Any]:
    return {
        "section": "tls",
        "jobId": "6710a3f2c1d2e3f4a5b6c7d8",
        "revision": "9f2c4a6e8b0d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a",
        "updatedAt": 1760000000000,
        "data": {
            "tls": {"protocol": "TLS 1.3", "issuer": "Example CA", "sanList": ["example.com"]}
        },
    }


@pytest.fixture
def device_presets_payload() -> list[dict[str, Any]]:
    return [
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


# ---------------------------------------------------------------------------
# Misc payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_media_files() -> list[dict[str, Any]]:
    return [
        {
            "id": "media-1",
            "name": "screenshot_001.png",
            "contentType": "image/png",
            "size": 50000,
            "kind": "screenshot",
        },
        {
            "id": "media-2",
            "name": "video.mp4",
            "contentType": "video/mp4",
            "size": 5000000,
            "kind": "video",
        },
    ]


@pytest.fixture
def report_unavailable_409_body() -> dict[str, Any]:
    return {
        "statusCode": 409,
        "error": "Conflict",
        "message": "Dynamic report is not available",
        "code": "DYNAMIC_REPORT_UNAVAILABLE",
        "details": {
            "submissionUuid": "11111111-2222-3333-4444-555555555555",
            "requiredReport": "dynamic",
            "currentStatus": "in_progress",
            "availableReports": ["static"],
        },
    }


# ---------------------------------------------------------------------------
# Network exfil requests, PDF report status, and AI report payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_network_exfil_request() -> dict[str, Any]:
    return {
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
        "processId": 1508,
        "processImage": "C:\\Users\\analyst\\AppData\\Local\\Temp\\sample.exe",
        "text": "A file was uploaded to the Telegram bot 123456789.",
    }


@pytest.fixture
def sample_pdf_report_status_queued() -> dict[str, Any]:
    return {"status": "queued", "retryAfterSeconds": 3}


@pytest.fixture
def sample_ai_report_evidence() -> dict[str, Any]:
    return {"source": "network_dns", "ref": "c2.example.com", "label": "DNS query"}


@pytest.fixture
def sample_ai_report(sample_ai_report_evidence: dict[str, Any]) -> dict[str, Any]:
    evidence = sample_ai_report_evidence
    return {
        "jobId": None,
        "status": "completed",
        "verdict": "malicious",
        "confidence": "high",
        "agreesWithEngine": True,
        "family": "AgentTesla",
        "familyStatus": "confirmed",
        "report": {
            "summary": {
                "verdict": "malicious",
                "confidence": "high",
                "text": "The sample drops a stealer payload and contacts a C2 host.",
                "engineVerdict": "malicious",
                "agreesWithEngine": True,
                "disagreementReason": None,
            },
            "classification": {
                "family": {"name": "AgentTesla", "status": "confirmed", "evidence": [evidence]},
                "category": "stealer",
                "impersonatedBrand": None,
            },
            "iocs": [
                {
                    "value": "c2.example.com",
                    "kind": "domain",
                    "status": "confirmed",
                    "reason": "Contacted over HTTP right after execution.",
                    "evidence": [evidence],
                }
            ],
            "techniques": [
                {
                    "id": "T1055",
                    "name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "origin": "engine",
                    "confidence": "high",
                    "evidence": [evidence],
                }
            ],
            "attackFlow": {
                "nodes": [
                    {
                        "id": "n1",
                        "kind": "process",
                        "label": "sample.exe",
                        "phase": "execution",
                        "evidence": evidence,
                    },
                    {
                        "id": "n2",
                        "kind": "network",
                        "label": "c2.example.com",
                        "phase": "c2",
                        "evidence": evidence,
                    },
                ],
                "edges": [{"from": "n1", "to": "n2", "label": "connects to"}],
            },
            "narrative": [
                {
                    "phase": "execution",
                    "text": "The sample starts and injects code into explorer.exe.",
                    "evidence": [evidence],
                }
            ],
            "screenshots": [
                {
                    "ordinal": 1,
                    "observation": "A fake invoice window is shown.",
                    "kind": "document",
                    "threatRelevant": True,
                }
            ],
            "engineAgreement": [
                {"engine": "dynamic", "reported": "malicious", "agrees": True, "note": None}
            ],
            "recommendations": [
                {"kind": "containment", "text": "Block c2.example.com at the proxy."}
            ],
            "iocReview": {
                "candidates": [
                    {
                        "value": "c2.example.com",
                        "kind": "domain",
                        "verdict": "valid",
                        "decidedBy": "rule",
                        "ruleId": "corroborated",
                        "reason": "Engine evidence shows this value in network traffic.",
                        "evidence": [evidence],
                    }
                ],
                "summary": {
                    "total": 1,
                    "valid": 1,
                    "invalid": 0,
                    "benign": 0,
                    "unverified": 0,
                    "reviewedByModel": 0,
                    "truncated": False,
                },
            },
        },
        "updatedAt": "2026-09-28T10:00:00.000Z",
        "reason": "finalized",
        "error": None,
        "analysisFinalized": True,
    }


@pytest.fixture
def sample_ai_report_failed() -> dict[str, Any]:
    return {
        "jobId": None,
        "status": "failed",
        "verdict": None,
        "confidence": None,
        "agreesWithEngine": None,
        "family": None,
        "familyStatus": None,
        "report": None,
        "updatedAt": "2026-09-28T10:00:00.000Z",
        "reason": "regenerate",
        "error": {"code": "PIPELINE_TIMEOUT"},
        "analysisFinalized": True,
    }


@pytest.fixture
def sample_ai_report_in_progress() -> dict[str, Any]:
    return {"status": "in_progress", "jobId": None, "stage": "writing"}


@pytest.fixture
def sample_ai_report_regenerate() -> dict[str, Any]:
    return {"status": "queued", "message": "AI report regeneration queued"}


@pytest.fixture
def sample_verdict() -> dict[str, Any]:
    """A Windows V2 schema 2.1 verdict, as in the public API docs."""
    return {
        "format": "windows-v2-worker-1",
        "score": 45,
        "tier": "Suspicious",
        "summary": "Suspicious (45/100): the sample read the clipboard.",
        "narrative": {
            "headline": "Suspicious (45/100): the sample read the clipboard.",
            "sequence": [
                {
                    "seq": 3,
                    "tOffsetS": 1.2,
                    "pid": 1924,
                    "image": "invoice.exe",
                    "text": "Read the clipboard.",
                }
            ],
            "decisive": [
                {"source": "policy:win.collect.clipboard_policy", "text": "Clipboard read."}
            ],
            "tierReason": "Owner policy floor. Malicious needs an upload of the data.",
            "notObserved": ["no persistence request"],
            "wouldRaise": ["an upload of the clipboard data"],
            "wouldLower": [],
            "coverageNote": None,
            "text": "Suspicious (45/100): the sample read the clipboard.",
        },
        "story": {
            "summary": ["invoice.exe connected to 203.0.113.7:5552 41 times."],
            "truncated": False,
            "headline": {
                "text": "invoice.exe connected to a remote host",
                "parts": [{"type": "process", "value": "invoice.exe"}],
            },
            "steps": [
                {
                    "tOffsetS": 1.5,
                    "process": {"image": "invoice.exe", "pid": 1924},
                    "category": "network",
                    "text": "Connected to 203.0.113.7:5552.",
                    "count": 41,
                    "evidenceSeqs": [12, 13],
                    "key": True,
                    "parts": [
                        {"type": "text", "value": "Connected to "},
                        {"type": "constant", "value": "203.0.113.7:5552"},
                    ],
                    "command": "C:\\Users\\analyst\\AppData\\Local\\Temp\\invoice.exe --connect",
                }
            ],
        },
    }


@pytest.fixture
def sample_verdict_legacy() -> dict[str, Any]:
    """The verdict of a legacy report: every field is null."""
    return {
        "format": None,
        "score": None,
        "tier": None,
        "summary": None,
        "narrative": None,
        "story": None,
    }


@pytest.fixture
def sample_run_notes() -> dict[str, Any]:
    """Run notes of a Windows V2 JAR run, as in the public API docs."""
    return {
        "javaOutput": {
            "summary": "The Java program stopped with an uncaught exception: no config",
            "error": "java.lang.IllegalStateException: no config",
            "cause": "java.io.FileNotFoundException: C:\\Users\\analyst\\config.bin",
            "text": (
                "Starting loader\nbot token 123456:AAH-secret-value\n"
                'Exception in thread "main" java.lang.IllegalStateException: no config\n'
            ),
            "size": 120,
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
        "isDumpCollectorActivated": True,
    }


@pytest.fixture
def sample_run_notes_legacy() -> dict[str, Any]:
    """Run notes of a legacy report."""
    return {
        "javaOutput": None,
        "analysisCutShort": None,
        "networkNotes": [],
        "submissionHints": [],
        "runNotes": [],
        "isDumpCollectorActivated": False,
    }


@pytest.fixture
def sample_annotations() -> dict[str, Any]:
    """The annotations view of the caller workspace, as in the public API docs."""
    return {
        "submissionUuid": "a1b2c3d4-e5f6-4789-abcd-ef1234567890",
        "pins": [
            {
                "id": "c1c2c3c4-e5f6-4789-abcd-ef1234567892",
                "kind": "process",
                "ref": "process:pid-4120",
                "label": "payload.exe",
                "createdBy": "64a000000000000000000001",
                "createdAt": "2026-10-14T08:00:00.000Z",
            }
        ],
        "note": {
            "text": "The sample drops a second stage.",
            "updatedBy": "64a000000000000000000001",
            "updatedAt": "2026-10-14T08:05:00.000Z",
        },
    }


@pytest.fixture
def sample_run_comparison() -> dict[str, Any]:
    """A run comparison, as in the public API docs."""
    return {
        "submissionUuid": "a1b2c3d4-e5f6-4789-abcd-ef1234567890",
        "otherSubmissionUuid": "b1b2c3d4-e5f6-4789-abcd-ef1234567891",
        "detections": {
            "added": [{"title": "Writes an executable to disk", "level": "malicious"}],
            "removed": [{"title": "Reads browser credentials", "level": "suspicious"}],
            "addedTotal": 1,
            "removedTotal": 1,
        },
        "techniques": {
            "added": ["T1059"],
            "removed": ["T1112"],
            "addedTotal": 1,
            "removedTotal": 1,
        },
        "iocs": {
            "added": [{"value": "192.0.2.10", "category": "ip"}],
            "removed": [{"value": "198.51.100.7", "category": "ip"}],
            "addedTotal": 1,
            "removedTotal": 1,
        },
        "droppedFiles": {
            "added": [
                {
                    "path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\payload.exe",
                    "sha256": "a" * 64,
                },
                {"path": "C:\\Users\\analyst\\notes.txt", "sha256": None},
            ],
            "removed": [],
            "addedTotal": 2,
            "removedTotal": 0,
        },
    }
