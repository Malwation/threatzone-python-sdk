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
        },
        {
            "key": "w11_x64",
            "name": "Windows 11 64-bit",
            "platform": "windows",
            "default": False,
        },
        {
            "key": "ubuntu_22",
            "name": "Ubuntu 22.04",
            "platform": "linux",
            "default": False,
        },
    ]


@pytest.fixture
def sample_metafields() -> dict[str, list[dict[str, Any]]]:
    return {
        "sandbox": [
            {
                "key": "timeout",
                "label": "Timeout",
                "description": "Analysis timeout in seconds",
                "type": "number",
                "default": 120,
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
        "operatingSystem": {"name": "Windows 10", "platform": "windows"},
    }


@pytest.fixture
def sample_report_status_in_progress() -> dict[str, Any]:
    return {
        "type": "dynamic",
        "status": "in_progress",
        "level": None,
        "score": None,
    }


@pytest.fixture
def sample_submission_overview() -> dict[str, Any]:
    return {
        "status": "completed",
        "jobs": {"completed": 3, "total": 3},
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
        "private": False,
        "tags": [{"type": "malware", "value": "trojan"}],
        "reports": [sample_report_status_completed, static_completed],
        "overview": sample_submission_overview,
        "indicators": sample_indicators_rollup,
        "mitreTechniques": ["T1547.001", "T1071.001"],
        "createdAt": "2024-01-15T10:30:00Z",
        "updatedAt": "2024-01-15T11:00:00Z",
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
        "category": "persistence",
        "level": "malicious",
        "score": 80,
        "pids": [1234, 5678],
        "attackCodes": ["T1547.001"],
        "eventIds": [42, 43],
        "syscallLineNumbers": [12, 100],
        "author": "system",
    }


@pytest.fixture
def sample_indicators_response(
    sample_indicator: dict[str, Any],
    sample_indicator_levels: dict[str, int],
) -> dict[str, Any]:
    return {
        "items": [sample_indicator],
        "total": 1,
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
    return {"items": [sample_ioc], "total": 1}


@pytest.fixture
def sample_yara_rule() -> dict[str, Any]:
    return {
        "rule": "Trojan_Generic",
        "category": "malicious",
        "artifacts": ["art-1", "art-2"],
    }


@pytest.fixture
def sample_yara_rules_response(sample_yara_rule: dict[str, Any]) -> dict[str, Any]:
    return {"items": [sample_yara_rule], "total": 1}


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
        "os": "windows",
    }


@pytest.fixture
def sample_syscalls_response() -> dict[str, Any]:
    return {
        "items": ["00:00:01 NtCreateFile()", "00:00:02 NtWriteFile()"],
        "total": 2,
    }


# ---------------------------------------------------------------------------
# CDR / static-scan / signature-check payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_cdr_response() -> dict[str, Any]:
    return {
        "items": [
            {
                "artifact": "art-1",
                "status": "completed",
                "data": {"reason": "macro stripped"},
                "lastErrorMessage": None,
                "engineVersion": "1.2.3",
            }
        ],
        "total": 1,
    }


@pytest.fixture
def sample_static_scan_response() -> dict[str, Any]:
    return {
        "items": [
            {
                "artifact": "art-1",
                "status": "completed",
                "data": {"sections": ["text", "data"]},
                "lastErrorMessage": None,
                "engineVersion": "9.9.9",
            }
        ],
        "total": 1,
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
    }


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
        },
        {
            "id": "media-2",
            "name": "video.mp4",
            "contentType": "video/mp4",
            "size": 5000000,
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
