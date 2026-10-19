"""Payloads shaped like current Public API responses (field names, nulls and value types)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from threatzone import (
    BadRequestError,
    BehaviourIndexBuildingError,
    BehaviourIndexingError,
    InternalServerError,
    PaymentRequiredError,
    PermissionDeniedError,
    QuotaUnavailableError,
    ServiceUnavailableError,
)
from threatzone._exceptions import raise_for_status
from threatzone.types import (
    Artifact,
    BehaviourEvent,
    Connection,
    DnsQuery,
    Indicator,
    MitreResponse,
    NetworkEndpoint,
    NetworkThreat,
    PaginatedSubmissions,
    Submission,
    SyscallSearchResult,
    UserInfo,
)
from threatzone.types.errors import ApiError

UUID_A = "00000000-0000-4000-8000-000000000001"
UUID_URL = "00000000-0000-4000-8000-000000000002"
SHA256 = "a" * 64


def _row_source() -> dict[str, Any]:
    return {
        "sourceScope": "submission_ip_scoped",
        "attribution": "sensor_only",
        "attributionReason": None,
        "processId": None,
        "processImage": None,
    }


def _tcp_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "65f0aa000000000000000101",
        "protocol": "tcp",
        "sourceIp": "192.0.2.10",
        "sourcePort": 49676,
        "destinationIp": "203.0.113.7",
        "destinationPort": 80,
        "domain": "cdn.example.com",
        "ptrDomain": "cdn.example.com",
        "asn": "EXAMPLE-ASN",
        "country": "US",
        "packets": {"sent": 0, "received": 1, "empty": False},
        "appProto": None,
        "hostname": None,
        "pktsToServer": None,
        "pktsToClient": None,
        "bytesToServer": None,
        "bytesToClient": None,
        "packetsTotal": None,
        "packetsOmitted": None,
        "connectOutcome": None,
        "timeshift": 0,
        **_row_source(),
    }
    row.update(overrides)
    return row


def _dns_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "65f0aa000000000000000102",
        "host": "api.example.com",
        "type": "CNAME",
        "status": "NOERROR",
        "statusText": "NOERROR",
        "records": ["edge.example.net"],
        "answered": None,
        "timeshift": 1660,
        **_row_source(),
    }
    row.update(overrides)
    return row


class TestNetworkRowFields:
    @pytest.mark.parametrize(
        "outcome", ["established", "no_response", "refused", "not_captured", None]
    )
    def test_connection_connect_outcome(self, outcome: str | None) -> None:
        row = Connection.model_validate(_tcp_row(connectOutcome=outcome))
        assert row.connect_outcome == outcome

    def test_connection_accepts_future_connect_outcome(self) -> None:
        row = Connection.model_validate(_tcp_row(connectOutcome="reset_late"))
        assert row.connect_outcome == "reset_late"

    def test_connection_without_new_fields_from_older_server(self) -> None:
        payload = _tcp_row()
        del payload["connectOutcome"]
        row = Connection.model_validate(payload)
        assert row.connect_outcome is None
        assert row.timeshift_seconds is None

    def test_timeshift_seconds_on_rows(self) -> None:
        assert Connection.model_validate(_tcp_row(timeshiftSeconds=1.66)).timeshift_seconds == 1.66
        assert DnsQuery.model_validate(_dns_row(timeshiftSeconds=1.66)).timeshift_seconds == 1.66

    @pytest.mark.parametrize("answered", [True, False, None])
    def test_dns_answered(self, answered: bool | None) -> None:
        assert DnsQuery.model_validate(_dns_row(answered=answered)).answered is answered

    def test_dns_unknown_status(self) -> None:
        row = DnsQuery.model_validate(_dns_row(status="UNKNOWN", statusText="weird sensor text"))
        assert row.status == "UNKNOWN"

    def test_dns_timeout_status_without_answer(self) -> None:
        row = DnsQuery.model_validate(_dns_row(status="TIMEOUT", answered=False, records=[]))
        assert (row.status, row.answered) == ("TIMEOUT", False)

    def test_threat_info_severity(self) -> None:
        threat = NetworkThreat.model_validate(
            {
                "signature": "ET INFO Example Lookup",
                "description": "Example lookup",
                "severity": "info",
                "severityLevel": 4,
                "protocol": "UDP",
                "appProto": "DNS",
                "sourceIp": "192.0.2.10",
                "sourcePort": 53000,
                "destinationIp": "198.51.100.53",
                "destinationPort": 53,
                "timeshift": 2.5,
                "metadata": {},
                "details": {},
                **_row_source(),
            }
        )
        assert (threat.severity, threat.severity_level) == ("info", 4)

    def test_endpoint_max_alert_severity_level(self) -> None:
        endpoint = NetworkEndpoint.model_validate(
            {
                "key": "c2.example.com",
                "host": "c2.example.com",
                "ips": ["203.0.113.9"],
                "ports": [4212],
                "protocols": ["DNS", "TCP"],
                "source": "sample",
                "firstTimeshift": 16600,
                "lastTimeshift": 37770,
                "requestCount": 2,
                "alertCount": 1,
                "maxAlertSeverity": "1",
                "processIds": [576],
                "attributionNote": None,
                "maxAlertSeverityLevel": 1,
            }
        )
        assert endpoint.max_alert_severity_level == 1
        assert endpoint.max_alert_severity == "1"


class TestMitreV20Fields:
    def test_mitre_response(self) -> None:
        mitre = MitreResponse.model_validate(
            {
                "techniques": ["T1055", "T1685"],
                "total": 2,
                "attackVersion": "20.0",
                "domain": "enterprise",
                "items": [
                    {
                        "techniqueId": "T1055",
                        "name": "Process Injection",
                        "tacticIds": ["TA0004", "TA0005"],
                        "score": 70,
                        "scoreMaximum": 100,
                        "inVerdictChain": True,
                        "attempted": False,
                        "indicatorIds": ["65f0aa000000000000000201"],
                    },
                    {
                        "techniqueId": "T1685",
                        "name": "Disable or Modify Tools",
                        "tacticIds": ["TA0005"],
                        "score": 45,
                        "scoreMaximum": 100,
                        "inVerdictChain": False,
                        "attempted": True,
                        "indicatorIds": ["65f0aa000000000000000202"],
                    },
                ],
            }
        )
        assert (mitre.attack_version, mitre.domain) == ("20.0", "enterprise")
        assert mitre.items is not None
        assert mitre.items[0].tactic_ids == ["TA0004", "TA0005"]
        assert [item.attempted for item in mitre.items] == [False, True]

    def test_mitre_response_from_older_server(self) -> None:
        mitre = MitreResponse.model_validate({"techniques": ["T1055"], "total": 1})
        assert (mitre.attack_version, mitre.domain) == (None, None)

    def test_mobile_domain(self) -> None:
        mitre = MitreResponse.model_validate(
            {"techniques": [], "total": 0, "attackVersion": "20.0", "domain": "mobile", "items": []}
        )
        assert mitre.domain == "mobile"


def _indicator(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "65f0aa000000000000000201",
        "source": "dynamic_scan",
        "name": "Code injection into a started process",
        "description": "The sample placed code in a process that it started.",
        "summary": "The sample placed code in a process that it started.",
        "category": ["injection"],
        "level": "malicious",
        "score": 70,
        "pids": [576],
        "attackCodes": ["T1055"],
        "eventIds": [5458, 5472],
        "syscallLineNumbers": [5459, 5473],
        "author": "system",
        "scoreMaximum": 100,
    }
    row.update(overrides)
    return row


class TestIndicatorFields:
    @pytest.mark.parametrize("source", ["dynamic_scan", "yara_scanner", "config_extractor", None])
    def test_source(self, source: str | None) -> None:
        assert Indicator.model_validate(_indicator(source=source)).source == source

    def test_attempted_attack_codes(self) -> None:
        indicator = Indicator.model_validate(
            _indicator(attackCodes=["T1055", "T1685"], attemptedAttackCodes=["T1685"])
        )
        assert indicator.attempted_attack_codes == ["T1685"]

    def test_attempted_attack_codes_absent(self) -> None:
        assert Indicator.model_validate(_indicator()).attempted_attack_codes is None


def _list_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "uuid": UUID_A,
        "filename": "sample.exe",
        "sha256": SHA256,
        "url": None,
        "level": "malicious",
        "type": "file",
        "private": False,
        "tags": [{"author": "system", "type": "malicious", "value": "rat", "origin": "dynamic"}],
        "reports": [
            {
                "type": "dynamic",
                "status": "completed",
                "level": "malicious",
                "duration": 318.4,
                "format": "regular",
                "operatingSystem": {"name": "Windows 10 x64", "platform": "windows"},
                "score": 70,
            }
        ],
        "mimetype": "application/x-msdownload",
        "size": 257536,
        "overview": {
            "status": "completed",
            "jobs": {
                "total": 5,
                "succeeded": 5,
                "failed": 0,
                "skipped": 0,
                "finished": 5,
                "completed": 5,
            },
        },
        "indicators": {
            "levels": {"malicious": 3, "suspicious": 2, "benign": 8},
            "artifactCount": 1,
        },
        "createdAt": "2026-10-19T16:43:27.691Z",
    }
    item.update(overrides)
    return item


def _url_list_item() -> dict[str, Any]:
    return _list_item(
        uuid=UUID_URL,
        filename=None,
        sha256=None,
        url="https://www.example.org/",
        level="benign",
        type="url",
        tags=[],
        reports=[
            {
                "type": "url_analysis",
                "status": "completed",
                "level": "benign",
                "duration": None,
                "format": "regular",
                "operatingSystem": None,
                "score": 0,
            }
        ],
        mimetype=None,
        size=None,
        overview={"status": "completed", "jobs": None},
        indicators={"levels": {"malicious": 0, "suspicious": 0, "benign": 0}, "artifactCount": 0},
    )


def _detail(**overrides: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "uuid": UUID_A,
        "type": "file",
        "level": "malicious",
        "score": 70,
        "family": None,
        "private": False,
        "tags": [],
        "reports": [
            {
                "type": "dynamic",
                "status": "completed",
                "level": "malicious",
                "duration": 280.1,
                "format": "regular",
                "operatingSystem": {"name": "Windows 10 x64", "platform": "windows"},
                "score": 70,
                "metafields": {"Execution Duration": "120 Seconds", "Work Path": "Desktop"},
                "metafieldValues": {
                    "private": False,
                    "timeout": 120,
                    "work_path": "desktop",
                    "trace_profile": "65f0aa000000000000000301",
                },
                "executionDurationSeconds": 120,
            },
            {
                "type": "static",
                "status": "completed",
                "level": "malicious",
                "duration": 9.8,
                "format": "exe",
                "operatingSystem": None,
                "score": 100,
                "metafields": None,
                "metafieldValues": None,
                "executionDurationSeconds": None,
            },
        ],
        "overview": {"status": "completed", "jobs": None, "duration": 280.1},
        "indicators": {
            "levels": {"malicious": 6, "suspicious": 2, "benign": 11},
            "artifactCount": 1,
        },
        "mitreTechniques": ["T1055"],
        "createdAt": "2026-10-19T13:58:44.959Z",
        "updatedAt": "2026-10-19T13:59:48.038Z",
        "scoreBreakdown": None,
    }
    detail.update(overrides)
    return detail


class TestSubmissionFields:
    def test_list_url_and_null_file_fields(self) -> None:
        page = PaginatedSubmissions.model_validate(
            {
                "items": [_list_item(), _url_list_item()],
                "total": 2,
                "page": 1,
                "limit": 50,
                "totalPages": 1,
            }
        )
        file_item, url_item = page.items
        assert (file_item.url, file_item.filename, file_item.sha256) == (
            None,
            "sample.exe",
            SHA256,
        )
        assert (url_item.url, url_item.filename, url_item.sha256) == (
            "https://www.example.org/",
            None,
            None,
        )

    def test_report_metafield_values(self) -> None:
        submission = Submission.model_validate(_detail())
        dynamic, static = submission.reports
        assert dynamic.metafield_values == {
            "private": False,
            "timeout": 120,
            "work_path": "desktop",
            "trace_profile": "65f0aa000000000000000301",
        }
        assert isinstance(dynamic.metafield_values["timeout"], int)
        assert isinstance(dynamic.metafield_values["private"], bool)
        assert dynamic.execution_duration_seconds == 120
        assert (static.metafield_values, static.execution_duration_seconds) == (None, None)

    def test_url_detail_without_file_fields(self) -> None:
        submission = Submission.model_validate(
            _detail(
                uuid=UUID_URL,
                type="url",
                url="https://www.example.org/",
                reports=[
                    {
                        "type": "url_analysis",
                        "status": "completed",
                        "level": "benign",
                        "duration": None,
                        "format": "regular",
                        "operatingSystem": None,
                        "score": 0,
                        "metafields": {"Execution Duration": "180 Seconds"},
                        "metafieldValues": {"timeout": 180, "record_session": True},
                        "executionDurationSeconds": None,
                    }
                ],
            )
        )
        assert (submission.filename, submission.hashes, submission.file) == (None, None, None)
        assert submission.reports[0].metafield_values == {"timeout": 180, "record_session": True}


def _me(**plan_overrides: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "planName": "Researcher",
        "startTime": "15 October 2026",
        "endTime": "Unlimited",
        "startsAt": "2026-10-15T10:55:26.100Z",
        "endsAt": None,
        "subsTime": "infinite",
        "fileLimits": {"extensions": [], "fileSize": "3.00 GB", "fileSizeBytes": 3221225472},
        "submissionLimits": {
            "apiLimit": 1000000,
            "dailyLimit": 10000,
            "concurrentLimit": 100,
            "aiReportLimit": 20,
        },
        "permissions": {"downloadSample": True, "aiReport": True},
    }
    plan.update(plan_overrides)
    return {
        "userInfo": {
            "email": "analyst@example.com",
            "fullName": "Analyst",
            "workspace": {
                "name": "Example Workspace",
                "alias": "example-workspace",
                "private": False,
                "type": "personal",
            },
            "limitsCount": {
                "apiRequestCount": 454,
                "dailySubmissionCount": 9,
                "concurrentSubmissionCount": 0,
                "aiReportCount": 1,
                "aiReportResetsAt": "2026-10-20T00:00:00.000Z",
            },
        },
        "plan": plan,
        "modules": [
            {
                "moduleId": "65f0aa000000000000000401",
                "moduleName": "CDR",
                "startTime": "1 October 2026",
                "endTime": "1 October 2027",
                "startsAt": "2026-10-01T00:00:00.000Z",
                "endsAt": "2027-10-01T00:00:00.000Z",
            }
        ],
    }


class TestMeFields:
    def test_machine_readable_plan_fields(self) -> None:
        me = UserInfo.model_validate(_me())
        assert me.plan.starts_at == datetime(2026, 10, 15, 10, 55, 26, 100000, tzinfo=timezone.utc)
        assert me.plan.ends_at is None
        assert me.plan.file_limits.file_size_bytes == 3221225472
        assert me.modules[0].starts_at == datetime(2026, 10, 1, tzinfo=timezone.utc)
        assert me.modules[0].ends_at == datetime(2027, 10, 1, tzinfo=timezone.utc)

    def test_older_server_without_machine_fields(self) -> None:
        payload = _me()
        for key in ("startsAt", "endsAt"):
            del payload["plan"][key]
            del payload["modules"][0][key]
        del payload["plan"]["fileLimits"]["fileSizeBytes"]
        me = UserInfo.model_validate(payload)
        assert (me.plan.starts_at, me.plan.file_limits.file_size_bytes) == (None, None)


class TestRegressionShapes:
    def test_behaviour_event_fractional_timestamp(self) -> None:
        event = BehaviourEvent.model_validate(
            {
                "type": "process",
                "pid": 576,
                "ppid": 4,
                "operation": "create",
                "eventId": 1,
                "eventCount": 1,
                "timestamp": 1790376279.55,
                "details": {},
            }
        )
        assert event.timestamp == 1790376279.55

    @pytest.mark.parametrize("artifact_type", ["email_file", "email_attachment"])
    def test_email_artifact_types(self, artifact_type: str) -> None:
        artifact = Artifact.model_validate(
            {
                "id": "65f0aa000000000000000501",
                "filename": "message.eml",
                "size": 2048,
                "type": artifact_type,
                "source": "static_report",
                "hashes": {"md5": "b" * 32, "sha1": "c" * 40, "sha256": "d" * 64},
                "tags": [],
            }
        )
        assert artifact.type == artifact_type

    def test_syscall_search_busy_retry_after_seconds(self) -> None:
        result = SyscallSearchResult.model_validate(
            {
                "lines": [],
                "nextFromLine": 0,
                "scannedTo": 0,
                "totalCount": None,
                "done": False,
                "truncated": False,
                "busy": True,
                "retryAfterSeconds": 5,
            }
        )
        assert result.retry_after_seconds == 5


def _error(status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    raise_for_status(
        httpx.Response(
            status,
            json=body,
            headers=headers,
            request=httpx.Request("GET", "https://test.threat.zone/x"),
        )
    )


class TestErrorCodes:
    def test_workspace_inactive(self) -> None:
        with pytest.raises(PaymentRequiredError) as exc_info:
            _error(
                402,
                {
                    "statusCode": 402,
                    "error": "Payment Required",
                    "message": "The workspace is not active. Renew the plan.",
                    "code": "WORKSPACE_INACTIVE",
                },
            )
        assert exc_info.value.code == "WORKSPACE_INACTIVE"

    def test_plan_api_access_denied(self) -> None:
        with pytest.raises(PermissionDeniedError) as exc_info:
            _error(
                403,
                {
                    "statusCode": 403,
                    "error": "Forbidden",
                    "message": "The plan of the workspace does not include API access.",
                    "code": "PLAN_API_ACCESS_DENIED",
                },
            )
        assert exc_info.value.code == "PLAN_API_ACCESS_DENIED"

    def test_code_is_none_without_body(self) -> None:
        with pytest.raises(InternalServerError) as exc_info:
            raise_for_status(
                httpx.Response(
                    502,
                    content=b"Bad Gateway",
                    request=httpx.Request("GET", "https://test.threat.zone/x"),
                )
            )
        assert exc_info.value.code is None

    def test_validation_field(self) -> None:
        with pytest.raises(BadRequestError) as exc_info:
            _error(
                400,
                {
                    "statusCode": 400,
                    "error": "Bad Request",
                    "message": "limit must not be greater than 100",
                    "code": "INVALID_QUERY_PARAM",
                    "details": {"field": "limit"},
                },
            )
        assert (exc_info.value.code, exc_info.value.field) == ("INVALID_QUERY_PARAM", "limit")

    def test_validation_without_field(self) -> None:
        with pytest.raises(BadRequestError) as exc_info:
            _error(400, {"statusCode": 400, "message": "Bad", "code": "INVALID_QUERY_PARAM"})
        assert exc_info.value.field is None

    def test_behaviour_index_building(self) -> None:
        with pytest.raises(BehaviourIndexBuildingError) as exc_info:
            _error(
                503,
                {
                    "statusCode": 503,
                    "error": "Service Unavailable",
                    "message": "The behaviour index is being built.",
                    "code": "BEHAVIOUR_INDEX_BUILDING",
                    "details": {"retryAfterSeconds": 30},
                },
                headers={"Retry-After": "30"},
            )
        error = exc_info.value
        assert isinstance(error, BehaviourIndexingError)
        assert isinstance(error, ServiceUnavailableError)
        assert isinstance(error, InternalServerError)
        assert (error.status_code, error.code, error.retry_after) == (
            503,
            "BEHAVIOUR_INDEX_BUILDING",
            30.0,
        )

    def test_service_unavailable_retry_after_from_details(self) -> None:
        with pytest.raises(ServiceUnavailableError) as exc_info:
            _error(
                503,
                {
                    "statusCode": 503,
                    "message": "Storage is not available.",
                    "code": "STORAGE_UNAVAILABLE",
                    "details": {"retryAfterSeconds": 15},
                },
            )
        assert (exc_info.value.code, exc_info.value.retry_after) == ("STORAGE_UNAVAILABLE", 15.0)

    def test_quota_unavailable_is_service_unavailable(self) -> None:
        with pytest.raises(QuotaUnavailableError) as exc_info:
            _error(
                503,
                {
                    "statusCode": 503,
                    "message": "The quota cannot be checked.",
                    "code": "QUOTA_UNAVAILABLE",
                    "retryAfter": 10,
                    "details": {"retryAfterSeconds": 10},
                },
                headers={"Retry-After": "10"},
            )
        assert isinstance(exc_info.value, ServiceUnavailableError)
        assert exc_info.value.retry_after == 10.0

    def test_api_error_envelope_with_field(self) -> None:
        error = ApiError.model_validate(
            {
                "statusCode": 400,
                "error": "Bad Request",
                "message": "limit must not be greater than 100",
                "code": "INVALID_QUERY_PARAM",
                "details": {"field": "limit"},
            }
        )
        assert error.details == {"field": "limit"}
