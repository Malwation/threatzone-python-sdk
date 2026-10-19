"""Retry policy, error bodies of downloads, and the opt-in list envelope."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from threatzone import (
    AsyncThreatZone,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ServiceUnavailableError,
    ThreatZone,
    TimeoutError,
)
from threatzone import _client as client_module

BASE_URL = "https://fake.threat.zone/public-api"
UUID = "00000000-0000-4000-8000-000000000001"

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []

    def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)

    async def fake_async_sleep(seconds: float) -> None:
        recorded.append(seconds)

    monkeypatch.setattr(client_module, "_sleep", fake_sleep)
    monkeypatch.setattr(client_module, "_async_sleep", fake_async_sleep)
    return recorded


def _sequence(*steps: httpx.Response | Exception) -> tuple[Handler, list[httpx.Request]]:
    seen: list[httpx.Request] = []
    queue = list(steps)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        step = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(step, Exception):
            raise step
        return step

    return handler, seen


def _sync(handler: Handler, **kwargs: Any) -> ThreatZone:
    return ThreatZone(
        api_key="test-key",
        base_url=BASE_URL,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def _async(handler: Handler, **kwargs: Any) -> AsyncThreatZone:
    return AsyncThreatZone(
        api_key="test-key",
        base_url=BASE_URL,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def _json(status: int, body: Any, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


def _busy(status: int = 503, retry_after: str | None = "2") -> httpx.Response:
    body = {
        "statusCode": status,
        "error": "Service Unavailable" if status == 503 else "Too Many Requests",
        "message": "Busy",
        "code": "STORAGE_UNAVAILABLE" if status == 503 else "RATE_LIMIT_EXCEEDED",
        "details": {"retryAfterSeconds": int(retry_after)} if retry_after else None,
    }
    return _json(status, body, {"Retry-After": retry_after} if retry_after else None)


_ME = {
    "userInfo": {
        "email": "analyst@example.com",
        "fullName": "Analyst",
        "workspace": {"name": "W", "alias": "w", "private": False, "type": "personal"},
        "limitsCount": {
            "apiRequestCount": 1,
            "dailySubmissionCount": 0,
            "concurrentSubmissionCount": 0,
        },
    },
    "plan": {
        "planName": "P",
        "startTime": "1 January 2026",
        "endTime": "Unlimited",
        "subsTime": "infinite",
        "fileLimits": {"extensions": [], "fileSize": "1.00 GB"},
        "submissionLimits": {"apiLimit": 10, "dailyLimit": 10, "concurrentLimit": 1},
    },
    "modules": [],
}

_CREATED = {"uuid": UUID, "message": "Submission created", "sha256": "a" * 64}


class TestIdempotentRetries:
    @pytest.mark.parametrize("status", [429, 503])
    def test_get_retries_after_retry_after(self, status: int, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(status, "2"), _json(200, _ME))
        with _sync(handler) as client:
            assert client.get_user_info().email == "analyst@example.com"
        assert len(seen) == 2
        assert sleeps == [2.0]

    def test_retry_without_header_uses_backoff(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(503, None), _busy(503, None), _json(200, _ME))
        with _sync(handler) as client:
            client.get_user_info()
        assert len(seen) == 3
        assert sleeps == [1.0, 2.0]

    def test_retries_are_bounded(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(503, "1"))
        with _sync(handler, max_retries=2) as client, pytest.raises(ServiceUnavailableError) as e:
            client.get_user_info()
        assert len(seen) == 3
        assert sleeps == [1.0, 1.0]
        assert e.value.retry_after == 1.0

    def test_long_retry_after_is_not_waited(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(429, "3600"), _json(200, _ME))
        with _sync(handler) as client, pytest.raises(RateLimitError) as exc_info:
            client.get_user_info()
        assert len(seen) == 1
        assert sleeps == []
        assert exc_info.value.retry_after == 3600.0

    def test_max_retries_zero_disables_retries(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(503, "1"), _json(200, _ME))
        with _sync(handler, max_retries=0) as client, pytest.raises(ServiceUnavailableError):
            client.get_user_info()
        assert len(seen) == 1
        assert sleeps == []

    def test_other_errors_are_not_retried(self, sleeps: list[float]) -> None:
        body = {
            "statusCode": 403,
            "message": "The plan has no API access.",
            "code": "PLAN_API_ACCESS_DENIED",
        }
        handler, seen = _sequence(_json(403, body))
        with _sync(handler) as client, pytest.raises(PermissionDeniedError):
            client.get_user_info()
        assert len(seen) == 1
        assert sleeps == []

    def test_put_is_retried(self, sleeps: list[float]) -> None:
        annotations = {
            "submissionUuid": UUID,
            "pins": [],
            "note": {
                "text": "x",
                "updatedBy": "analyst@example.com",
                "updatedAt": "2026-10-19T10:30:00.000Z",
            },
        }
        handler, seen = _sequence(_busy(503, "1"), _json(200, annotations))
        with _sync(handler) as client:
            assert client.set_note(UUID, "x").note is not None
        assert len(seen) == 2
        assert sleeps == [1.0]

    async def test_async_get_retries(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(429, "2"), _json(200, _ME))
        async with _async(handler) as client:
            assert (await client.get_user_info()).email == "analyst@example.com"
        assert len(seen) == 2
        assert sleeps == [2.0]


class TestNonIdempotentRequests:
    def test_upload_read_timeout_is_not_retried(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(httpx.ReadTimeout("read timed out"), _json(200, _CREATED))
        with _sync(handler) as client, pytest.raises(TimeoutError):
            client.create_sandbox_submission(b"MZ")
        assert len(seen) == 1
        assert sleeps == []

    def test_url_submission_write_timeout_is_not_retried(self) -> None:
        handler, seen = _sequence(httpx.WriteTimeout("write timed out"), _json(200, _CREATED))
        with _sync(handler) as client, pytest.raises(TimeoutError):
            client.create_url_submission("https://www.example.org/")
        assert len(seen) == 1

    def test_upload_connect_error_is_retried(self) -> None:
        handler, seen = _sequence(httpx.ConnectError("refused"), _json(200, _CREATED))
        with _sync(handler) as client:
            assert client.create_sandbox_submission(b"MZ").uuid == UUID
        assert len(seen) == 2

    def test_upload_connect_timeout_is_retried(self) -> None:
        handler, seen = _sequence(httpx.ConnectTimeout("connect timed out"), _json(200, _CREATED))
        with _sync(handler) as client:
            assert client.create_sandbox_submission(b"MZ").uuid == UUID
        assert len(seen) == 2

    def test_post_503_is_not_retried(self, sleeps: list[float]) -> None:
        body = {
            "statusCode": 503,
            "message": "The quota cannot be checked.",
            "code": "QUOTA_UNAVAILABLE",
            "retryAfter": 5,
        }
        handler, seen = _sequence(_json(503, body, {"Retry-After": "5"}), _json(200, _CREATED))
        with _sync(handler) as client, pytest.raises(ServiceUnavailableError):
            client.create_sandbox_submission(b"MZ")
        assert len(seen) == 1
        assert sleeps == []

    def test_get_read_timeout_is_retried(self) -> None:
        handler, seen = _sequence(httpx.ReadTimeout("read timed out"), _json(200, _ME))
        with _sync(handler) as client:
            client.get_user_info()
        assert len(seen) == 2

    async def test_async_upload_read_timeout_is_not_retried(self) -> None:
        handler, seen = _sequence(httpx.ReadTimeout("read timed out"), _json(200, _CREATED))
        async with _async(handler) as client:
            with pytest.raises(TimeoutError):
                await client.create_sandbox_submission(b"MZ")
        assert len(seen) == 1


_SAMPLE_GONE = {
    "statusCode": 404,
    "error": "Not Found",
    "message": "The sample file is not available.",
    "code": "SAMPLE_NOT_AVAILABLE",
}


class TestDownloads:
    def test_download_error_keeps_code(self) -> None:
        handler, _ = _sequence(_json(404, _SAMPLE_GONE))
        with _sync(handler) as client, pytest.raises(NotFoundError) as exc_info:
            client.download_sample(UUID)
        assert exc_info.value.code == "SAMPLE_NOT_AVAILABLE"
        assert exc_info.value.message == "The sample file is not available."

    async def test_async_download_error_keeps_code(self) -> None:
        handler, _ = _sequence(_json(404, _SAMPLE_GONE))
        async with _async(handler) as client:
            with pytest.raises(NotFoundError) as exc_info:
                await client.download_sample(UUID)
        assert exc_info.value.code == "SAMPLE_NOT_AVAILABLE"

    def test_download_retries_on_503(self, sleeps: list[float]) -> None:
        handler, seen = _sequence(_busy(503, "1"), httpx.Response(200, content=b"PCAP"))
        with _sync(handler) as client:
            assert client.download_pcap(UUID).read() == b"PCAP"
        assert len(seen) == 2
        assert sleeps == [1.0]

    async def test_async_download_retries_on_429(self) -> None:
        handler, seen = _sequence(_busy(429, "1"), httpx.Response(200, content=b"PCAP"))
        async with _async(handler) as client:
            assert await (await client.download_pcap(UUID)).read() == b"PCAP"
        assert len(seen) == 2


def _tcp(idx: int) -> dict[str, Any]:
    return {
        "id": f"65f0aa00000000000000010{idx}",
        "protocol": "tcp",
        "destinationIp": "203.0.113.7",
        "destinationPort": 443,
        "packets": {"sent": 1, "received": 1, "empty": False},
        "connectOutcome": "established",
        "timeshift": 1.5,
    }


def _envelope_handler() -> tuple[Handler, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path.removeprefix("/public-api")
        envelope = request.url.params.get("envelope") == "1"
        if path.endswith("/network/tcp"):
            items = [_tcp(1), _tcp(2)]
            if envelope:
                return _json(
                    200,
                    {
                        "items": items,
                        "total": 7,
                        "page": 1,
                        "pageSize": 2,
                        "next": f"/public-api/submissions/{UUID}/network/tcp?skip=2&limit=2&envelope=1",
                    },
                )
            return _json(200, items, {"X-Total-Count": "7", "Deprecation": "@1792368000"})
        if path == "/config/environments":
            items = [
                {
                    "key": "w10_x64",
                    "name": "Windows 10 x64",
                    "platform": "windows",
                    "default": True,
                    "active": True,
                    "accessible": True,
                }
            ]
            if envelope:
                return _json(
                    200, {"items": items, "total": 1, "page": 1, "pageSize": 1, "next": None}
                )
            return _json(200, items)
        if path.startswith("/submissions/search/sha256/"):
            return _json(200, [], {"X-Total-Count": "35"})
        return _json(404, {"statusCode": 404, "message": "x", "code": "NOT_FOUND"})

    return handler, seen


class TestListEnvelope:
    def test_off_by_default(self) -> None:
        handler, seen = _envelope_handler()
        with _sync(handler) as client:
            rows = client.get_tcp_connections(UUID, limit=2)
        assert "envelope" not in seen[0].url.params
        assert rows.total_count == 7
        assert [row.connect_outcome for row in rows] == ["established", "established"]

    def test_opt_in_sends_envelope_and_unwraps(self) -> None:
        handler, seen = _envelope_handler()
        with _sync(handler, list_envelope=True) as client:
            rows = client.get_tcp_connections(UUID, limit=2)
            environments = client.get_environments()
        assert [request.url.params.get("envelope") for request in seen] == ["1", "1"]
        assert rows.total_count == 7
        assert len(rows) == 2
        assert environments[0].name == "Windows 10 x64"

    def test_envelope_not_sent_to_detail_routes(self) -> None:
        handler, seen = _envelope_handler()
        with _sync(handler, list_envelope=True) as client, pytest.raises(NotFoundError):
            client.get_submission(UUID)
        assert "envelope" not in seen[0].url.params

    async def test_async_opt_in(self) -> None:
        handler, seen = _envelope_handler()
        async with _async(handler, list_envelope=True) as client:
            rows = await client.get_tcp_connections(UUID, limit=2)
        assert seen[0].url.params.get("envelope") == "1"
        assert rows.total_count == 7

    def test_paged_models_read_page_size_and_next(self) -> None:
        body = {
            "items": [],
            "total": 120,
            "page": 1,
            "limit": 50,
            "totalPages": 3,
            "pageSize": 50,
            "next": "/public-api/submissions?page=2&limit=50&envelope=1",
        }

        def handler(_: httpx.Request) -> httpx.Response:
            return _json(200, body)

        with _sync(handler, list_envelope=True) as client:
            page = client.list_submissions(limit=50)
        assert (page.page_size, page.next) == (
            50,
            "/public-api/submissions?page=2&limit=50&envelope=1",
        )

    def test_sha256_search_total(self) -> None:
        handler, _ = _envelope_handler()
        with _sync(handler) as client:
            result = client.search_by_sha256("a" * 64)
        assert result == []
        assert result.total_count == 35


class TestExfilAttribution:
    def test_attribution_param(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return _json(200, [], {"X-Total-Count": "0"})

        with _sync(handler) as client:
            client.get_network_exfil_requests(UUID, attribution=["sample", "sample_child"])
        assert seen[0].url.params.get("attribution") == "sample,sample_child"
