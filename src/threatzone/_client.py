"""Base HTTP client logic for the Threat.Zone Python SDK."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from collections.abc import Mapping
from io import IOBase
from pathlib import Path
from typing import Any, BinaryIO

import httpx

from ._config import ClientConfig
from ._constants import MAX_RETRY_AFTER_SECONDS
from ._exceptions import (
    ConnectionError,
    TimeoutError,
    raise_for_status,
    retry_after_seconds,
)
from ._streaming import AsyncDownloadResponse, DownloadResponse

FileInput = BinaryIO | bytes | str | Path | IOBase

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_RETRY_STATUSES = frozenset({429, 503})
_SAFE_TIMEOUTS = (httpx.ConnectTimeout, httpx.PoolTimeout)

_LIST_ROUTE = re.compile(
    r"^/(?:"
    r"config/(?:metafields/[^/]+|environments|device-presets)"
    r"|(?:v1/)?network-configs"
    r"|submissions(?:/search/sha256/[^/]+)?"
    r"|submissions/[^/]+/(?:behaviours|media|indicators|iocs|yara-rules|extracted-configs"
    r"|artifacts|artifacts/[^/]+/jobs|eml-analysis|processes|syscalls"
    r"|network/(?:dns|http|tcp|udp|threats|exfil-requests|endpoints))"
    r")$"
)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


async def _async_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _is_idempotent(method: str) -> bool:
    return method.upper() in _IDEMPOTENT_METHODS


def _timeout_error(method: str, exc: httpx.TimeoutException) -> TimeoutError:
    if _is_idempotent(method) or isinstance(exc, _SAFE_TIMEOUTS):
        return TimeoutError(f"Request timed out: {exc}")
    return TimeoutError(
        f"Request timed out: {exc}. The server can have received the request, "
        "so the SDK did not send it again. Check the result before you send it again."
    )


def _may_retry_timeout(method: str, exc: httpx.TimeoutException) -> bool:
    return _is_idempotent(method) or isinstance(exc, _SAFE_TIMEOUTS)


def _response_body(response: httpx.Response) -> dict[str, Any] | None:
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError, httpx.ResponseNotRead):
        return None
    return body if isinstance(body, dict) else None


def _status_retry_delay(method: str, response: httpx.Response, attempt: int) -> float | None:
    """Return the wait before a retry of a busy idempotent request, or ``None`` for no retry."""
    if response.status_code not in _RETRY_STATUSES or not _is_idempotent(method):
        return None
    delay = retry_after_seconds(response, _response_body(response))
    if delay is None:
        return float(2**attempt)
    if delay < 0 or delay > MAX_RETRY_AFTER_SECONDS:
        return None
    return delay


def is_list_route(path: str) -> bool:
    """``True`` for a list route that accepts the ``envelope`` parameter."""
    return _LIST_ROUTE.match(path) is not None


class BaseClient:
    """Base class with shared HTTP logic for sync and async clients."""

    def __init__(self, config: ClientConfig) -> None:
        self._config = config
        self._file_stack: contextlib.ExitStack = contextlib.ExitStack()

    def _prepare_file_upload(
        self,
        file: FileInput,
        field_name: str = "file",
    ) -> tuple[str, tuple[str, BinaryIO | bytes | IOBase, str]]:
        """Prepare a file for multipart upload.

        For file paths, opens the file and passes the handle directly to enable
        streaming uploads without loading the entire file into memory.
        """
        content: BinaryIO | bytes | IOBase
        if isinstance(file, (str, Path)):
            path = Path(file)
            file_handle = self._file_stack.enter_context(path.open("rb"))
            filename = path.name
            content = file_handle
        elif isinstance(file, bytes):
            content = file
            filename = "file"
        elif hasattr(file, "read"):
            filename = Path(file.name).name if hasattr(file, "name") else "file"
            content = file
        else:
            raise TypeError(f"Unsupported file type: {type(file)}")

        return field_name, (filename, content, "application/octet-stream")

    def _query_params(
        self, method: str, path: str, params: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        filtered = {k: v for k, v in (params or {}).items() if v is not None}
        if self._config.list_envelope and method.upper() == "GET" and is_list_route(path):
            filtered["envelope"] = 1
        return filtered or None

    def _cleanup_files(self) -> None:
        """Close any file handles opened during file upload preparation."""
        with contextlib.suppress(Exception):
            self._file_stack.close()
        self._file_stack = contextlib.ExitStack()

    def _build_multipart_data(
        self,
        file: FileInput,
        **fields: Any,
    ) -> dict[str, Any]:
        """Build multipart form data with file and additional fields."""
        file_tuple = self._prepare_file_upload(file)

        files = {file_tuple[0]: file_tuple[1]}

        data: dict[str, Any] = {}
        for key, value in fields.items():
            if value is None:
                continue
            if key == "metafields" and isinstance(value, list):
                # Accept both formats:
                # - {"timeout": 120, "internet_connection": True}
                # - [{"key": "timeout", "value": 120}, ...]
                # Normalize to the object-map format expected by the Public API.
                normalized: dict[str, Any] = {}
                for item in value:
                    if not isinstance(item, dict) or "key" not in item:
                        raise TypeError(
                            "metafields list items must be dicts with at least a 'key' field"
                        )
                    k = str(item["key"])
                    normalized[k] = item.get("value")
                import json

                data[key] = json.dumps(normalized)
                continue
            if isinstance(value, bool):
                data[key] = str(value).lower()
            elif isinstance(value, (list, dict)):
                import json

                data[key] = json.dumps(value)
            else:
                data[key] = str(value)

        return {"files": files, "data": data}


class SyncHTTPClient(BaseClient):
    """Synchronous HTTP client wrapper."""

    def __init__(
        self,
        config: ClientConfig,
        *,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(config)
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=httpx.Timeout(config.timeout),
                follow_redirects=True,
                verify=config.verify_ssl,
            )
            self._owns_client = True

    def close(self) -> None:
        """Close the HTTP client.

        If the client was supplied by the caller via ``http_client=``, the SDK does not
        close it — the caller retains ownership and is responsible for cleanup.
        """
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> SyncHTTPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with error handling and retries.

        Connection failures are retried for every method. A timeout is retried only for an
        idempotent method, or when the request was not sent (connect or pool timeout). A
        ``429`` or ``503`` response to an idempotent request is retried after its
        ``Retry-After`` wait when the wait is at most ``MAX_RETRY_AFTER_SECONDS``.
        """
        url = self._config.build_url(path)
        request_headers = {**self._config.get_headers(), **(headers or {})}
        query = self._query_params(method, path, params)
        max_retries = self._config.max_retries

        for attempt in range(max_retries + 1):
            last_attempt = attempt == max_retries
            try:
                response = self._client.request(
                    method,
                    url,
                    params=query,
                    json=json,
                    data=data,
                    files=files,
                    headers=request_headers,
                )
            except httpx.TimeoutException as e:
                if last_attempt or not _may_retry_timeout(method, e):
                    raise _timeout_error(method, e) from e
                _sleep(2**attempt)
                continue
            except httpx.ConnectError as e:
                if last_attempt:
                    raise ConnectionError(f"Failed to connect: {e}") from e
                _sleep(2**attempt)
                continue

            delay = None if last_attempt else _status_retry_delay(method, response, attempt)
            if delay is None:
                raise_for_status(response)
                return response
            response.close()
            _sleep(delay)

        raise RuntimeError("Unexpected end of the request retry loop")

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a GET request."""
        return self._request("GET", path, params=params)

    def post(
        self,
        path: str,
        *,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a POST request."""
        try:
            return self._request("POST", path, json=json, data=data, files=files)
        finally:
            self._cleanup_files()

    def put(self, path: str, *, json: Any | None = None) -> httpx.Response:
        """Make a PUT request."""
        return self._request("PUT", path, json=json)

    def delete(self, path: str) -> httpx.Response:
        """Make a DELETE request without a body."""
        return self._request("DELETE", path)

    def get_stream(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> DownloadResponse:
        """Make a GET request and return a streaming response.

        An error response is read before it is raised, so the error keeps its ``code``.
        Retries follow the rules of ``_request()`` for a ``GET``.
        """
        url = self._config.build_url(path)
        headers = self._config.get_headers()
        query = self._query_params("GET", path, params)
        max_retries = self._config.max_retries

        for attempt in range(max_retries + 1):
            last_attempt = attempt == max_retries
            stream_context = self._client.stream("GET", url, params=query, headers=headers)
            try:
                response = stream_context.__enter__()
            except httpx.TimeoutException as e:
                if last_attempt:
                    raise TimeoutError(f"Request timed out: {e}") from e
                _sleep(2**attempt)
                continue
            except httpx.ConnectError as e:
                if last_attempt:
                    raise ConnectionError(f"Failed to connect: {e}") from e
                _sleep(2**attempt)
                continue

            if response.is_success:
                return DownloadResponse(response, stream_context=stream_context)
            try:
                response.read()
                delay = None if last_attempt else _status_retry_delay("GET", response, attempt)
                if delay is None:
                    raise_for_status(response)
                    return DownloadResponse(response, stream_context=stream_context)
            except BaseException:
                stream_context.__exit__(None, None, None)
                raise
            stream_context.__exit__(None, None, None)
            _sleep(delay)

        raise RuntimeError("Unexpected end of the download retry loop")


class AsyncHTTPClient(BaseClient):
    """Asynchronous HTTP client wrapper."""

    def __init__(
        self,
        config: ClientConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(config)
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(config.timeout),
                follow_redirects=True,
                verify=config.verify_ssl,
            )
            self._owns_client = True

    async def close(self) -> None:
        """Close the HTTP client.

        If the client was supplied by the caller via ``http_client=``, the SDK does not
        close it — the caller retains ownership and is responsible for cleanup.
        """
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncHTTPClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with error handling and retries.

        Connection failures are retried for every method. A timeout is retried only for an
        idempotent method, or when the request was not sent (connect or pool timeout). A
        ``429`` or ``503`` response to an idempotent request is retried after its
        ``Retry-After`` wait when the wait is at most ``MAX_RETRY_AFTER_SECONDS``.
        """
        url = self._config.build_url(path)
        request_headers = {**self._config.get_headers(), **(headers or {})}
        query = self._query_params(method, path, params)
        max_retries = self._config.max_retries

        for attempt in range(max_retries + 1):
            last_attempt = attempt == max_retries
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=query,
                    json=json,
                    data=data,
                    files=files,
                    headers=request_headers,
                )
            except httpx.TimeoutException as e:
                if last_attempt or not _may_retry_timeout(method, e):
                    raise _timeout_error(method, e) from e
                await _async_sleep(2**attempt)
                continue
            except httpx.ConnectError as e:
                if last_attempt:
                    raise ConnectionError(f"Failed to connect: {e}") from e
                await _async_sleep(2**attempt)
                continue

            delay = None if last_attempt else _status_retry_delay(method, response, attempt)
            if delay is None:
                raise_for_status(response)
                return response
            await response.aclose()
            await _async_sleep(delay)

        raise RuntimeError("Unexpected end of the request retry loop")

    async def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a GET request."""
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        *,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a POST request."""
        try:
            return await self._request("POST", path, json=json, data=data, files=files)
        finally:
            self._cleanup_files()

    async def put(self, path: str, *, json: Any | None = None) -> httpx.Response:
        """Make a PUT request."""
        return await self._request("PUT", path, json=json)

    async def delete(self, path: str) -> httpx.Response:
        """Make a DELETE request without a body."""
        return await self._request("DELETE", path)

    async def get_stream(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> AsyncDownloadResponse:
        """Make a GET request and return a streaming response.

        An error response is read before it is raised, so the error keeps its ``code``.
        Retries follow the rules of ``_request()`` for a ``GET``.
        """
        url = self._config.build_url(path)
        headers = self._config.get_headers()
        query = self._query_params("GET", path, params)
        max_retries = self._config.max_retries

        for attempt in range(max_retries + 1):
            last_attempt = attempt == max_retries
            stream_context = self._client.stream("GET", url, params=query, headers=headers)
            try:
                response = await stream_context.__aenter__()
            except httpx.TimeoutException as e:
                if last_attempt:
                    raise TimeoutError(f"Request timed out: {e}") from e
                await _async_sleep(2**attempt)
                continue
            except httpx.ConnectError as e:
                if last_attempt:
                    raise ConnectionError(f"Failed to connect: {e}") from e
                await _async_sleep(2**attempt)
                continue

            if response.is_success:
                return AsyncDownloadResponse(response, stream_context=stream_context)
            try:
                await response.aread()
                delay = None if last_attempt else _status_retry_delay("GET", response, attempt)
                if delay is None:
                    raise_for_status(response)
                    return AsyncDownloadResponse(response, stream_context=stream_context)
            except BaseException:
                await stream_context.__aexit__(None, None, None)
                raise
            await stream_context.__aexit__(None, None, None)
            await _async_sleep(delay)

        raise RuntimeError("Unexpected end of the download retry loop")
