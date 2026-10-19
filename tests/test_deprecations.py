"""Deprecated SDK parameters warn and keep working."""

from __future__ import annotations

import warnings
from typing import Any

import httpx
import pytest

from threatzone import AsyncThreatZone, ThreatZone

UUID = "00000000-0000-4000-8000-000000000001"
_PAGE = {"items": [], "total": 0, "page": 1, "limit": 20, "totalPages": 0}


def _handler(seen: list[httpx.Request]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_PAGE)

    return handler


@pytest.mark.parametrize(
    ("kwargs", "param", "replacement"),
    [
        ({"type": "file"}, "type", "types"),
        ({"pid": 576}, "pid", "pids"),
        ({"operation": "create"}, "operation", "operations"),
        ({"process_name": "sample.exe"}, "processName", "process_name_contains"),
    ],
)
def test_singular_behaviour_filters_warn(
    kwargs: dict[str, Any], param: str, replacement: str
) -> None:
    seen: list[httpx.Request] = []
    client = ThreatZone(
        api_key="k",
        base_url="https://fake.threat.zone/public-api",
        http_client=httpx.Client(transport=httpx.MockTransport(_handler(seen))),
    )
    with pytest.warns(DeprecationWarning, match=replacement):
        client.get_behaviours(UUID, **kwargs)
    assert param in seen[0].url.params


def test_plural_filters_do_not_warn() -> None:
    seen: list[httpx.Request] = []
    client = ThreatZone(
        api_key="k",
        base_url="https://fake.threat.zone/public-api",
        http_client=httpx.Client(transport=httpx.MockTransport(_handler(seen))),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        client.get_behaviours(UUID, types=["file"], pids=[576])


async def test_async_singular_filter_warns() -> None:
    seen: list[httpx.Request] = []
    client = AsyncThreatZone(
        api_key="k",
        base_url="https://fake.threat.zone/public-api",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(_handler(seen))),
    )
    with pytest.warns(DeprecationWarning, match="pids"):
        await client.get_behaviours(UUID, pid=576)
