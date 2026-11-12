"""Deprecated SDK parameters warn and keep working."""

from __future__ import annotations

import ast
import inspect
import textwrap
import warnings
from typing import Any

import httpx
import pytest

from threatzone import AsyncThreatZone, ThreatZone
from threatzone.types import UrlAnalysisIpInfo, UrlAnalysisResponse

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


def _field_docstring(model: type, field_name: str) -> str | None:
    """Return the string literal that follows the field annotation in the class body."""
    class_def = ast.parse(textwrap.dedent(inspect.getsource(model))).body[0]
    assert isinstance(class_def, ast.ClassDef)
    statements = class_def.body
    for index, statement in enumerate(statements[:-1]):
        target = statement.target if isinstance(statement, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == field_name:
            following = statements[index + 1]
            if isinstance(following, ast.Expr) and isinstance(following.value, ast.Constant):
                value = following.value.value
                return value if isinstance(value, str) else None
            return None
    return None


@pytest.mark.parametrize(
    ("model", "field_name", "expected_start"),
    [
        (
            UrlAnalysisResponse,
            "extracted_file",
            "Deprecated: never populated; always None. Use downloaded_files.",
        ),
        (UrlAnalysisIpInfo, "threat_status", "Deprecated: no source writes it."),
    ],
)
def test_deprecated_report_fields_say_so(model: type, field_name: str, expected_start: str) -> None:
    docstring = _field_docstring(model, field_name)
    assert docstring is not None
    assert docstring.startswith(expected_start)


def test_deprecated_report_fields_still_parse() -> None:
    info = UrlAnalysisIpInfo.model_validate(
        {
            "ip": "203.0.113.42",
            "threatStatus": {"verdict": "unknown", "title": "", "description": ""},
        }
    )
    assert info.threat_status.verdict == "unknown"
    assert UrlAnalysisResponse.model_fields["extracted_file"].default is None
