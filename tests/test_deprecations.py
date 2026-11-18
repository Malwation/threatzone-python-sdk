"""Deprecated SDK parameters and fields warn and keep working."""

from __future__ import annotations

import ast
import inspect
import textwrap
import warnings
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from threatzone import AsyncThreatZone, ThreatZone, types
from threatzone.types import (
    IndicatorRelated,
    IoC,
    RunNote,
    UrlAnalysisIpInfo,
    UrlAnalysisResponse,
    VerdictDecisive,
)

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
    with pytest.warns(DeprecationWarning, match="threat_status"):
        status = info.threat_status
    assert status is not None
    assert status.verdict == "unknown"
    assert UrlAnalysisResponse.model_fields["extracted_file"].default is None


def _deprecated_fields() -> list[tuple[type[BaseModel], str]]:
    found = []
    for name in dir(types):
        model = getattr(types, name)
        if not (isinstance(model, type) and issubclass(model, BaseModel)):
            continue
        own = vars(model).get("__annotations__", {})
        for field_name, field in model.model_fields.items():
            if field.deprecated and field_name in own:
                found.append((model, field_name))
    return found


_DEPRECATED = _deprecated_fields()


def test_api_deprecations_are_marked() -> None:
    marked = {f"{model.__name__}.{field}" for model, field in _DEPRECATED}
    assert {
        "Indicator.rule_source",
        "Indicator.score_factors",
        "Indicator.score_result",
        "Indicator.score_cap",
        "Indicator.finding_source",
        "Indicator.author",
        "Indicator.score_maximum",
        "IndicatorRelated.signal_id",
        "VerdictDecisive.source",
        "Verdict.format",
        "ScoreBreakdown.deciding_layer",
        "IoC.raw_type",
        "KillchainDroppedFile.raw_path",
        "KillchainDroppedFile.path_authority",
        "KillchainInventoryCoverage.counts",
        "KillchainProcess.tid",
        "Process.tid",
        "Artifact.process_attribution",
        "NetworkEndpoint.max_alert_severity",
        "UrlAnalysisResponse.job_id",
        "UrlAnalysisResponse.verdict_provenance",
        "UrlAnalysisResponse.extracted_file",
        "UrlAnalysisIpInfo.threat_status",
        "UrlScoreIndicator.weighted_points",
        "UrlScoreExplanation.scoring_version",
    } <= marked


@pytest.mark.parametrize(
    ("model", "field_name"), _DEPRECATED, ids=[f"{m.__name__}.{f}" for m, f in _DEPRECATED]
)
def test_deprecated_field_is_optional_and_documented(
    model: type[BaseModel], field_name: str
) -> None:
    assert not model.model_fields[field_name].is_required()
    docstring = _field_docstring(model, field_name)
    assert docstring is not None
    assert docstring.startswith("Deprecated:")


@pytest.mark.parametrize(
    ("model", "field_name"), _DEPRECATED, ids=[f"{m.__name__}.{f}" for m, f in _DEPRECATED]
)
def test_deprecated_field_warns_on_read(model: type[BaseModel], field_name: str) -> None:
    instance = model.model_construct()
    with pytest.warns(DeprecationWarning, match=field_name):
        getattr(instance, field_name)


def test_fields_the_api_removes_next_may_be_absent() -> None:
    related = IndicatorRelated.model_validate({"eventId": 7, "text": "Read the key."})
    decisive = VerdictDecisive.model_validate({"text": "Child process image replaced."})
    note = RunNote.model_validate({"text": "The sample exited early."})
    assert related.model_dump()["signal_id"] is None
    assert decisive.model_dump()["source"] is None
    assert note.code is None


def test_dump_of_a_deprecated_field_does_not_warn() -> None:
    row = IoC.model_validate(
        {"type": "ip", "value": "203.0.113.7", "artifacts": [], "rawType": "IP"}
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert row.model_dump(by_alias=True)["rawType"] == "IP"
        repr(row)
