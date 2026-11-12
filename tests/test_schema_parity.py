"""The URL analysis model keeps every field of the documented v1 response.

``fixtures/url_analysis_response.json`` is a verbatim copy of the v1 response example in the
Public API guide (``docs/api/url-analysis.md``). Copy the example again when the guide changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from threatzone.types import UrlAnalysisResponse

FIXTURE = Path(__file__).parent / "fixtures" / "url_analysis_response.json"


def _missing_keys(expected: Any, actual: Any, path: str = "$") -> list[str]:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [path]
        missing: list[str] = []
        for key, value in expected.items():
            if key not in actual:
                missing.append(f"{path}.{key}")
            else:
                missing.extend(_missing_keys(value, actual[key], f"{path}.{key}"))
        return missing
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return [path]
        return [
            key
            for index, (item, dumped) in enumerate(zip(expected, actual, strict=True))
            for key in _missing_keys(item, dumped, f"{path}[{index}]")
        ]
    return []


@pytest.fixture
def documented_response() -> dict[str, Any]:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_model_dump_keeps_every_documented_key(documented_response: dict[str, Any]) -> None:
    dumped = UrlAnalysisResponse.model_validate(documented_response).model_dump(
        by_alias=True, exclude_unset=False
    )

    assert _missing_keys(documented_response, dumped) == []


def test_documented_response_parses_the_new_fields(documented_response: dict[str, Any]) -> None:
    report = UrlAnalysisResponse.model_validate(documented_response)

    assert [item.state for item in report.downloaded_files] == ["completed", "incomplete"]
    assert report.score_state == "scored"
    assert report.extracted_file is None
    assert report.completeness is not None
    assert report.completeness.browser_collection_note is not None
    assert report.browser_snapshot is not None
    assert report.browser_snapshot.sections == ["overview", "findings", "tls", "network-summary"]
    assert report.threat_analysis is not None
    assert [node.via for node in report.threat_analysis.url_results] == [
        "submitted",
        "http_redirect",
    ]


def test_missing_keys_reports_a_dropped_nested_key() -> None:
    expected = {"a": {"b": 1, "c": [{"d": 2}]}}
    actual = {"a": {"b": 1, "c": [{}]}}

    assert _missing_keys(expected, actual) == ["$.a.c[0].d"]
