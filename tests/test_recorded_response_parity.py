"""Every key of a recorded Public API response survives the SDK model.

``fixtures/recorded/<run>/<route>.json`` holds real staging responses of five runs (three
Windows file runs, an Android APK and a URL analysis) with only the shape kept: names, paths,
hosts, sentences, hashes, IDs and addresses are replaced, lists are cut. Keys, nesting, value
types and short code values such as the DNS ``type`` ``"-"`` are as the API sent them.

``scripts/scrub-recorded-responses.py <run dir> <fixture dir>`` makes a fixture directory from
the raw responses of one run.

The models ignore unknown keys, so a field that the API adds is dropped without an error.
This test fails on every dropped key. When it fails, model the new field.

Set ``THREATZONE_RECORDED_RESPONSES`` to a directory of unscrubbed responses
(``<uuid>/<route>.json``) to run the same check against them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, TypeAdapter

from threatzone import types as T

FIXTURES = Path(__file__).parent / "fixtures" / "recorded"

_LIST_ROUTES: dict[str, type[BaseModel]] = {
    "network_dns_limit_5": T.DnsQuery,
    "network_http_limit_5": T.HttpRequest,
    "network_tcp_limit_5": T.Connection,
    "network_udp_limit_3": T.Connection,
    "network_threats_limit_10": T.NetworkThreat,
    "network_exfil-requests": T.NetworkExfilRequest,
    "eml-analysis": T.EmlAnalysis,
}

_ROUTES: dict[str, type[BaseModel]] = {
    "root": T.Submission,
    "summary": T.OverviewSummary,
    "indicators": T.IndicatorsResponse,
    "indicators_limit_100": T.IndicatorsResponse,
    "iocs": T.IoCsResponse,
    "iocs_limit_50": T.IoCsResponse,
    "yara-rules": T.YaraRulesResponse,
    "extracted-configs": T.ExtractedConfigsResponse,
    "artifacts": T.ArtifactsResponse,
    "mitre": T.MitreResponse,
    "static-scan": T.StaticScanResponse,
    "static-scan_string-facts": T.StringFacts,
    "signature-check": T.SignatureCheckResponse,
    "processes": T.ProcessesResponse,
    "processes_tree": T.ProcessTreeResponse,
    "killchain": T.Killchain,
    "behaviours_limit_5": T.BehavioursResponse,
    "behaviours_summary": T.BehaviourSummary,
    "syscalls_limit_3": T.SyscallsResponse,
    "verdict": T.Verdict,
    "run": T.RunNotes,
    "network_summary": T.NetworkSummary,
    "network_endpoints_limit_5": T.NetworkEndpoints,
    "url-analysis": T.UrlAnalysisResponse,
    "url-analysis_indicators": T.UrlAnalysisIndicators,
    "url-analysis_session": T.UrlAnalysisSession,
}


def _dropped_keys(sent: Any, kept: Any, path: str = "$") -> list[str]:
    if isinstance(sent, dict):
        if not isinstance(kept, dict):
            return [path]
        dropped: list[str] = []
        for key, value in sent.items():
            if key not in kept:
                dropped.append(f"{path}.{key}")
            else:
                dropped.extend(_dropped_keys(value, kept[key], f"{path}.{key}"))
        return dropped
    if isinstance(sent, list):
        if not isinstance(kept, list) or len(kept) != len(sent):
            return [path]
        return [
            key
            for index, (item, dumped) in enumerate(zip(sent, kept, strict=True))
            for key in _dropped_keys(item, dumped, f"{path}[{index}]")
        ]
    return []


def _dump(route: str, payload: Any) -> Any:
    if route in _LIST_ROUTES:
        adapter: TypeAdapter[list[BaseModel]] = TypeAdapter(list[_LIST_ROUTES[route]])
        rows = payload["items"] if isinstance(payload, dict) else payload
        return adapter.dump_python(adapter.validate_python(rows), by_alias=True), rows
    model = _ROUTES[route]
    return model.model_validate(payload).model_dump(by_alias=True), payload


def _responses(root: Path) -> list[Any]:
    cases = []
    for path in sorted(root.glob("*/*.json")):
        route = path.stem
        if route in _ROUTES or route in _LIST_ROUTES:
            cases.append(pytest.param(route, path, id=f"{path.parent.name}/{route}"))
    return cases


def _check(route: str, path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    kept, sent = _dump(route, payload)
    return _dropped_keys(sent, kept)


@pytest.mark.parametrize(("route", "path"), _responses(FIXTURES))
def test_model_keeps_every_recorded_key(route: str, path: Path) -> None:
    assert _check(route, path) == []


def test_fixtures_cover_every_route() -> None:
    routes = {path.stem for path in FIXTURES.glob("*/*.json")}
    assert routes == set(_ROUTES) | set(_LIST_ROUTES)


def test_fixtures_keep_the_unrecorded_dns_type() -> None:
    rows = [
        row
        for path in FIXTURES.glob("*/network_dns_limit_5.json")
        for row in json.loads(path.read_text(encoding="utf-8"))
    ]
    assert any(row["type"] == "-" for row in rows)
    TypeAdapter(list[T.DnsQuery]).validate_python(rows)


def test_dropped_keys_reports_a_nested_key() -> None:
    assert _dropped_keys({"a": {"b": 1, "c": [{"d": 2}]}}, {"a": {"b": 1, "c": [{}]}}) == [
        "$.a.c[0].d"
    ]


_RAW = os.environ.get("THREATZONE_RECORDED_RESPONSES")


@pytest.mark.skipif(not _RAW, reason="THREATZONE_RECORDED_RESPONSES is not set")
@pytest.mark.parametrize(("route", "path"), _responses(Path(_RAW)) if _RAW else [])
def test_model_keeps_every_key_of_unscrubbed_responses(route: str, path: Path) -> None:
    assert _check(route, path) == []
