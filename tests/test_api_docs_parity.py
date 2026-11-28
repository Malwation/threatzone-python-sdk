"""The models keep every field of the documented v1 response examples of Threat.Zone v3.9.6.

Each file in ``fixtures/api_docs/`` is a verbatim copy of one response example of the Public
API guide (``apps/public-api-service/docs/api/*.md`` at the ``v3.9.6`` tag). Copy the example
again when the guide changes.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter

from threatzone.types import (
    ArtifactsResponse,
    DynamicSession,
    IoCsResponse,
    MediaFile,
    Metafields,
    NetworkEndpoints,
    NetworkHttpPackets,
    OverviewSummary,
    Submission,
    UrlAnalysisBrowserSection,
    UrlAnalysisIndicators,
)

from .test_schema_parity import _missing_keys

FIXTURES = Path(__file__).parent / "fixtures" / "api_docs"

DOCUMENTED: dict[str, Any] = {
    "artifacts": ArtifactsResponse,
    "dynamic_session": DynamicSession,
    "iocs": IoCsResponse,
    "media": list[MediaFile],
    "metafields": Metafields,
    "network_endpoints": NetworkEndpoints,
    "network_http_packets": NetworkHttpPackets,
    "submission": Submission,
    "summary": OverviewSummary,
    "url_analysis_browser_section": UrlAnalysisBrowserSection,
    "url_analysis_indicators": UrlAnalysisIndicators,
}


def _example(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def test_every_fixture_has_a_model() -> None:
    assert {path.stem for path in FIXTURES.glob("*.json")} == set(DOCUMENTED)


@pytest.mark.parametrize("name", sorted(DOCUMENTED))
def test_model_dump_keeps_every_documented_key(name: str) -> None:
    adapter: TypeAdapter[Any] = TypeAdapter(DOCUMENTED[name])
    documented = _example(name)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        dumped = adapter.dump_python(
            adapter.validate_python(documented), by_alias=True, mode="json"
        )

    assert _missing_keys(documented, dumped) == []


def test_submission_example_parses_the_run_verdict() -> None:
    submission = Submission.model_validate(_example("submission"))

    assert submission.dynamic_verdict is not None
    assert submission.dynamic_verdict.tier == "Suspicious"
    assert submission.dynamic_verdict.run_notes[0].code == "sample_exited_early"
    assert submission.reports[0].decline_reason is None


def test_iocs_example_parses_the_row_fields() -> None:
    item = IoCsResponse.model_validate(_example("iocs")).items[0]

    assert item.id is not None
    assert item.exported is not None
    assert item.reasons
    assert item.reasons[0].code


def test_endpoints_example_parses_the_hosts_fields() -> None:
    endpoints = NetworkEndpoints.model_validate(_example("network_endpoints"))

    assert endpoints.summary is not None
    assert endpoints.items[0].rank == 0
    assert endpoints.items[0].group in {"sample", "shared", "background"}


def test_artifacts_example_parses_the_writer_and_paging() -> None:
    artifacts = ArtifactsResponse.model_validate(_example("artifacts"))

    assert artifacts.total_pages is not None
    assert any(item.writer is not None for item in artifacts.items)


def test_browser_examples_without_the_deprecated_job_id_parse() -> None:
    section = UrlAnalysisBrowserSection.model_validate(_example("url_analysis_browser_section"))
    indicators = UrlAnalysisIndicators.model_validate(_example("url_analysis_indicators"))

    assert section.revision
    assert indicators.snapshot is not None
    assert indicators.snapshot.browser_snapshot is not None
    assert "job_id" not in indicators.snapshot.browser_snapshot.model_fields_set


def test_dynamic_session_example_parses_the_live_view() -> None:
    session = DynamicSession.model_validate(_example("dynamic_session"))

    assert session.state == "running"
    assert session.vnc_available is True
    assert session.link is not None
    assert session.link.startswith("wss://")
    assert session.expires_at == 1756200600000
