"""Flow — the full dynamic analysis lifecycle end to end."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from threatzone import (
    AsyncThreatZone,
    BadRequestError,
    BehaviourIndexingError,
    NotFoundError,
    PermissionDeniedError,
    ThreatZone,
    YaraRulePendingError,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    ArtifactsResponse,
    BehaviourMatches,
    BehavioursResponse,
    IndicatorsResponse,
    IoCsResponse,
    NetworkSummary,
    OverviewSummary,
    ProcessesResponse,
    ProcessTreeResponse,
    YaraRulesResponse,
)


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_overview_summary_reachable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    summary = sync_client.get_overview_summary(uuid)
    assert isinstance(summary, OverviewSummary)


def test_processes_and_tree(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    procs = sync_client.get_processes(uuid)
    tree = sync_client.get_process_tree(uuid)
    assert isinstance(procs, ProcessesResponse)
    assert isinstance(tree, ProcessTreeResponse)


def test_behaviours_without_os_parameter(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    behaviours = sync_client.get_behaviours(
        uuid,
        type="file",
        process_name="malware.exe",
    )
    assert isinstance(behaviours, BehavioursResponse)
    assert behaviours.total == 1
    assert behaviours.page == 1
    assert behaviours.limit == 100
    assert behaviours.total_pages == 1


def test_processes_carry_the_process_identity(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    process = sync_client.get_processes(uuid).items[0]
    assert process.pid_gen == 0
    assert process.origin == "sample"
    assert process.image is not None
    assert process.timestamp is not None
    node = sync_client.get_process_tree(uuid).nodes[0]
    assert (node.pid, node.pid_gen) == (process.pid, process.pid_gen)
    assert node.cwd == process.cwd


def test_behaviour_index_filters(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    plain = sync_client.get_behaviours(uuid)
    assert plain.total == 2
    assert plain.sorted_by is None
    indexed = sync_client.get_behaviours(
        uuid,
        parent_pids=[1508],
        operations=["regsetvalue"],
        fields={"key": "currentversion"},
        sort="time",
    )
    assert indexed.total == 1
    assert indexed.sorted_by == "time"
    assert indexed.many_processes_match is False
    event = indexed.items[0]
    assert event.process_name == "cmd.exe"
    assert event.subject is not None
    assert sync_client.get_behaviours(uuid, event_ids=[1]).items[0].event_id == 1
    assert sync_client.get_behaviours(uuid, text="dropped").total == 2


def test_behaviour_summary_and_facets(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    summary = sync_client.get_behaviour_summary(uuid)
    assert summary.total_count == 2
    assert {row.process_id for row in summary.by_process} == {1508, 2044}
    facets = sync_client.get_behaviour_facets(uuid, "processName", contains="CMD")
    assert [(item.value, item.count) for item in facets.items] == [("cmd.exe", 1)]
    assert facets.complete is True


def test_behaviour_index_not_ready(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.mark_behaviour_index_missing(uuid)
    with pytest.raises(BehaviourIndexingError) as exc_info:
        sync_client.get_behaviour_summary(uuid)
    assert exc_info.value.retry_after == 60.0
    with pytest.raises(BehaviourIndexingError):
        sync_client.get_behaviours(uuid, pids=[1508])
    assert sync_client.get_behaviours(uuid, event_ids=[2]).total == 1


def test_syscall_search_pages(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    first = sync_client.search_syscalls(uuid, query="ntcreatefile", failed_only=True, limit=2)
    assert [hit.line for hit in first.lines] == [2, 4]
    assert first.done is False
    assert first.next_from_line == 4
    rest = sync_client.search_syscalls(
        uuid, query="ntcreatefile", failed_only=True, after_line=first.next_from_line
    )
    assert [hit.line for hit in rest.lines] == [6, 8, 10, 12]
    assert rest.done is True
    assert rest.next_from_line is None
    by_pid = sync_client.search_syscalls(uuid, query="ntdll", pids=[1508], apis=["NtReadFile"])
    assert len(by_pid.lines) == 6
    page = sync_client.get_syscalls(uuid, page=2, limit=5)
    assert page.first_line == 6
    assert page.items[0] == sync_client.search_syscalls(uuid, query="NtCreateFile").lines[2].raw


def test_raw_behaviour_and_syscall_downloads(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    with sync_client.download_behaviour(uuid) as dl:
        events = json.loads(dl.read())
    assert [event["eventId"] for event in events] == [1, 2]
    with sync_client.download_syscalls(uuid) as dl:
        lines = dl.read().decode("utf-8").split("\n")
    assert lines == sync_client.get_syscalls(uuid).items
    fake_api.deny_download_report(uuid)
    with pytest.raises(PermissionDeniedError):
        sync_client.download_behaviour(uuid)


async def test_async_behaviour_index_and_syscall_search(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    summary = await async_client.get_behaviour_summary(uuid)
    assert summary.total_count == 2
    facets = await async_client.get_behaviour_facets(uuid, "type")
    assert len(facets.items) == 2
    behaviours = await async_client.get_behaviours(uuid, types=["file"])
    assert behaviours.total == 1
    result = await async_client.search_syscalls(uuid, query="NtReadFile")
    assert len(result.lines) == 6
    download = await async_client.download_syscalls(uuid)
    async with download as dl:
        assert len(await dl.read()) > 0


def test_behaviour_matches(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    texts = ["DROPPED.EXE", "currentversion\\run", "dropped.exe", "not-in-the-run", "DROPPED.EXE"]
    matches = sync_client.get_behaviour_matches(uuid, texts)
    assert isinstance(matches, BehaviourMatches)
    assert [item.needle for item in matches.items] == texts[:4]
    upper, run_key, lower, missing = matches.items
    assert (upper.count, upper.first_event_id) == (1, 1)
    assert upper.samples == ["C:\\Users\\test\\dropped.exe"]
    assert (lower.count, lower.first_event_id, lower.samples) == (
        upper.count,
        upper.first_event_id,
        upper.samples,
    )
    assert (run_key.count, run_key.first_event_id) == (1, 2)
    assert (missing.count, missing.first_event_id, missing.samples) == (0, None, [])
    assert all(item.complete and item.scanned_rows == 2 for item in matches.items)
    [first] = sync_client.get_behaviours(uuid, event_ids=[run_key.first_event_id or 0]).items
    assert first.subject is not None
    assert "currentversion\\run" in first.subject.lower()
    single = sync_client.get_behaviour_matches(uuid, "dropped.exe,other")
    assert [item.needle for item in single.items] == ["dropped.exe,other"]
    assert single.items[0].count == 0


def test_behaviour_matches_reject_bad_texts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    requests_before = len(fake_api.request_log)
    with pytest.raises(ValueError, match="texts"):
        sync_client.get_behaviour_matches(uuid, [])
    assert len(fake_api.request_log) == requests_before
    with pytest.raises(BadRequestError) as exc_info:
        sync_client.get_behaviour_matches(uuid, ["x"])
    assert (exc_info.value.body or {}).get("code") == "INVALID_QUERY_PARAM"
    fake_api.mark_behaviour_index_missing(uuid)
    with pytest.raises(BehaviourIndexingError):
        sync_client.get_behaviour_matches(uuid, ["dropped.exe"])


@pytest.mark.parametrize(
    "call_route",
    [
        pytest.param(
            lambda client, uuid: client.get_behaviours(uuid, event_ids=[]), id="event_ids"
        ),
        pytest.param(lambda client, uuid: client.get_behaviours(uuid, pids=[]), id="pids"),
        pytest.param(lambda client, uuid: client.get_behaviours(uuid, types=[]), id="types"),
        pytest.param(
            lambda client, uuid: client.get_behaviours(uuid, types=""), id="types-empty-string"
        ),
        pytest.param(
            lambda client, uuid: client.get_behaviours(uuid, fields={"path": []}), id="fields"
        ),
        pytest.param(
            lambda client, uuid: client.search_syscalls(uuid, query="NtCreateFile", apis=[]),
            id="apis",
        ),
        pytest.param(
            lambda client, uuid: client.search_syscalls(uuid, query="NtCreateFile", apis=""),
            id="apis-empty-string",
        ),
    ],
)
def test_empty_filters_are_refused_before_the_request(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    call_route: Callable[[ThreatZone, str], object],
) -> None:
    uuid = _submit(fake_api, sync_client)
    requests_before = len(fake_api.request_log)
    with pytest.raises(ValueError, match="must not be empty"):
        call_route(sync_client, uuid)
    assert len(fake_api.request_log) == requests_before


def test_artifact_yara_rule(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    artifact_id = sync_client.get_artifacts(uuid).items[0].id
    with pytest.raises(YaraRulePendingError) as exc_info:
        sync_client.download_artifact_yara_rule(uuid, artifact_id)
    assert exc_info.value.retry_after == 10.0
    assert exc_info.value.message == "YARA rule generation is in progress. Retry shortly."
    with sync_client.download_artifact_yara_rule(uuid, artifact_id) as dl:
        assert dl.filename == f"{uuid}_{artifact_id}.yar"
        assert dl.read().startswith(b"rule ")
    with pytest.raises(NotFoundError) as not_found:
        sync_client.download_artifact_yara_rule(uuid, "507f1f77bcf86cd799439011")
    assert (not_found.value.body or {}).get("code") == "ARTIFACT_NOT_FOUND"
    with pytest.raises(BadRequestError) as malformed:
        sync_client.download_artifact_yara_rule(uuid, "no-such-artifact")
    assert (malformed.value.body or {}).get("code") == "INVALID_QUERY_PARAM"


async def test_async_behaviour_matches_and_artifact_yara_rule(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    matches = await async_client.get_behaviour_matches(uuid, ["malware", "dropped.exe"])
    assert [item.count for item in matches.items] == [0, 1]
    artifact_id = (await async_client.get_artifacts(uuid)).items[0].id
    with pytest.raises(YaraRulePendingError):
        await async_client.download_artifact_yara_rule(uuid, artifact_id)
    download = await async_client.download_artifact_yara_rule(uuid, artifact_id)
    async with download as dl:
        assert (await dl.read()).startswith(b"rule ")
    with pytest.raises(ValueError, match="must not be empty"):
        await async_client.get_behaviour_facets(uuid, "type", pids=[])


def test_indicators_iocs_yara_artifacts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    assert isinstance(sync_client.get_indicators(uuid), IndicatorsResponse)
    assert isinstance(sync_client.get_iocs(uuid), IoCsResponse)
    assert isinstance(sync_client.get_yara_rules(uuid), YaraRulesResponse)
    assert isinstance(sync_client.get_artifacts(uuid), ArtifactsResponse)


def test_network_endpoints_on_dynamic(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    summary = sync_client.get_network_summary(uuid)
    assert isinstance(summary, NetworkSummary)
    assert sync_client.get_network_threats(uuid)


def test_download_sample_and_pcap(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    with sync_client.download_sample(uuid) as dl:
        assert len(dl.read()) > 0
    with sync_client.download_pcap(uuid) as dl:
        assert len(dl.read()) > 0


def test_poll_count_records_polling(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    assert fake_api.poll_count(uuid) >= 1


def test_request_log_captures_post_and_get(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    _submit(fake_api, sync_client)
    methods = [r.method for r in fake_api.request_log]
    assert "POST" in methods
    assert "GET" in methods
