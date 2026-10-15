"""Flow — verdict, run notes, annotations, run compare, IoC export and SHA-256 search scope."""

from __future__ import annotations

import json
from typing import Literal

import pytest

from threatzone import (
    AsyncThreatZone,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    ReportUnavailableError,
    ThreatZone,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Annotations, RunComparison, RunNotes, Verdict


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_verdict_and_run_notes(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    verdict = sync_client.get_verdict(uuid)
    assert isinstance(verdict, Verdict)
    assert verdict.tier == "Malicious"
    assert verdict.story is not None
    assert verdict.story.steps[0].category == "network"
    notes = sync_client.get_run(uuid)
    assert isinstance(notes, RunNotes)
    assert notes.java_output is not None
    assert "bot token 123456:ABCDEF" in notes.java_output.text
    assert notes.run_notes[0].code == "sample_exited_early"


def test_verdict_needs_a_dynamic_report(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_verdict(created.uuid)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_run(created.uuid)


def test_annotation_lifecycle(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    empty = sync_client.get_annotations(uuid)
    assert (empty.submission_uuid, empty.pins, empty.note) == (uuid, [], None)

    pinned = sync_client.pin_evidence(
        uuid, kind="technique", ref="technique:T1055", label="  Process injection  "
    )
    [pin] = pinned.pins
    assert (pin.kind, pin.ref, pin.label) == ("technique", "technique:T1055", "Process injection")
    again = sync_client.pin_evidence(uuid, kind="technique", ref="technique:T1055", label="Other")
    assert [p.id for p in again.pins] == [pin.id]

    noted = sync_client.set_note(uuid, "The sample injects into explorer.exe.")
    assert noted.note is not None
    assert noted.note.text == "The sample injects into explorer.exe."
    assert sync_client.set_note(uuid, "   ").note is None

    assert sync_client.unpin_evidence(uuid, pin.id).pins == []
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.unpin_evidence(uuid, pin.id)
    assert exc_info.value.body is not None
    assert exc_info.value.body["code"] == "ANNOTATION_PIN_NOT_FOUND"


def test_pin_rejects_an_unknown_kind(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    with pytest.raises(BadRequestError):
        sync_client.pin_evidence(uuid, kind="screenshot", ref="x", label="x")


def test_public_submission_of_another_workspace_can_be_annotated(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.mark_private(uuid, owning_workspace="other-workspace")
    with pytest.raises(NotFoundError):
        sync_client.get_annotations(uuid)
    with pytest.raises(NotFoundError):
        sync_client.set_note(uuid, "note")
    with pytest.raises(NotFoundError) as pin_error:
        sync_client.pin_evidence(uuid, kind="process", ref="process:pid-1508", label="x")
    assert (pin_error.value.body or {}).get("code") == "NOT_FOUND"
    with pytest.raises(NotFoundError) as unpin_error:
        sync_client.unpin_evidence(uuid, "0b5e8c1e-6a5f-4c33-9c1e-2f4b8d7e9a10")
    assert (unpin_error.value.body or {}).get("code") == "NOT_FOUND"

    other_public = fake_api.register_previous_run(uuid, owning_workspace="other-workspace")
    annotations = sync_client.pin_evidence(
        other_public, kind="process", ref="process:pid-1508", label="malware.exe"
    )
    assert isinstance(annotations, Annotations)
    assert len(annotations.pins) == 1


def test_unpin_rejects_a_pin_id_that_is_not_uuid_v4(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    with pytest.raises(BadRequestError) as exc_info:
        sync_client.unpin_evidence(uuid, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    assert (exc_info.value.body or {}).get("code") == "INVALID_QUERY_PARAM"


def test_previous_run_and_compare(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    assert sync_client.get_previous_run(uuid).previous_run_uuid is None

    previous_uuid = fake_api.register_previous_run(
        uuid,
        indicators=[("T1112", "suspicious", [1508])],
        iocs=[("ip", "198.51.100.7")],
        mitre_techniques=["T1112"],
        dropped_files=[],
    )
    assert sync_client.get_previous_run(uuid).previous_run_uuid == previous_uuid
    assert sync_client.get_previous_run(previous_uuid).previous_run_uuid is None

    comparison = sync_client.compare_runs(uuid, previous_uuid)
    assert isinstance(comparison, RunComparison)
    assert comparison.other_submission_uuid == previous_uuid
    assert comparison.detections.removed == []
    assert {d.title for d in comparison.detections.added} == {
        "Indicator T1055",
        "Indicator T1547.001",
    }
    assert set(comparison.techniques.added) == {"T1055", "T1547.001", "T1059.001"}
    assert comparison.techniques.removed == []
    assert [(i.category, i.value) for i in comparison.iocs.removed] == [("ip", "198.51.100.7")]
    assert comparison.dropped_files.added_total == 1
    assert comparison.dropped_files.added[0].sha256 == "0" * 64

    same = sync_client.compare_runs(uuid, uuid)
    assert same.iocs.added_total == 0
    assert same.techniques.removed_total == 0


def test_private_runs_of_another_workspace_stay_hidden(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    hidden = fake_api.register_previous_run(uuid, private=True, owning_workspace="other-workspace")
    assert sync_client.get_previous_run(uuid).previous_run_uuid is None
    with pytest.raises(NotFoundError):
        sync_client.compare_runs(uuid, hidden)


@pytest.mark.parametrize(
    ("export_format", "content_type", "suffix"),
    [
        ("csv", "text/csv; charset=utf-8", ".csv"),
        ("text", "text/plain; charset=utf-8", ".txt"),
        ("stix", "application/json", ".json"),
        ("misp", "application/json", ".json"),
    ],
)
def test_ioc_export_formats(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    export_format: Literal["csv", "text", "stix", "misp"],
    content_type: str,
    suffix: str,
) -> None:
    uuid = _submit(fake_api, sync_client)
    with sync_client.download_iocs(uuid, format=export_format) as download:
        body = download.read()
        assert download.content_type == content_type
        assert download.filename is not None
        assert download.filename.endswith(suffix)
    if export_format == "csv":
        lines = body.decode().splitlines()
        assert lines[0] == "type,value,defanged,sources"
        assert "ip,192.0.2.10,192[.]0[.]2[.]10,dynamic" in lines
        assert f"sha256,{'b' * 64},{'b' * 64},dynamic" in lines
    elif export_format == "text":
        assert "malware-c2[.]example[.]com" in body.decode().splitlines()
    elif export_format == "stix":
        assert len(json.loads(body)["objects"]) == 3
    else:
        assert len(json.loads(body)["Event"]["Attribute"]) == 3


def test_stix_and_misp_exports_need_the_permission(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.deny_stix_report(uuid)
    with pytest.raises(PermissionDeniedError), sync_client.download_iocs(uuid, format="stix"):
        pass
    with pytest.raises(PermissionDeniedError), sync_client.download_iocs(uuid, format="misp"):
        pass
    with sync_client.download_iocs(uuid, format="csv") as download:
        assert download.read().startswith(b"type,value")


def test_sha256_search_scope(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _submit(fake_api, sync_client)
    sha = "a" * 64
    other_private = fake_api.register_previous_run(
        uuid, private=True, owning_workspace="other-workspace"
    )
    assert other_private not in {s.uuid for s in sync_client.search_by_sha256(sha)}
    workspace_rows = sync_client.search_by_sha256(sha, scope="workspace")
    assert [s.uuid for s in workspace_rows] == [uuid]

    fake_api.mark_private(uuid, owning_workspace="test-workspace")
    assert [s.uuid for s in sync_client.search_by_sha256(sha)] == [uuid]
    assert sync_client.search_by_sha256(sha, scope="public") == []


async def test_async_annotations_and_compare(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    pinned = await async_client.pin_evidence(uuid, kind="file", ref="file:a", label="dropped.exe")
    [pin] = pinned.pins
    assert (await async_client.get_annotations(uuid)).pins[0].id == pin.id
    assert (await async_client.unpin_evidence(uuid, pin.id)).pins == []
    previous_uuid = fake_api.register_previous_run(uuid)
    assert (await async_client.get_previous_run(uuid)).previous_run_uuid == previous_uuid
    comparison = await async_client.compare_runs(uuid, previous_uuid)
    assert comparison.iocs.added == []
    async with await async_client.download_iocs(uuid, format="text") as download:
        assert (await download.read()).decode().count("\n") == 3
