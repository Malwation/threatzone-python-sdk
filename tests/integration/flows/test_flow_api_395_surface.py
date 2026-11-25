"""The v3.9.5 parameters and fields of the Public API through the fake API."""

from __future__ import annotations

import pytest

from threatzone import AsyncThreatZone, BadRequestError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios


def _completed_pe(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_detail_and_summary_carry_the_run_verdict(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    submission = sync_client.get_submission(uuid)
    summary = sync_client.get_overview_summary(uuid)
    verdict = sync_client.get_verdict(uuid)

    assert submission.dynamic_verdict is not None
    assert submission.dynamic_verdict.tier == verdict.tier
    assert submission.dynamic_verdict.score == verdict.score
    assert summary.dynamic_verdict == submission.dynamic_verdict
    assert submission.reports[0].decline_reason is None
    assert verdict.narrative is not None
    assert verdict.narrative.decisive[0].indicator_id in {
        row.id for row in sync_client.get_indicators(uuid).items
    }


def test_in_verdict_chain_and_compact_view(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    chain = sync_client.get_indicators(uuid, in_verdict_chain=True)
    others = sync_client.get_indicators(uuid, in_verdict_chain=False)
    compact = sync_client.get_compact_indicators(uuid)

    assert chain.total + others.total == compact.total
    assert all(row.in_verdict_chain for row in chain.items)
    assert not any(row.in_verdict_chain for row in others.items)
    assert [row.id for row in compact.items] == [
        row.id for row in sync_client.get_indicators(uuid).items
    ]


def test_iocs_row_fields_and_filters(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    rows = sync_client.get_iocs(uuid).items
    assert all(row.id and row.exported for row in rows)

    network = sync_client.get_iocs(uuid, source=["network"]).items
    assert {row.type for row in network} == {"domain", "ip"}
    assert all(row.state == "contacted" and row.process is not None for row in network)

    files = sync_client.get_iocs(uuid, group="file").items
    [file_row] = [row for row in files if row.type == "file"]
    assert file_row.file is not None
    assert file_row.file.sha256 == file_row.value

    graded = sync_client.get_iocs(uuid, sort="grade").items
    assert graded[0].grade == "high"
    assert sync_client.get_iocs(uuid, grade=["none"]).total == 0
    assert sync_client.get_iocs(uuid, labelled="only").total == 0
    assert sync_client.get_iocs(uuid, exported=False).total == 0


def test_iocs_reject_an_unknown_group(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    with pytest.raises(BadRequestError):
        sync_client.get_iocs(uuid, group="artifact")


def test_artifacts_writer_and_paging(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    everything = sync_client.get_artifacts(uuid)
    assert everything.page == 1
    assert everything.limit == everything.total
    assert all(item.writer is not None for item in everything.items)

    first = sync_client.get_artifacts(uuid, page=1, limit=1)
    assert first.limit == 1
    assert len(first.items) == min(1, everything.total)
    assert first.total_pages == everything.total


def test_endpoints_hosts_order_groups_and_summary(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    endpoints = sync_client.get_network_endpoints(uuid)
    assert [item.rank for item in endpoints.items] == list(range(len(endpoints.items)))
    assert endpoints.summary is not None
    assert endpoints.summary.shared_count == 1

    before = sync_client.get_network_endpoints(uuid, sort="default")
    assert before.items[1].group == "shared"
    shared = sync_client.get_network_endpoints(uuid, group=["shared"])
    assert [item.label for item in shared.items] == ["shared_infrastructure"]
    assert shared.items[0].grade is None


def test_media_download_link_and_version(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    [media] = sync_client.list_media_files(uuid, source="dynamic")
    assert media.download_link is not None
    assert media.download_link.endswith(f"/media/{media.id}?source=dynamic")
    assert sync_client.get_version().api_version is not None


def test_ioc_export_filters(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    every = sync_client.download_iocs(uuid, format="text").read().decode().splitlines()
    domains = (
        sync_client.download_iocs(uuid, format="text", types=["domain"]).read().decode().split()
    )
    found = sync_client.download_iocs(uuid, format="text", search="C2").read().decode().split()

    assert len(domains) == 1
    assert len(every) > len(domains)
    assert found == domains


async def test_async_client_reads_the_same_fields(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _completed_pe(fake_api, sync_client)
    compact = await async_client.get_compact_indicators(uuid, in_verdict_chain=True)
    iocs = await async_client.get_iocs(uuid, group="file")
    endpoints = await async_client.get_network_endpoints(uuid, sort="first_contact")

    assert compact.items
    assert any(row.type == "file" for row in iocs.items)
    assert endpoints.summary is not None
