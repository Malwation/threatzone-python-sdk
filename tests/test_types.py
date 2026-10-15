"""Tests for the Pydantic type models exposed by the SDK.

Every top-level type from `src/threatzone/types/` gets:
- canonical-payload happy path parsing
- field-aliasing assertion (camelCase JSON -> snake_case Python)
- a missing-required-field rejection where applicable
- nested-type assertions where the model has nested children
- a model_dump round-trip where the model has aliased fields

Recursive `ProcessTreeNode.children` and the new error envelope are also covered.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from threatzone.types import (
    AiReport,
    AiReportPending,
    Artifact,
    ArtifactHashes,
    ArtifactsResponse,
    BehaviourEvent,
    BehavioursResponse,
    CdrResponse,
    Connection,
    ConnectionPackets,
    DevicePresetOption,
    DnsQuery,
    EmlAnalysis,
    EmlAnalysisAttachment,
    EmlAnalysisHeaders,
    EmlAnalysisQrResult,
    EnvironmentOption,
    ExtractedConfig,
    ExtractedConfigsResponse,
    FileInfo,
    Hashes,
    HttpRequest,
    Indicator,
    IndicatorLevels,
    IndicatorsResponse,
    IoC,
    IoCsResponse,
    LimitsCount,
    MediaFile,
    Message,
    MetafieldOption,
    Metafields,
    MitreResponse,
    ModuleInfo,
    NetworkAvailability,
    NetworkConfigListItem,
    NetworkConfigListResponse,
    NetworkExfilRequest,
    NetworkSummary,
    NetworkThreat,
    NetworkThreatTls,
    OverviewSummary,
    PaginatedSubmissions,
    PdfReportStatus,
    PlanInfo,
    Process,
    ProcessesResponse,
    ProcessTreeNode,
    ProcessTreeResponse,
    ReportStatus,
    SignatureCheckResponse,
    SignatureCheckResult,
    StaticScanResponse,
    Submission,
    SubmissionCreated,
    SubmissionListItem,
    SubmissionOverview,
    SubmissionOverviewJobs,
    SyscallsResponse,
    Tag,
    UrlAnalysisResponse,
    UrlAnalysisSession,
    UserInfo,
    UserInfoDetails,
    WorkspaceBasicInfo,
    YaraRule,
    YaraRulesResponse,
)
from threatzone.types.errors import ApiError

# ---------------------------------------------------------------------------
# Common types
# ---------------------------------------------------------------------------


class TestCommonTypes:
    def test_hashes_model(self) -> None:
        h = Hashes.model_validate({"md5": "a", "sha1": "b", "sha256": "c"})
        assert h.md5 == "a"
        assert h.sha1 == "b"
        assert h.sha256 == "c"

    def test_hashes_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            Hashes.model_validate({"md5": "a", "sha1": "b"})

    def test_tag_model(self) -> None:
        t = Tag.model_validate({"type": "malware", "value": "trojan"})
        assert t.type == "malware"
        assert t.value == "trojan"

    def test_file_info_model_aliases_camelcase(self) -> None:
        info = FileInfo.model_validate(
            {
                "name": "x.exe",
                "size": 1024,
                "extension": ".exe",
                "mimetype": "application/octet-stream",
                "isMimetypeChecked": True,
                "entrypoint": None,
                "source": {"type": "upload", "url": None},
            }
        )
        assert info.is_mimetype_checked is True
        assert info.source.type == "upload"

    def test_file_info_round_trip(self) -> None:
        payload: dict[str, Any] = {
            "name": "x.exe",
            "size": 1024,
            "extension": ".exe",
            "mimetype": "application/octet-stream",
            "isMimetypeChecked": False,
            "entrypoint": {"filename": "main.exe"},
            "source": {"type": "url", "url": "https://example.com/x.exe"},
        }
        first = FileInfo.model_validate(payload)
        dumped = first.model_dump(by_alias=True)
        second = FileInfo.model_validate(dumped)
        assert second.entrypoint is not None
        assert second.entrypoint.filename == "main.exe"
        assert second.source.url == "https://example.com/x.exe"

    def test_report_status_with_operating_system(self) -> None:
        status = ReportStatus.model_validate(
            {
                "type": "dynamic",
                "status": "completed",
                "level": "malicious",
                "score": 95,
                "format": "v2",
                "operatingSystem": {
                    "name": "Windows 10",
                    "platform": "windows",
                },
            }
        )
        assert status.type == "dynamic"
        assert status.operating_system is not None
        assert status.operating_system.platform == "windows"

    def test_report_status_accepts_a_fractional_score(self) -> None:
        status = ReportStatus.model_validate(
            {"type": "dynamic", "status": "completed", "level": "malicious", "score": 87.5}
        )
        assert status.score == 87.5

    def test_report_status_keeps_an_integer_score(self) -> None:
        status = ReportStatus.model_validate({"type": "static", "status": "completed", "score": 42})
        assert status.score == 42

    def test_report_status_accepts_an_empty_platform(self) -> None:
        status = ReportStatus.model_validate(
            {
                "type": "dynamic",
                "status": "completed",
                "operatingSystem": {"name": "Unknown", "platform": ""},
            }
        )
        assert status.operating_system is not None
        assert status.operating_system.platform == ""

    def test_report_status_accepts_an_unknown_platform(self) -> None:
        status = ReportStatus.model_validate(
            {
                "type": "dynamic",
                "status": "completed",
                "operatingSystem": {"name": "FreeBSD 14", "platform": "freebsd"},
            }
        )
        assert status.operating_system is not None
        assert status.operating_system.platform == "freebsd"

    def test_report_status_optional_fields_nullable(self) -> None:
        status = ReportStatus.model_validate({"type": "static", "status": "in_progress"})
        assert status.level is None
        assert status.score is None
        assert status.operating_system is None


# ---------------------------------------------------------------------------
# Submissions types
# ---------------------------------------------------------------------------


class TestSubmissionTypes:
    def test_submission_created(self, sample_submission_created: dict[str, Any]) -> None:
        sc = SubmissionCreated.model_validate(sample_submission_created)
        assert sc.uuid == sample_submission_created["uuid"]
        assert sc.message == sample_submission_created["message"]

    def test_submission_overview_jobs(self) -> None:
        jobs = SubmissionOverviewJobs.model_validate(
            {"total": 3, "succeeded": 2, "failed": 0, "skipped": 1, "finished": 3}
        )
        assert jobs.finished == jobs.total
        assert jobs.succeeded == 2
        assert jobs.skipped == 1

    def test_submission_overview_jobs_completed_alias(self) -> None:
        jobs = SubmissionOverviewJobs.model_validate(
            {"total": 5, "succeeded": 4, "failed": 1, "skipped": 0, "finished": 5}
        )
        assert jobs.completed == jobs.finished
        dumped = jobs.model_dump()
        assert "completed" in dumped
        assert dumped["completed"] == jobs.finished

    def test_submission_overview_jobs_completed_mirrors_finished(self) -> None:
        jobs = SubmissionOverviewJobs.model_validate(
            {
                "total": 5,
                "succeeded": 4,
                "failed": 1,
                "skipped": 0,
                "finished": 5,
                "completed": 999,
            }
        )
        assert jobs.completed == 5

    def test_submission_score_family_duration(self, sample_submission: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission)
        assert sub.score == 78.5
        assert sub.family == "Sheetrat"
        assert sub.reports[0].duration == 0.2

    def test_submission_overview(self, sample_submission_overview: dict[str, Any]) -> None:
        ov = SubmissionOverview.model_validate(sample_submission_overview)
        assert ov.status == "completed"
        assert ov.jobs is not None
        assert ov.jobs.total == 3

    def test_submission_list_item(self, sample_submission_list_item: dict[str, Any]) -> None:
        item = SubmissionListItem.model_validate(sample_submission_list_item)
        assert item.uuid == "sub-789"
        assert item.indicators.artifact_count == 7
        assert item.indicators.levels.malicious == 5

    def test_submission_list_item_missing_indicators_raises(
        self, sample_submission_list_item: dict[str, Any]
    ) -> None:
        bad = {**sample_submission_list_item}
        bad.pop("indicators")
        with pytest.raises(ValidationError):
            SubmissionListItem.model_validate(bad)

    def test_paginated_submissions(self, sample_paginated_submissions: dict[str, Any]) -> None:
        page = PaginatedSubmissions.model_validate(sample_paginated_submissions)
        assert page.total == 1
        assert page.total_pages == 1
        assert len(page.items) == 1

    def test_submission_full_detail(self, sample_submission: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission)
        assert sub.uuid == "sub-789"
        assert sub.hashes is not None
        assert sub.hashes.sha256.startswith("e3b0c4")
        assert sub.mitre_techniques == ["T1547.001", "T1071.001"]
        assert sub.indicators.artifact_count == 7

    def test_submission_is_complete(self, sample_submission: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission)
        assert sub.is_complete() is True
        assert sub.has_errors() is False

    def test_submission_not_complete(self, sample_submission: dict[str, Any]) -> None:
        sample_submission["reports"][0]["status"] = "in_progress"
        sub = Submission.model_validate(sample_submission)
        assert sub.is_complete() is False

    def test_submission_has_errors(self, sample_submission: dict[str, Any]) -> None:
        sample_submission["reports"][0]["status"] = "error"
        sub = Submission.model_validate(sample_submission)
        assert sub.is_complete() is True
        assert sub.has_errors() is True

    def test_submission_round_trip(self, sample_submission: dict[str, Any]) -> None:
        first = Submission.model_validate(sample_submission)
        dumped = first.model_dump(by_alias=True, mode="json")
        second = Submission.model_validate(dumped)
        assert second.mitre_techniques == first.mitre_techniques
        assert second.indicators.artifact_count == first.indicators.artifact_count


# ---------------------------------------------------------------------------
# Indicators surface
# ---------------------------------------------------------------------------


class TestIndicatorsSurfaceTypes:
    def test_indicator_levels(self) -> None:
        levels = IndicatorLevels.model_validate({"malicious": 1, "suspicious": 2, "benign": 3})
        assert levels.malicious == 1
        assert levels.benign == 3

    def test_indicator(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_indicator)
        assert ind.id == "ind-1"
        assert ind.attack_codes == ["T1547.001"]
        assert ind.event_ids == [42, 43]
        assert ind.syscall_line_numbers == [12, 100]
        assert ind.author == "system"

    def test_indicator_score_maximum(self, sample_indicator: dict[str, Any]) -> None:
        v2 = Indicator.model_validate({**sample_indicator, "score": 45, "scoreMaximum": 100})
        assert v2.score == 45
        assert v2.score_maximum == 100
        legacy = Indicator.model_validate({**sample_indicator, "scoreMaximum": 10})
        assert legacy.score_maximum == 10

    def test_indicator_unknown_score_maximum(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate({**sample_indicator, "scoreMaximum": 1000})
        assert ind.score_maximum == 1000

    def test_indicator_without_score_maximum(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_indicator)
        assert ind.score_maximum is None
        assert ind.score == sample_indicator["score"]

    def test_indicator_summary(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(
            {**sample_indicator, "summary": "word.exe hollowed svchost.exe.", "scoreMaximum": 100}
        )
        assert ind.summary == "word.exe hollowed svchost.exe."
        assert ind.description == sample_indicator["description"]

    def test_indicator_without_summary(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_indicator)
        assert ind.summary is None

    def test_indicator_accepts_a_fractional_score(self, sample_indicator: dict[str, Any]) -> None:
        indicator = Indicator.model_validate({**sample_indicator, "score": 7.5})
        assert indicator.score == 7.5

    def test_indicator_keeps_an_integer_score(self, sample_indicator: dict[str, Any]) -> None:
        indicator = Indicator.model_validate({**sample_indicator, "score": 8})
        assert indicator.score == 8

    def test_indicator_category_is_list(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_indicator)
        assert ind.category == ["evasion", "persistence"]

    def test_indicator_missing_field_raises(self, sample_indicator: dict[str, Any]) -> None:
        bad = {**sample_indicator}
        bad.pop("attackCodes")
        with pytest.raises(ValidationError):
            Indicator.model_validate(bad)

    def test_indicator_round_trip(self, sample_indicator: dict[str, Any]) -> None:
        first = Indicator.model_validate(sample_indicator)
        dumped = first.model_dump(by_alias=True)
        second = Indicator.model_validate(dumped)
        assert second.attack_codes == first.attack_codes

    def test_indicators_response(self, sample_indicators_response: dict[str, Any]) -> None:
        resp = IndicatorsResponse.model_validate(sample_indicators_response)
        assert resp.total == 1
        assert resp.levels.malicious == 5
        assert isinstance(resp.items[0], Indicator)

    def test_ioc(self, sample_ioc: dict[str, Any]) -> None:
        ioc = IoC.model_validate(sample_ioc)
        assert ioc.type == "domain"
        assert ioc.artifacts == ["art-1"]

    def test_iocs_response(self, sample_iocs_response: dict[str, Any]) -> None:
        resp = IoCsResponse.model_validate(sample_iocs_response)
        assert resp.total == 1
        assert isinstance(resp.items[0], IoC)

    def test_yara_rule(self, sample_yara_rule: dict[str, Any]) -> None:
        rule = YaraRule.model_validate(sample_yara_rule)
        assert rule.rule == "Trojan_Generic"
        assert rule.category == "malicious"

    def test_yara_rules_response(self, sample_yara_rules_response: dict[str, Any]) -> None:
        resp = YaraRulesResponse.model_validate(sample_yara_rules_response)
        assert isinstance(resp.items[0], YaraRule)

    def test_paginated_indicator_surfaces_expose_the_full_envelope(
        self,
        sample_iocs_response: dict[str, Any],
        sample_indicators_response: dict[str, Any],
        sample_yara_rules_response: dict[str, Any],
    ) -> None:
        # The API returns page/limit/totalPages on all three, but only `items` and `total`
        # were modelled, so a caller could not page without recomputing what was already
        # on the wire -- BehavioursResponse has exposed them all along.
        for resp in (
            IoCsResponse.model_validate(sample_iocs_response),
            IndicatorsResponse.model_validate(sample_indicators_response),
            YaraRulesResponse.model_validate(sample_yara_rules_response),
        ):
            assert resp.page == 1
            assert resp.limit == 20
            assert resp.total_pages == 1

    def test_extracted_config(self, sample_extracted_config: dict[str, Any]) -> None:
        cfg = ExtractedConfig.model_validate(sample_extracted_config)
        assert cfg.family == "AgentTesla"
        assert cfg.c2s == ["http://evil.com"]
        assert cfg.config["version"] == "1.0"

    def test_extracted_configs_response(
        self, sample_extracted_configs_response: dict[str, Any]
    ) -> None:
        resp = ExtractedConfigsResponse.model_validate(sample_extracted_configs_response)
        assert isinstance(resp.items[0], ExtractedConfig)

    def test_artifact_hashes(self) -> None:
        h = ArtifactHashes.model_validate({"md5": "a", "sha1": "b", "sha256": "c"})
        assert h.sha256 == "c"

    @pytest.mark.parametrize(
        "artifact_type",
        [
            "sample",
            "compressed_file_entry",
            "malware_config",
            "memory_dump",
            "file_dump",
            "pcap",
            "deobfuscated_code",
            "process_dump",
            "unpacked_file",
            "yara_rule",
            "email_file",
            "email_attachment",
            "embedded_file",
            "unknown",
            "dropped_file",
            "downloaded_file",
            "screenshot",
        ],
    )
    def test_artifact_accepts_all_known_types(
        self, sample_artifact: dict[str, Any], artifact_type: str
    ) -> None:
        artifact = Artifact.model_validate({**sample_artifact, "type": artifact_type})
        assert artifact.type == artifact_type
        assert isinstance(artifact.hashes, ArtifactHashes)

    def test_artifact_keeps_an_unknown_type(self, sample_artifact: dict[str, Any]) -> None:
        artifact = Artifact.model_validate({**sample_artifact, "type": "future_artifact_type"})
        assert artifact.type == "future_artifact_type"

    def test_artifacts_response(self, sample_artifacts_response: dict[str, Any]) -> None:
        resp = ArtifactsResponse.model_validate(sample_artifacts_response)
        assert isinstance(resp.items[0], Artifact)
        assert resp.items[0].hashes.sha256.startswith("e3b0c4")

    def test_overview_summary(self, sample_overview_summary: dict[str, Any]) -> None:
        summary = OverviewSummary.model_validate(sample_overview_summary)
        assert summary.indicators.total == 10
        assert summary.indicators.levels.malicious == 5
        assert summary.behavior_event_count == 200
        assert summary.syscall_count == 1500
        assert summary.network is not None
        assert summary.network.dns_count == 15

    def test_overview_summary_score_family(self, sample_overview_summary: dict[str, Any]) -> None:
        s = OverviewSummary.model_validate(sample_overview_summary)
        assert s.score == 84.0
        assert s.family == "Sheetrat"

    def test_overview_summary_without_network(
        self, sample_overview_summary: dict[str, Any]
    ) -> None:
        sample_overview_summary["network"] = None
        summary = OverviewSummary.model_validate(sample_overview_summary)
        assert summary.network is None

    def test_overview_summary_network_v2_unavailable(
        self, sample_overview_summary: dict[str, Any]
    ) -> None:
        sample_overview_summary["network"] = {
            "dnsCount": 0,
            "httpCount": 0,
            "tcpCount": 0,
            "udpCount": 0,
            "threatCount": 0,
            "countsAvailable": False,
            "availability": {
                "state": "unavailable",
                "reason": "capture_unavailable",
                "coverage": "none",
            },
            "sourceScope": "none",
        }
        network = OverviewSummary.model_validate(sample_overview_summary).network
        assert network is not None
        assert network.dns_count == 0
        assert network.counts_available is False
        assert network.availability == NetworkAvailability(
            state="unavailable", reason="capture_unavailable", coverage="none"
        )
        assert network.source_scope == "none"

    def test_overview_summary_network_legacy_has_no_availability(
        self, sample_overview_summary: dict[str, Any]
    ) -> None:
        network = OverviewSummary.model_validate(sample_overview_summary).network
        assert network is not None
        assert network.dns_count == 15
        assert network.counts_available is None
        assert network.availability is None
        assert network.source_scope is None

    def test_overview_summary_network_explicit_null_and_unknown_values(
        self, sample_overview_summary: dict[str, Any]
    ) -> None:
        sample_overview_summary["network"].update(
            {"countsAvailable": None, "availability": None, "sourceScope": None}
        )
        network = OverviewSummary.model_validate(sample_overview_summary).network
        assert network is not None
        assert network.counts_available is None
        assert network.availability is None
        assert network.source_scope is None

        sample_overview_summary["network"].update(
            {
                "availability": {"state": "future_state", "reason": None, "coverage": "future_cov"},
                "sourceScope": "future_scope",
            }
        )
        network = OverviewSummary.model_validate(sample_overview_summary).network
        assert network is not None
        assert network.availability is not None
        assert network.availability.state == "future_state"
        assert network.source_scope == "future_scope"

    def test_overview_summary_round_trip(self, sample_overview_summary: dict[str, Any]) -> None:
        first = OverviewSummary.model_validate(sample_overview_summary)
        dumped = first.model_dump(by_alias=True)
        assert "behaviorEventCount" in dumped
        second = OverviewSummary.model_validate(dumped)
        assert second.behavior_event_count == first.behavior_event_count


# ---------------------------------------------------------------------------
# Network types
# ---------------------------------------------------------------------------


class TestNetworkTypes:
    def test_network_summary(self, sample_network_summary: dict[str, Any]) -> None:
        s = NetworkSummary.model_validate(sample_network_summary)
        assert s.dns_count == 15
        assert s.pcap_available is True

    def test_network_summary_v2_unavailable(self, sample_network_summary: dict[str, Any]) -> None:
        payload = {
            **sample_network_summary,
            "pcapAvailable": False,
            "countsAvailable": False,
            "availability": {
                "state": "unavailable",
                "reason": "capture_unavailable",
                "coverage": "none",
            },
            "sourceScope": "none",
        }
        s = NetworkSummary.model_validate(payload)
        assert s.counts_available is False
        assert s.availability == NetworkAvailability(
            state="unavailable", reason="capture_unavailable", coverage="none"
        )
        assert s.source_scope == "none"
        assert s.pcap_available is False

    def test_network_summary_legacy_has_no_availability(
        self, sample_network_summary: dict[str, Any]
    ) -> None:
        s = NetworkSummary.model_validate(sample_network_summary)
        assert s.counts_available is None
        assert s.availability is None
        assert s.source_scope is None
        assert s.dns_count == 15
        assert s.pcap_available is True

    def test_network_summary_legacy_explicit_nulls(
        self, sample_network_summary: dict[str, Any]
    ) -> None:
        payload = {
            **sample_network_summary,
            "countsAvailable": True,
            "availability": None,
            "sourceScope": None,
        }
        s = NetworkSummary.model_validate(payload)
        assert s.counts_available is True
        assert s.availability is None

    def test_unknown_enum_values_parse(
        self,
        sample_network_summary: dict[str, Any],
        sample_dns_query: dict[str, Any],
    ) -> None:
        s = NetworkSummary.model_validate(
            {
                **sample_network_summary,
                "availability": {"state": "future_state", "reason": None, "coverage": "future_cov"},
                "sourceScope": "future_scope",
            }
        )
        assert s.availability is not None
        assert s.availability.state == "future_state"
        assert s.availability.coverage == "future_cov"
        assert s.source_scope == "future_scope"
        assert DnsQuery.model_validate({**sample_dns_query, "sourceScope": "x"}).source_scope == "x"

    def test_network_availability_null_reason(self) -> None:
        a = NetworkAvailability.model_validate(
            {"state": "observed", "reason": None, "coverage": "complete"}
        )
        assert a.reason is None

    def test_list_rows_source_scope(
        self,
        sample_dns_query: dict[str, Any],
        sample_http_request: dict[str, Any],
        sample_network_threat: dict[str, Any],
    ) -> None:
        assert DnsQuery.model_validate(sample_dns_query).source_scope is None
        dns = DnsQuery.model_validate({**sample_dns_query, "sourceScope": "sample_attributed"})
        assert dns.source_scope == "sample_attributed"
        http = HttpRequest.model_validate(
            {**sample_http_request, "sourceScope": "submission_ip_scoped"}
        )
        assert http.source_scope == "submission_ip_scoped"
        threat = NetworkThreat.model_validate({**sample_network_threat, "sourceScope": "none"})
        assert threat.source_scope == "none"

    def test_network_summary_round_trip(self, sample_network_summary: dict[str, Any]) -> None:
        first = NetworkSummary.model_validate(sample_network_summary)
        dumped = first.model_dump(by_alias=True)
        assert "pcapAvailable" in dumped
        second = NetworkSummary.model_validate(dumped)
        assert second.pcap_available is True

    def test_dns_query(self, sample_dns_query: dict[str, Any]) -> None:
        q = DnsQuery.model_validate(sample_dns_query)
        assert q.host == "malware.example.com"
        assert q.type == "A"
        assert q.status == "NOERROR"

    def test_dns_query_rejects_invalid_type(self, sample_dns_query: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            DnsQuery.model_validate({**sample_dns_query, "type": "AAAAA"})

    def test_http_request(self, sample_http_request: dict[str, Any]) -> None:
        h = HttpRequest.model_validate(sample_http_request)
        assert h.host == "malware.example.com"
        assert h.ip == "192.168.1.100"
        assert h.port == 80
        assert h.country == "US"

    def test_http_request_country_optional(self, sample_http_request: dict[str, Any]) -> None:
        no_country = {**sample_http_request}
        no_country.pop("country")
        h = HttpRequest.model_validate(no_country)
        assert h.country is None

    def test_http_request_does_not_have_method_field(
        self, sample_http_request: dict[str, Any]
    ) -> None:
        h = HttpRequest.model_validate(sample_http_request)
        assert not hasattr(h, "method")
        assert not hasattr(h, "url")

    def test_connection_packets(self) -> None:
        p = ConnectionPackets.model_validate({"sent": 1, "received": 2, "empty": False})
        assert p.sent == 1
        assert p.empty is False

    def test_connection_tcp(self, sample_tcp_connection: dict[str, Any]) -> None:
        c = Connection.model_validate(sample_tcp_connection)
        assert c.protocol == "tcp"
        assert c.destination_ip == "8.8.8.8"
        assert c.destination_port == 443
        assert c.packets.sent == 10

    def test_connection_udp(self, sample_udp_connection: dict[str, Any]) -> None:
        c = Connection.model_validate(sample_udp_connection)
        assert c.protocol == "udp"
        assert c.destination_port == 53

    def test_connection_round_trip(self, sample_tcp_connection: dict[str, Any]) -> None:
        first = Connection.model_validate(sample_tcp_connection)
        dumped = first.model_dump(by_alias=True)
        assert "destinationIp" in dumped
        second = Connection.model_validate(dumped)
        assert second.destination_ip == first.destination_ip

    def test_network_threat(self, sample_network_threat: dict[str, Any]) -> None:
        t = NetworkThreat.model_validate(sample_network_threat)
        assert t.signature == "ET MALWARE Trojan Communication"
        assert t.app_proto == "TLS"
        assert t.destination_port == 443
        assert t.tls is not None
        assert t.tls.ja3_hash == "abc123"

    @pytest.mark.parametrize("severity", ["high", "low", "info"])
    def test_network_threat_accepts_every_known_severity(
        self, sample_network_threat: dict[str, Any], severity: str
    ) -> None:
        t = NetworkThreat.model_validate({**sample_network_threat, "severity": severity})
        assert t.severity == severity

    def test_network_threat_keeps_an_unknown_severity(
        self, sample_network_threat: dict[str, Any]
    ) -> None:
        t = NetworkThreat.model_validate({**sample_network_threat, "severity": "critical"})
        assert t.severity == "critical"

    def test_network_threat_without_tls(self, sample_network_threat: dict[str, Any]) -> None:
        sample_network_threat["tls"] = None
        t = NetworkThreat.model_validate(sample_network_threat)
        assert t.tls is None

    def test_network_threat_tls_round_trip(self, sample_network_threat: dict[str, Any]) -> None:
        tls_payload = sample_network_threat["tls"]
        tls = NetworkThreatTls.model_validate(tls_payload)
        dumped = tls.model_dump(by_alias=True)
        assert "ja3Hash" in dumped
        again = NetworkThreatTls.model_validate(dumped)
        assert again.sni == "evil.com"


# ---------------------------------------------------------------------------
# Process / behaviour / syscall types
# ---------------------------------------------------------------------------


class TestNetworkRowSourceTypes:
    def test_older_server_rows_keep_every_field_and_default_the_source(
        self,
        sample_dns_query: dict[str, Any],
        sample_http_request: dict[str, Any],
        sample_tcp_connection: dict[str, Any],
        sample_network_threat: dict[str, Any],
    ) -> None:
        rows = [
            DnsQuery.model_validate(sample_dns_query),
            HttpRequest.model_validate(sample_http_request),
            Connection.model_validate(sample_tcp_connection),
            NetworkThreat.model_validate(sample_network_threat),
        ]
        for row in rows:
            assert row.attribution is None
            assert row.attribution_reason is None
            assert row.process_id is None
            assert row.process_image is None
        assert rows[0].status == "NOERROR"
        assert rows[0].status_text is None
        assert rows[2].destination_port == 443

    def test_rows_with_sources(self, sample_dns_query: dict[str, Any]) -> None:
        q = DnsQuery.model_validate(
            {
                **sample_dns_query,
                "status": "TIMEOUT",
                "statusText": "NO RESPONSE",
                "attribution": "sample_child",
                "attributionReason": "pid 2001 child",
                "processId": 2001,
                "processImage": "C:\\Windows\\System32\\cmd.exe",
            }
        )
        assert q.attribution == "sample_child"
        assert q.attribution_reason == "pid 2001 child"
        assert q.process_id == 2001
        assert q.status_text == "NO RESPONSE"

    def test_unknown_source_value_does_not_fail(self, sample_http_request: dict[str, Any]) -> None:
        r = HttpRequest.model_validate({**sample_http_request, "attribution": "future_source"})
        assert r.attribution == "future_source"

    def test_summary_windows_background_count(self, sample_network_summary: dict[str, Any]) -> None:
        assert (
            NetworkSummary.model_validate(sample_network_summary).windows_background_count is None
        )
        s = NetworkSummary.model_validate({**sample_network_summary, "windowsBackgroundCount": 7})
        assert s.windows_background_count == 7


class TestProcessTypes:
    def test_process(self, sample_process: dict[str, Any]) -> None:
        p = Process.model_validate(sample_process)
        assert p.pid == 1234
        assert p.network.count == 1
        assert p.events.items[0].type == "file"

    def test_processes_response(self, sample_processes_response: dict[str, Any]) -> None:
        resp = ProcessesResponse.model_validate(sample_processes_response)
        assert resp.total == 1
        assert isinstance(resp.items[0], Process)

    def test_process_tree_recursive(self, sample_process_tree_response: dict[str, Any]) -> None:
        resp = ProcessTreeResponse.model_validate(sample_process_tree_response)
        assert len(resp.nodes) == 1
        root = resp.nodes[0]
        assert root.pid == 1234
        assert len(root.children) == 1
        child = root.children[0]
        assert isinstance(child, ProcessTreeNode)
        assert child.pid == 5678
        assert child.children == []

    def test_process_tree_round_trip(self, sample_process_tree_response: dict[str, Any]) -> None:
        first = ProcessTreeResponse.model_validate(sample_process_tree_response)
        dumped = first.model_dump(by_alias=True)
        second = ProcessTreeResponse.model_validate(dumped)
        assert second.nodes[0].children[0].pid == 5678


class TestBehaviourTypes:
    def test_behaviour_event(self, sample_behaviour_event: dict[str, Any]) -> None:
        e = BehaviourEvent.model_validate(sample_behaviour_event)
        assert e.process_name == "evil.exe"
        assert e.event_id == 42
        assert e.event_count == 1
        assert e.syscall_line_number == 100
        assert e.details["path"] == "C:\\evil.dll"

    def test_behaviours_response(self, sample_behaviours_response: dict[str, Any]) -> None:
        resp = BehavioursResponse.model_validate(sample_behaviours_response)
        assert resp.total == 1
        assert resp.page == 1
        assert resp.limit == 100
        assert resp.total_pages == 1
        assert isinstance(resp.items[0], BehaviourEvent)

    def test_behaviour_event_round_trip(self, sample_behaviour_event: dict[str, Any]) -> None:
        first = BehaviourEvent.model_validate(sample_behaviour_event)
        dumped = first.model_dump(by_alias=True)
        assert "processName" in dumped
        assert "eventId" in dumped
        second = BehaviourEvent.model_validate(dumped)
        assert second.event_id == 42

    def test_behaviour_event_accepts_a_fractional_timestamp(
        self, sample_behaviour_event: dict[str, Any]
    ) -> None:
        e = BehaviourEvent.model_validate({**sample_behaviour_event, "timestamp": 1790376279.35})
        assert e.timestamp == 1790376279.35

    def test_behaviour_event_accepts_a_zero_timestamp(
        self, sample_behaviour_event: dict[str, Any]
    ) -> None:
        e = BehaviourEvent.model_validate({**sample_behaviour_event, "timestamp": 0})
        assert e.timestamp == 0

    def test_behaviour_event_keeps_an_integer_timestamp(
        self, sample_behaviour_event: dict[str, Any]
    ) -> None:
        e = BehaviourEvent.model_validate(sample_behaviour_event)
        assert e.timestamp == 1700000000

    def test_behaviour_event_without_timestamp(
        self, sample_behaviour_event: dict[str, Any]
    ) -> None:
        payload = {k: v for k, v in sample_behaviour_event.items() if k != "timestamp"}
        e = BehaviourEvent.model_validate(payload)
        assert e.timestamp is None


class TestSyscallTypes:
    def test_syscalls_response(self, sample_syscalls_response: dict[str, Any]) -> None:
        resp = SyscallsResponse.model_validate(sample_syscalls_response)
        assert resp.total == 2
        assert resp.items[0].startswith("00:00:01")


# ---------------------------------------------------------------------------
# CDR / static-scan / signature-check
# ---------------------------------------------------------------------------


class TestCdrTypes:
    def test_cdr_singleton(self, sample_cdr_response: dict[str, Any]) -> None:
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.submission == "uuid-1"
        assert resp.sanitized == ["doc.pdf"]
        assert resp.removed == ["macro1"]
        assert resp.sanitized_file_info is not None
        assert resp.sanitized_file_info.file_type == "PDF"
        assert resp.sanitized_file_info.file_size == 1024
        assert resp.sanitized_file_info.details[0].action == "removed"
        assert resp.elapsed_time == "00:00:43"
        assert resp.metafields is None

    def test_cdr_detail_data_as_a_string_list(self, sample_cdr_response: dict[str, Any]) -> None:
        sample_cdr_response["sanitizedFileInfo"]["details"] = [
            {"name": "macro", "action": "removed", "data": ["AutoOpen", "Document_Open"]}
        ]
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.sanitized_file_info is not None
        assert resp.sanitized_file_info.details[0].data == ["AutoOpen", "Document_Open"]

    def test_cdr_detail_data_as_an_object(self, sample_cdr_response: dict[str, Any]) -> None:
        sample_cdr_response["sanitizedFileInfo"]["details"] = [
            {"name": "macro", "action": "removed", "data": {"count": 2}}
        ]
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.sanitized_file_info is not None
        assert resp.sanitized_file_info.details[0].data == {"count": 2}

    def test_cdr_detail_data_as_a_string(self, sample_cdr_response: dict[str, Any]) -> None:
        sample_cdr_response["sanitizedFileInfo"]["details"] = [
            {"name": "macro", "action": "removed", "data": "AutoOpen"}
        ]
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.sanitized_file_info is not None
        assert resp.sanitized_file_info.details[0].data == "AutoOpen"


class TestStaticScanTypes:
    def test_static_scan_singleton_and_extra(
        self, sample_static_scan_response: dict[str, Any]
    ) -> None:
        resp = StaticScanResponse.model_validate(sample_static_scan_response)
        assert resp.submission == "uuid-1"
        assert resp.report_format == "exe"
        assert resp.level == "malicious"
        assert resp.score == 92.0
        assert resp.file_info is not None
        assert resp.file_info.sha256 == "c" * 64
        assert resp.strings is not None
        assert resp.strings.total_count == 1234
        assert resp.die_results[0].name == "PE"
        assert resp.analysis_time == "00:00:02"
        assert resp.metafields is None
        assert resp.model_extra is not None
        assert resp.model_extra["peExeSections"][0]["name"] == ".text"
        assert resp.model_extra["imports"][0]["library"] == "kernel32.dll"


class TestSignatureCheckTypes:
    def test_signature_check_result(self, sample_signature_check_response: dict[str, Any]) -> None:
        result = SignatureCheckResult.model_validate(sample_signature_check_response["items"][0])
        assert result.artifact == "art-1"
        assert result.data["signed"] is True

    def test_signature_check_response(
        self, sample_signature_check_response: dict[str, Any]
    ) -> None:
        resp = SignatureCheckResponse.model_validate(sample_signature_check_response)
        assert isinstance(resp.items[0], SignatureCheckResult)


# ---------------------------------------------------------------------------
# EML / MITRE / URL analysis
# ---------------------------------------------------------------------------


class TestEmlTypes:
    def test_eml_headers(self, sample_eml_analysis: dict[str, Any]) -> None:
        headers = EmlAnalysisHeaders.model_validate(sample_eml_analysis["headers"])
        assert headers.from_email == "alice@example.com"
        assert headers.to_emails == ["bob@example.com"]

    def test_eml_attachment(self, sample_eml_analysis: dict[str, Any]) -> None:
        att = EmlAnalysisAttachment.model_validate(sample_eml_analysis["attachments"][0])
        assert att.mime_type == "application/pdf"
        assert att.hash["md5"] == "abcd"

    def test_eml_qr_result(self, sample_eml_analysis: dict[str, Any]) -> None:
        qr = EmlAnalysisQrResult.model_validate(sample_eml_analysis["qr_results"][0])
        assert qr.data.startswith("https://")

    def test_eml_analysis(self, sample_eml_analysis: dict[str, Any]) -> None:
        eml = EmlAnalysis.model_validate(sample_eml_analysis)
        assert eml.headers.subject == "Hello"
        assert len(eml.attachments) == 1
        assert eml.artifact == "art-1"


class TestMitreTypes:
    def test_mitre_response(self, sample_mitre_response: dict[str, Any]) -> None:
        m = MitreResponse.model_validate(sample_mitre_response)
        assert m.total == 2
        assert m.techniques[0] == "T1547.001"


class TestUrlAnalysisTypes:
    def test_url_analysis_response(self, sample_url_analysis_response: dict[str, Any]) -> None:
        resp = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        assert resp.level == "malicious"
        assert resp.general_info.domain == "evil.com"
        assert resp.ip_info is not None
        assert resp.ip_info.threat_status.verdict == "malicious"
        assert resp.whois is not None
        assert resp.whois.name_servers == ["ns1.evil.com"]
        assert resp.ssl_certificate is not None
        assert resp.ssl_certificate.expires_at == 1900000000
        assert resp.threat_analysis is not None
        assert resp.threat_analysis.blacklist is True

    def test_url_analysis_optional_fields_nullable(
        self, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        sample_url_analysis_response["ipInfo"] = None
        sample_url_analysis_response["whois"] = None
        sample_url_analysis_response["sslCertificate"] = None
        sample_url_analysis_response["threatAnalysis"] = None
        sample_url_analysis_response["extractedFile"] = None
        resp = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        assert resp.ip_info is None
        assert resp.whois is None
        assert resp.ssl_certificate is None

    def test_url_analysis_round_trip(self, sample_url_analysis_response: dict[str, Any]) -> None:
        first = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        dumped = first.model_dump(by_alias=True)
        assert "generalInfo" in dumped
        assert "dnsRecords" in dumped
        second = UrlAnalysisResponse.model_validate(dumped)
        assert second.general_info.url == first.general_info.url

    def test_url_analysis_response_keeps_the_scoring_fields(
        self, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        report = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        assert report.threat_score == 72
        assert report.risk_level == "High"
        assert report.privacy_score == 35
        assert report.privacy_risk_level == "Medium"
        assert report.privacy_breakdown is not None
        assert report.privacy_breakdown[0].factor == "trackers"
        assert report.privacy_breakdown[0].delta == 20
        assert report.verdict_provenance is not None
        assert report.verdict_provenance.raw_verdict == "malicious"
        assert report.verdict_provenance.quorum_applied is False
        assert report.verdict_provenance.pass_ == "final"
        assert report.impersonation_target is not None
        assert report.impersonation_target.brand_name == "PayPal"
        assert report.impersonation_target.canonical_domain == "paypal.com"
        assert report.completeness is not None
        assert report.completeness.measured_sources == ["dns", "tls", "intel"]
        assert report.completeness.browser_collection == "partial"
        assert report.intel_detections[0].source == "urlhaus"
        assert report.intel_detections[0].detection_type == "malware_url"
        assert report.metafields == {"timeout": 240, "record_session": True}
        assert report.scored_at is not None

    def test_url_analysis_response_accepts_fractional_scores(
        self, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        sample_url_analysis_response["threatScore"] = 72.5
        sample_url_analysis_response["privacyScore"] = 35.25
        sample_url_analysis_response["privacyBreakdown"][0]["delta"] = 12.5
        report = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        assert report.threat_score == 72.5
        assert report.privacy_score == 35.25
        assert report.privacy_breakdown is not None
        assert report.privacy_breakdown[0].delta == 12.5

    def test_url_analysis_response_tolerates_an_unscored_report(self) -> None:
        report = UrlAnalysisResponse.model_validate(
            {
                "level": "unknown",
                "status": "completed",
                "generalInfo": {"url": "https://x", "domain": "x", "websiteTitle": None},
                "screenshot": {"available": False},
                "dnsRecords": [],
                "pages": [],
            }
        )
        assert report.threat_score is None
        assert report.risk_level is None
        assert report.verdict_provenance is None
        assert report.impersonation_target is None
        assert report.completeness is None
        assert report.intel_detections == []
        assert report.metafields is None
        assert report.scored_at is None

    def test_url_analysis_scoring_round_trip(
        self, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        first = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        dumped = first.model_dump(by_alias=True)
        assert "threatScore" in dumped
        assert "verdictProvenance" in dumped
        assert dumped["verdictProvenance"]["pass"] == "final"
        assert "intelDetections" in dumped
        second = UrlAnalysisResponse.model_validate(dumped)
        assert second.threat_score == first.threat_score


class TestUrlAnalysisSessionTypes:
    def test_url_analysis_session(self, url_analysis_session_payload: dict[str, Any]) -> None:
        session = UrlAnalysisSession.model_validate(url_analysis_session_payload)
        assert session.state == "running"
        assert session.collection_status == "collecting"
        assert session.recording_status == "recording"
        assert session.queue_position is None
        assert session.vnc_available is True
        assert session.report_available is False
        assert session.started_at == 1756288800000
        assert session.ready_at == 1756288805000
        assert session.expires_at == 1756288920000
        assert session.finished_at is None
        assert session.failure_code is None
        assert session.extensions_used == 0
        assert session.extensions_max == 3
        assert session.link == "wss://gateway.example/?token=abc"
        assert session.expired is False
        assert session.session_config is not None
        assert session.session_config.device_profile_id == "iphone-15-pro"
        assert session.session_config.network_config_id is None
        assert session.session_config.session_duration_seconds == 240
        assert session.session_config.device_preset_id == "68b0000000000000000000a1"

    def test_url_analysis_session_without_config(
        self, url_analysis_session_payload: dict[str, Any]
    ) -> None:
        url_analysis_session_payload["sessionConfig"] = None
        url_analysis_session_payload["link"] = None
        session = UrlAnalysisSession.model_validate(url_analysis_session_payload)
        assert session.session_config is None
        assert session.link is None

    def test_url_analysis_session_round_trip(
        self, url_analysis_session_payload: dict[str, Any]
    ) -> None:
        first = UrlAnalysisSession.model_validate(url_analysis_session_payload)
        dumped = first.model_dump(by_alias=True)
        assert "vncAvailable" in dumped
        assert "sessionConfig" in dumped
        second = UrlAnalysisSession.model_validate(dumped)
        assert second.state == first.state


# ---------------------------------------------------------------------------
# Config / downloads / me
# ---------------------------------------------------------------------------


class TestMessageType:
    def test_message(self) -> None:
        msg = Message.model_validate({"message": "URL report restart initiated successfully"})
        assert msg.message == "URL report restart initiated successfully"

    def test_message_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            Message.model_validate({})


class TestConfigTypes:
    def test_device_preset_option(self, device_presets_payload: list[dict[str, Any]]) -> None:
        preset = DevicePresetOption.model_validate(device_presets_payload[1])
        assert preset.id == "68b0000000000000000000a1"
        assert preset.name == "iPhone 15 Pro"
        assert preset.category == "mobile"
        assert preset.base_key == "iphone-15-pro"
        assert preset.default is False

    def test_device_preset_option_round_trip(
        self, device_presets_payload: list[dict[str, Any]]
    ) -> None:
        first = DevicePresetOption.model_validate(device_presets_payload[0])
        dumped = first.model_dump(by_alias=True)
        assert "baseKey" in dumped
        second = DevicePresetOption.model_validate(dumped)
        assert second.base_key == first.base_key

    def test_metafield_option(self, sample_metafields: dict[str, list[dict[str, Any]]]) -> None:
        opt = MetafieldOption.model_validate(sample_metafields["sandbox"][0])
        assert opt.key == "timeout"
        assert opt.type == "select"

    def test_metafields(self, sample_metafields: dict[str, list[dict[str, Any]]]) -> None:
        m = Metafields.model_validate(sample_metafields)
        assert len(m.sandbox) == 1
        assert len(m.open_in_browser) == 1

    def test_environment_option(self, sample_environments: list[dict[str, Any]]) -> None:
        env = EnvironmentOption.model_validate(sample_environments[0])
        assert env.key == "w10_x64"
        assert env.platform == "windows"
        assert env.default is True

    def test_metafield_active_accessible(
        self, sample_metafields: dict[str, list[dict[str, Any]]]
    ) -> None:
        mf = Metafields.model_validate(sample_metafields)
        opt = mf.sandbox[0]
        assert opt.active is True and opt.accessible is True
        assert opt.options is not None
        assert opt.options[0].accessible is True
        assert opt.options[2].accessible is False

    def test_environment_active_accessible(self, sample_environments: list[dict[str, Any]]) -> None:
        env = EnvironmentOption.model_validate(sample_environments[0])
        assert env.active is True and env.accessible is True


class TestDownloadTypes:
    def test_media_file(self, sample_media_files: list[dict[str, Any]]) -> None:
        media = MediaFile.model_validate(sample_media_files[0])
        assert media.id == "media-1"
        assert media.content_type == "image/png"

    def test_media_file_round_trip(self, sample_media_files: list[dict[str, Any]]) -> None:
        first = MediaFile.model_validate(sample_media_files[0])
        dumped = first.model_dump(by_alias=True)
        assert "contentType" in dumped

    def test_media_file_kind(self, sample_media_files: list[dict[str, Any]]) -> None:
        screenshot = MediaFile.model_validate(sample_media_files[0])
        video = MediaFile.model_validate(sample_media_files[1])
        assert screenshot.kind == "screenshot"
        assert video.kind == "video"

    def test_media_file_kind_defaults_to_none(self) -> None:
        media = MediaFile.model_validate({"id": "report.txt", "name": "report.txt"})
        assert media.kind is None


class TestMeTypes:
    def test_workspace_basic_info(self, sample_user_info: dict[str, Any]) -> None:
        ws = WorkspaceBasicInfo.model_validate(sample_user_info["userInfo"]["workspace"])
        assert ws.name == "Harkonnens"
        assert ws.type == "personal"

    def test_limits_count(self, sample_user_info: dict[str, Any]) -> None:
        lc = LimitsCount.model_validate(sample_user_info["userInfo"]["limitsCount"])
        assert lc.api_request_count == 50
        assert lc.daily_submission_count == 10

    def test_user_info_details(self, sample_user_info: dict[str, Any]) -> None:
        details = UserInfoDetails.model_validate(sample_user_info["userInfo"])
        assert details.email == "feyd@harkonnen.com"
        assert details.full_name == "Feyd Rautha"

    def test_plan_info(self, sample_user_info: dict[str, Any]) -> None:
        plan = PlanInfo.model_validate(sample_user_info["plan"])
        assert plan.plan_name == "Professional"
        assert plan.file_limits.file_size == "100 MB"
        assert plan.submission_limits.api_limit == 1000

    def test_module_info(self, sample_user_info: dict[str, Any]) -> None:
        m = ModuleInfo.model_validate(sample_user_info["modules"][0])
        assert m.module_id == "mod-1"
        assert m.module_name == "cdr"
        assert m.end_time == "Unlimited"

    def test_user_info(self, sample_user_info: dict[str, Any]) -> None:
        user = UserInfo.model_validate(sample_user_info)
        assert user.email == "feyd@harkonnen.com"
        assert user.workspace_name == "Harkonnens"
        assert user.workspace_alias == "spice-maniacs"

    def test_user_info_round_trip(self, sample_user_info: dict[str, Any]) -> None:
        first = UserInfo.model_validate(sample_user_info)
        dumped = first.model_dump(by_alias=True)
        assert "userInfo" in dumped
        assert "fullName" in dumped["userInfo"]
        second = UserInfo.model_validate(dumped)
        assert second.full_name == first.full_name


# ---------------------------------------------------------------------------
# API error envelope
# ---------------------------------------------------------------------------


class TestNetworkConfigs:
    def test_network_config_item(self, sample_network_config: dict[str, Any]) -> None:
        item = NetworkConfigListItem.model_validate(sample_network_config)
        assert item.id == "cfg1"
        assert item.type == "proxy"
        assert item.port == 1080
        assert item.has_config_file is False
        assert item.created_at == "2026-06-01T00:00:00.000Z"
        assert item.updated_at == "2026-06-01T00:00:00.000Z"

    def test_network_config_list_response(self, sample_network_config: dict[str, Any]) -> None:
        response = NetworkConfigListResponse.model_validate({"items": [sample_network_config]})
        assert len(response.items) == 1
        assert response.items[0].name == "Corp Proxy"

    def test_network_config_optional_fields_default_none(self) -> None:
        item = NetworkConfigListItem.model_validate(
            {
                "id": "cfg2",
                "name": "Corp VPN",
                "type": "openvpn",
                "hasConfigFile": True,
                "createdAt": "2026-06-02T00:00:00.000Z",
                "updatedAt": "2026-06-02T00:00:00.000Z",
            }
        )
        assert item.protocol is None
        assert item.host is None
        assert item.port is None
        assert item.username is None
        assert item.has_config_file is True


class TestApiErrorEnvelope:
    def test_api_error_canonical_payload(self, report_unavailable_409_body: dict[str, Any]) -> None:
        body = report_unavailable_409_body
        err = ApiError.model_validate(
            {
                "status_code": body["statusCode"],
                "error": body["error"],
                "message": body["message"],
                "code": body["code"],
                "details": body["details"],
            }
        )
        assert err.status_code == 409
        assert err.code == "DYNAMIC_REPORT_UNAVAILABLE"
        assert err.details is not None
        assert err.details["requiredReport"] == "dynamic"

    def test_api_error_rejects_unknown_code(self) -> None:
        with pytest.raises(ValidationError):
            ApiError.model_validate(
                {
                    "status_code": 500,
                    "error": "Internal",
                    "message": "boom",
                    "code": "NOT_A_REAL_CODE",
                }
            )


# ---------------------------------------------------------------------------
# Fields that the API returns (old server payloads omit them)
# ---------------------------------------------------------------------------


class TestSubmissionFileAndTagFields:
    def test_old_file_info_has_no_extension_facts(self, sample_submission: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission)
        assert sub.file is not None
        assert sub.file.declared_extension is None
        assert sub.file.real_extension is None
        assert sub.file.is_mimetype_mismatched is None

    def test_file_info_reads_the_extension_facts(self, sample_submission: dict[str, Any]) -> None:
        sample_submission["file"] = {
            **sample_submission["file"],
            "declaredExtension": "pdf",
            "realExtension": "exe",
            "isMimetypeMismatched": True,
        }
        sub = Submission.model_validate(sample_submission)
        assert sub.file is not None
        assert sub.file.declared_extension == "pdf"
        assert sub.file.real_extension == "exe"
        assert sub.file.is_mimetype_mismatched is True
        dumped = sub.file.model_dump(by_alias=True)
        assert dumped["declaredExtension"] == "pdf"
        assert dumped["isMimetypeMismatched"] is True

    def test_old_tag_has_no_origin(self) -> None:
        tag = Tag.model_validate({"type": "malware", "value": "trojan"})
        assert tag.origin is None

    def test_tag_reads_the_origin(self) -> None:
        tag = Tag.model_validate({"type": "malware", "value": "trojan", "origin": "dynamic"})
        assert tag.origin == "dynamic"

    def test_tag_keeps_a_null_origin(self) -> None:
        tag = Tag.model_validate({"type": "user", "value": "triage", "origin": None})
        assert tag.origin is None

    def test_tag_keeps_an_unknown_origin(self) -> None:
        tag = Tag.model_validate({"type": "malware", "value": "trojan", "origin": "future_engine"})
        assert tag.origin == "future_engine"


class TestIndicatorVerdictFields:
    def test_old_indicator_has_no_verdict_fields(self, sample_indicator: dict[str, Any]) -> None:
        indicator = Indicator.model_validate(sample_indicator)
        assert indicator.why_matched is None
        assert indicator.in_verdict_chain is None

    def test_indicator_reads_the_verdict_fields(self, sample_indicator: dict[str, Any]) -> None:
        indicator = Indicator.model_validate(
            {
                **sample_indicator,
                "whyMatched": "The sample opened lsass.exe with PROCESS_VM_READ access.",
                "inVerdictChain": True,
            }
        )
        assert indicator.why_matched == "The sample opened lsass.exe with PROCESS_VM_READ access."
        assert indicator.in_verdict_chain is True
        dumped = indicator.model_dump(by_alias=True)
        assert dumped["whyMatched"].startswith("The sample opened")
        assert dumped["inVerdictChain"] is True


class TestArtifactProcessAttribution:
    def test_old_artifact_has_no_process_attribution(self, sample_artifact: dict[str, Any]) -> None:
        artifact = Artifact.model_validate(sample_artifact)
        assert artifact.process_attribution is None

    def test_artifact_reads_the_process_attribution(self, sample_artifact: dict[str, Any]) -> None:
        artifact = Artifact.model_validate({**sample_artifact, "processAttribution": "unknown"})
        assert artifact.process_attribution == "unknown"

    def test_artifact_keeps_an_unknown_process_attribution(
        self, sample_artifact: dict[str, Any]
    ) -> None:
        artifact = Artifact.model_validate({**sample_artifact, "processAttribution": "sample"})
        assert artifact.process_attribution == "sample"


class TestSyscallPagination:
    def test_old_syscalls_response_has_no_page_fields(
        self, sample_syscalls_response: dict[str, Any]
    ) -> None:
        resp = SyscallsResponse.model_validate(sample_syscalls_response)
        assert resp.page is None
        assert resp.limit is None
        assert resp.total_pages is None

    def test_syscalls_response_reads_the_page_fields(
        self, sample_syscalls_response: dict[str, Any]
    ) -> None:
        resp = SyscallsResponse.model_validate(
            {**sample_syscalls_response, "page": 2, "limit": 500, "totalPages": 31}
        )
        assert resp.page == 2
        assert resp.limit == 500
        assert resp.total_pages == 31


class TestNetworkExfilFields:
    def test_old_network_summary_has_no_exfil_count(
        self, sample_network_summary: dict[str, Any]
    ) -> None:
        summary = NetworkSummary.model_validate(sample_network_summary)
        assert summary.exfil_request_count is None

    def test_network_summary_reads_the_exfil_count(
        self, sample_network_summary: dict[str, Any]
    ) -> None:
        summary = NetworkSummary.model_validate({**sample_network_summary, "exfilRequestCount": 2})
        assert summary.exfil_request_count == 2

    def test_old_network_threat_has_no_capture(self, sample_network_threat: dict[str, Any]) -> None:
        threat = NetworkThreat.model_validate(sample_network_threat)
        assert threat.capture is None

    @pytest.mark.parametrize("capture", ["decrypted_https", "offline_scan"])
    def test_network_threat_reads_every_known_capture(
        self, sample_network_threat: dict[str, Any], capture: str
    ) -> None:
        threat = NetworkThreat.model_validate({**sample_network_threat, "capture": capture})
        assert threat.capture == capture

    def test_network_threat_keeps_an_unknown_capture(
        self, sample_network_threat: dict[str, Any]
    ) -> None:
        threat = NetworkThreat.model_validate({**sample_network_threat, "capture": "live_tap"})
        assert threat.capture == "live_tap"

    def test_exfil_request_reads_every_field(
        self, sample_network_exfil_request: dict[str, Any]
    ) -> None:
        entry = NetworkExfilRequest.model_validate(sample_network_exfil_request)
        assert entry.api == "telegram_bot"
        assert entry.kind == "send_file"
        assert entry.api_method == "sendDocument"
        assert entry.target_id == "123456789"
        assert entry.masked_target == "/bot123456789:FAKE-TOKEN-FOR-TESTS/sendDocument"
        assert entry.request_bytes == 1051
        assert entry.reply_status is None
        assert entry.request_count == 1
        assert entry.capture == "decrypted_https"
        assert entry.first_seen is not None
        assert entry.first_seen.year == 2026
        assert entry.score == 80
        assert entry.tier == "Malicious"
        assert entry.process_id == 1508
        assert entry.process_image is not None
        assert entry.text is not None

    def test_exfil_request_keeps_unknown_enum_values(
        self, sample_network_exfil_request: dict[str, Any]
    ) -> None:
        entry = NetworkExfilRequest.model_validate(
            {
                **sample_network_exfil_request,
                "api": "matrix_bot",
                "kind": "edit_message",
                "capture": "offline_scan",
            }
        )
        assert entry.api == "matrix_bot"
        assert entry.kind == "edit_message"
        assert entry.capture == "offline_scan"

    def test_exfil_request_accepts_a_sparse_payload(self) -> None:
        entry = NetworkExfilRequest.model_validate({"api": "discord_webhook"})
        assert entry.api == "discord_webhook"
        assert entry.masked_target is None
        assert entry.first_seen is None


class TestPdfReportStatusTypes:
    def test_queued_status_reads_the_retry_hint(
        self, sample_pdf_report_status_queued: dict[str, Any]
    ) -> None:
        status = PdfReportStatus.model_validate(sample_pdf_report_status_queued)
        assert status.status == "queued"
        assert status.retry_after_seconds == 3
        assert status.message is None

    def test_analysis_in_progress_status_reads_the_message(self) -> None:
        status = PdfReportStatus.model_validate(
            {"status": "analysis_in_progress", "message": "V2 report is not committed."}
        )
        assert status.message == "V2 report is not committed."
        assert status.retry_after_seconds is None

    def test_status_keeps_an_unknown_value(self) -> None:
        status = PdfReportStatus.model_validate({"status": "rendering_pages"})
        assert status.status == "rendering_pages"


class TestAiReportTypes:
    def test_completed_report_reads_the_content(self, sample_ai_report: dict[str, Any]) -> None:
        report = AiReport.model_validate(sample_ai_report)
        assert report.status == "completed"
        assert report.verdict == "malicious"
        assert report.family_status == "confirmed"
        assert report.updated_at is not None
        content = report.report
        assert content is not None
        assert content.summary is not None
        assert content.summary.engine_verdict == "malicious"
        assert content.classification is not None
        assert content.classification.family is not None
        assert content.classification.family.name == "AgentTesla"
        assert content.techniques is not None
        assert content.techniques[0].origin == "engine"
        assert content.attack_flow is not None
        assert content.attack_flow.edges is not None
        assert content.attack_flow.edges[0].from_ == "n1"
        assert content.screenshots is not None
        assert content.screenshots[0].threat_relevant is True
        assert content.ioc_review is not None
        assert content.ioc_review.summary is not None
        assert content.ioc_review.summary.reviewed_by_model == 0
        assert content.ioc_review.candidates is not None
        assert content.ioc_review.candidates[0].decided_by == "rule"

    def test_edge_dumps_the_from_key(self, sample_ai_report: dict[str, Any]) -> None:
        report = AiReport.model_validate(sample_ai_report)
        dumped = report.model_dump(by_alias=True)
        assert dumped["report"]["attackFlow"]["edges"][0]["from"] == "n1"

    def test_failed_report_has_no_content(self) -> None:
        report = AiReport.model_validate(
            {
                "jobId": None,
                "status": "failed",
                "verdict": None,
                "confidence": None,
                "agreesWithEngine": None,
                "family": None,
                "familyStatus": None,
                "report": None,
                "updatedAt": "2026-09-28T10:00:00.000Z",
            }
        )
        assert report.status == "failed"
        assert report.report is None

    def test_report_without_ioc_review(self, sample_ai_report: dict[str, Any]) -> None:
        sample_ai_report["report"]["iocReview"] = None
        report = AiReport.model_validate(sample_ai_report)
        assert report.report is not None
        assert report.report.ioc_review is None

    def test_report_keeps_unknown_enum_values(self, sample_ai_report: dict[str, Any]) -> None:
        sample_ai_report["status"] = "archived"
        sample_ai_report["verdict"] = "likely_malicious"
        sample_ai_report["report"]["narrative"][0]["phase"] = "lateral_movement"
        sample_ai_report["report"]["iocs"][0]["evidence"][0]["source"] = "future_engine"
        report = AiReport.model_validate(sample_ai_report)
        assert report.status == "archived"
        assert report.verdict == "likely_malicious"
        assert report.report is not None
        assert report.report.narrative is not None
        assert report.report.narrative[0].phase == "lateral_movement"

    def test_report_accepts_a_sparse_content(self) -> None:
        report = AiReport.model_validate(
            {"status": "stale", "report": {"summary": {"verdict": "benign"}}}
        )
        assert report.report is not None
        assert report.report.iocs is None
        assert report.updated_at is None

    def test_in_progress_body_reads_the_stage(
        self, sample_ai_report_in_progress: dict[str, Any]
    ) -> None:
        pending = AiReportPending.model_validate(sample_ai_report_in_progress)
        assert pending.status == "in_progress"
        assert pending.stage == "writing"

    @pytest.mark.parametrize("status", ["waiting_for_analysis", "queued"])
    def test_pending_body_has_no_stage(self, status: str) -> None:
        pending = AiReportPending.model_validate({"status": status})
        assert pending.status == status
        assert pending.stage is None
        assert pending.job_id is None

    def test_pending_body_keeps_unknown_values(self) -> None:
        pending = AiReportPending.model_validate({"status": "throttled", "stage": "reviewing"})
        assert pending.status == "throttled"
        assert pending.stage == "reviewing"
