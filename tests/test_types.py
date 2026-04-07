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
    Artifact,
    ArtifactHashes,
    ArtifactsResponse,
    BehaviourEvent,
    BehavioursResponse,
    CdrResponse,
    CdrResult,
    Connection,
    ConnectionPackets,
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
    MetafieldOption,
    Metafields,
    MitreResponse,
    ModuleInfo,
    NetworkSummary,
    NetworkThreat,
    NetworkThreatTls,
    OverviewSummary,
    PaginatedSubmissions,
    PlanInfo,
    Process,
    ProcessesResponse,
    ProcessTreeNode,
    ProcessTreeResponse,
    ReportStatus,
    SignatureCheckResponse,
    SignatureCheckResult,
    StaticScanResponse,
    StaticScanResult,
    Submission,
    SubmissionCreated,
    SubmissionListItem,
    SubmissionOverview,
    SubmissionOverviewJobs,
    SyscallsResponse,
    Tag,
    UrlAnalysisResponse,
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
        jobs = SubmissionOverviewJobs.model_validate({"completed": 2, "total": 3})
        assert jobs.completed == 2
        assert jobs.total == 3

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

    def test_artifact_rejects_invalid_type(self, sample_artifact: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            Artifact.model_validate({**sample_artifact, "type": "not-a-real-type"})

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

    def test_overview_summary_without_network(
        self, sample_overview_summary: dict[str, Any]
    ) -> None:
        sample_overview_summary["network"] = None
        summary = OverviewSummary.model_validate(sample_overview_summary)
        assert summary.network is None

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
        assert resp.os == "windows"
        assert resp.total == 1
        assert isinstance(resp.items[0], BehaviourEvent)

    def test_behaviour_event_round_trip(self, sample_behaviour_event: dict[str, Any]) -> None:
        first = BehaviourEvent.model_validate(sample_behaviour_event)
        dumped = first.model_dump(by_alias=True)
        assert "processName" in dumped
        assert "eventId" in dumped
        second = BehaviourEvent.model_validate(dumped)
        assert second.event_id == 42


class TestSyscallTypes:
    def test_syscalls_response(self, sample_syscalls_response: dict[str, Any]) -> None:
        resp = SyscallsResponse.model_validate(sample_syscalls_response)
        assert resp.total == 2
        assert resp.items[0].startswith("00:00:01")


# ---------------------------------------------------------------------------
# CDR / static-scan / signature-check
# ---------------------------------------------------------------------------


class TestCdrTypes:
    def test_cdr_result(self, sample_cdr_response: dict[str, Any]) -> None:
        result = CdrResult.model_validate(sample_cdr_response["items"][0])
        assert result.artifact == "art-1"
        assert result.engine_version == "1.2.3"

    def test_cdr_response(self, sample_cdr_response: dict[str, Any]) -> None:
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.total == 1
        assert isinstance(resp.items[0], CdrResult)


class TestStaticScanTypes:
    def test_static_scan_result(self, sample_static_scan_response: dict[str, Any]) -> None:
        result = StaticScanResult.model_validate(sample_static_scan_response["items"][0])
        assert result.artifact == "art-1"
        assert result.data is not None
        assert result.engine_version == "9.9.9"

    def test_static_scan_response(self, sample_static_scan_response: dict[str, Any]) -> None:
        resp = StaticScanResponse.model_validate(sample_static_scan_response)
        assert isinstance(resp.items[0], StaticScanResult)


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


# ---------------------------------------------------------------------------
# Config / downloads / me
# ---------------------------------------------------------------------------


class TestConfigTypes:
    def test_metafield_option(self, sample_metafields: dict[str, list[dict[str, Any]]]) -> None:
        opt = MetafieldOption.model_validate(sample_metafields["sandbox"][0])
        assert opt.key == "timeout"
        assert opt.type == "number"

    def test_metafields(self, sample_metafields: dict[str, list[dict[str, Any]]]) -> None:
        m = Metafields.model_validate(sample_metafields)
        assert len(m.sandbox) == 1
        assert len(m.open_in_browser) == 1

    def test_environment_option(self, sample_environments: list[dict[str, Any]]) -> None:
        env = EnvironmentOption.model_validate(sample_environments[0])
        assert env.key == "w10_x64"
        assert env.platform == "windows"
        assert env.default is True


class TestDownloadTypes:
    def test_media_file(self, sample_media_files: list[dict[str, Any]]) -> None:
        media = MediaFile.model_validate(sample_media_files[0])
        assert media.id == "media-1"
        assert media.content_type == "image/png"

    def test_media_file_round_trip(self, sample_media_files: list[dict[str, Any]]) -> None:
        first = MediaFile.model_validate(sample_media_files[0])
        dumped = first.model_dump(by_alias=True)
        assert "contentType" in dumped


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
