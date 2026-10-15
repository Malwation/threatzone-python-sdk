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
    AiReportRegenerateResult,
    AnnotationNote,
    AnnotationPin,
    Annotations,
    Artifact,
    ArtifactHashes,
    ArtifactJob,
    ArtifactsResponse,
    BehaviourEvent,
    BehaviourFacets,
    BehavioursResponse,
    BehaviourSummary,
    CdrResponse,
    CdrSanitizedFileInfoDetail,
    CompareDetection,
    CompareDroppedFile,
    CompareIoc,
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
    IndicatorActor,
    IndicatorLevels,
    IndicatorRelated,
    IndicatorRelatedActor,
    IndicatorsResponse,
    IndicatorTarget,
    IoC,
    IoCsResponse,
    Killchain,
    KillchainDroppedFile,
    KillchainMemoryDump,
    KillchainProcess,
    LimitsCount,
    MediaFile,
    Message,
    MetafieldOption,
    Metafields,
    MitreResponse,
    MitreTechniqueUsage,
    ModuleInfo,
    NetworkAvailability,
    NetworkConfigListItem,
    NetworkConfigListResponse,
    NetworkEndpoints,
    NetworkExfilRequest,
    NetworkFlowPackets,
    NetworkHostFlows,
    NetworkHttpPackets,
    NetworkPacketData,
    NetworkSummary,
    NetworkThreat,
    NetworkThreatTls,
    OverviewSummary,
    PaginatedSubmissions,
    PdfReportStatus,
    PlanInfo,
    PlanPermissions,
    PreviousRun,
    Process,
    ProcessesResponse,
    ProcessTreeNode,
    ProcessTreeResponse,
    ReportStatus,
    RunComparison,
    RunJavaOutput,
    RunNote,
    RunNotes,
    ScoreBreakdown,
    SignatureCheckResponse,
    SignatureCheckResult,
    StaticScanOneNoteEmbeddedFile,
    StaticScanResponse,
    StringFact,
    StringFacts,
    StringItem,
    StringObservable,
    StringsPage,
    Submission,
    SubmissionCreated,
    SubmissionListItem,
    SubmissionOverview,
    SubmissionOverviewJobs,
    SyscallSearchResult,
    SyscallsResponse,
    Tag,
    TotalCountList,
    UrlAnalysisBrowserSection,
    UrlAnalysisIndicatorEvidence,
    UrlAnalysisIndicators,
    UrlAnalysisResponse,
    UrlAnalysisSession,
    UserInfo,
    UserInfoDetails,
    Verdict,
    VerdictNarrative,
    VerdictStory,
    VerdictStoryStep,
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
        assert t.author is None

    def test_tag_author(self) -> None:
        system_tag = Tag.model_validate({"type": "family", "value": "x", "author": "system"})
        user_tag = Tag.model_validate({"type": "note", "value": "y", "author": "user"})
        assert system_tag.author == "system"
        assert user_tag.author == "user"

    def test_tag_keeps_an_unknown_author(self) -> None:
        tag = Tag.model_validate({"type": "family", "value": "x", "author": "integration"})
        assert tag.author == "integration"

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
        assert status.metafields is None

    def test_report_status_metafields(self) -> None:
        status = ReportStatus.model_validate(
            {
                "type": "dynamic",
                "status": "completed",
                "metafields": {"Work Path": "Desktop", "Timeout": "120"},
            }
        )
        assert status.metafields == {"Work Path": "Desktop", "Timeout": "120"}

    def test_file_info_without_history(self) -> None:
        info = FileInfo.model_validate(
            {
                "name": "x.exe",
                "size": 1024,
                "extension": "exe",
                "mimetype": "application/octet-stream",
                "isMimetypeChecked": True,
                "source": {"type": "upload", "url": None},
            }
        )
        assert info.history is None

    def test_file_info_history(self) -> None:
        info = FileInfo.model_validate(
            {
                "name": "x.exe",
                "size": 1024,
                "extension": "exe",
                "mimetype": "application/octet-stream",
                "isMimetypeChecked": True,
                "source": {"type": "upload", "url": None},
                "history": {"filenames": ["x.exe", "y.exe"], "lastReceivedAt": 1718447400000},
            }
        )
        assert info.history is not None
        assert info.history.filenames == ["x.exe", "y.exe"]
        assert info.history.last_received_at == 1718447400000


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

    def test_submission_from_an_older_server(self, sample_submission: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission)
        assert sub.score_breakdown is None
        assert sub.overview.duration is None
        assert sub.file is not None
        assert sub.file.history is None
        assert all(report.metafields is None for report in sub.reports)
        assert all(tag.author is None for tag in sub.tags)

    def test_submission_detail_fields(self, sample_submission_detail: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission_detail)
        assert sub.overview.duration == 42.7
        assert sub.file is not None
        assert sub.file.history is not None
        assert sub.file.history.filenames == ["test.exe", "invoice.exe"]
        assert sub.file.history.last_received_at == 1718447400000
        assert sub.reports[0].metafields == {
            "Work Path": "Desktop",
            "Enable Memory Dumps": "Enabled",
        }
        assert sub.reports[1].metafields is None
        assert [tag.author for tag in sub.tags] == ["system", "user"]

    def test_submission_score_breakdown(self, sample_submission_detail: dict[str, Any]) -> None:
        sub = Submission.model_validate(sample_submission_detail)
        breakdown = sub.score_breakdown
        assert breakdown is not None
        assert breakdown.deciding_layer == "indicator_mean"
        assert breakdown.verdict == "Malicious"
        assert breakdown.score == sub.score
        assert breakdown.cap == 95
        assert [c.indicator_id for c in breakdown.contributors] == [
            "ransomware-shadow-copy-delete",
            None,
        ]
        assert breakdown.contributors[1].points == 62.5
        assert breakdown.contributors[1].level == "suspicious"
        assert breakdown.what_would_change == [
            "One malicious finding removes the benign findings from the mean score."
        ]

    def test_score_breakdown_keeps_unknown_layer_and_level(
        self, sample_score_breakdown: dict[str, Any]
    ) -> None:
        payload = {**sample_score_breakdown, "decidingLayer": "ml_model", "cap": None}
        payload["contributors"] = [{**payload["contributors"][0], "level": "informative"}]
        breakdown = ScoreBreakdown.model_validate(payload)
        assert breakdown.deciding_layer == "ml_model"
        assert breakdown.cap is None
        assert breakdown.contributors[0].level == "informative"

    def test_pure_url_submission_has_no_score(self, sample_submission: dict[str, Any]) -> None:
        payload = {
            **sample_submission,
            "type": "url",
            "filename": None,
            "url": "https://example.com",
            "hashes": None,
            "file": None,
            "level": "unknown",
            "score": None,
            "scoreBreakdown": None,
        }
        sub = Submission.model_validate(payload)
        assert sub.score is None
        assert sub.score_breakdown is None

    def test_submission_detail_round_trip(self, sample_submission_detail: dict[str, Any]) -> None:
        first = Submission.model_validate(sample_submission_detail)
        second = Submission.model_validate(first.model_dump(by_alias=True, mode="json"))
        assert second == first

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

    def test_indicator_without_v2_fields(self, sample_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_indicator)
        assert ind.pid_gens is None
        assert ind.rule_source is None
        assert ind.what_happened is None
        assert ind.why_it_matters is None
        assert ind.why_this_tier is None
        assert ind.not_observed is None
        assert ind.outcome is None
        assert ind.score_note is None
        assert ind.score_factors is None
        assert ind.score_result is None
        assert ind.score_cap is None
        assert ind.related is None
        assert ind.actor is None
        assert ind.target is None
        assert ind.t_offset_s is None
        assert ind.span_s is None
        assert ind.occurrences is None
        assert ind.finding_source is None
        assert ind.artifacts is None
        assert ind.dynamic_indicator_id is None

    def test_indicator_v2_fields(self, sample_indicator_v2: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_indicator_v2)
        assert ind.pid_gens == [1, 2]
        assert ind.rule_source == "behavior:process_hollowing"
        assert ind.what_happened is not None
        assert ind.why_it_matters is not None
        assert ind.why_this_tier is not None
        assert ind.not_observed == ["No network connection from svchost.exe"]
        assert ind.outcome == "svchost.exe ran the injected code."
        assert ind.score_note == "Score: base 90 x confidence 1.05 = 95 (cap 95)."
        assert ind.score_factors == ["base 90", "confidence 1.05"]
        assert ind.score_result == 95
        assert ind.score_cap == 95
        assert ind.t_offset_s == 4.2
        assert ind.span_s == 1.5
        assert ind.occurrences == 3
        assert ind.actor == IndicatorActor(
            image="word.exe", pid=3448, pid_gen=1, lineage="explorer.exe > word.exe"
        )
        assert ind.target == IndicatorTarget(kind="process", value="svchost.exe")
        assert ind.related is not None
        first, second = ind.related
        assert isinstance(first, IndicatorRelated)
        assert first.event_id == 1024
        assert first.signal_id == "sig-0012"
        assert first.t_offset_s == 4.2
        assert first.actor == IndicatorRelatedActor(image="word.exe", pid=3448)
        assert second.event_id is None
        assert second.t_offset_s is None
        assert second.actor is None

    def test_indicator_score_note_without_known_form(
        self, sample_indicator_v2: dict[str, Any]
    ) -> None:
        ind = Indicator.model_validate(
            {
                **sample_indicator_v2,
                "scoreNote": None,
                "scoreFactors": [],
                "scoreResult": None,
                "scoreCap": None,
            }
        )
        assert ind.score_note is None
        assert ind.score_factors == []
        assert ind.score_result is None
        assert ind.score_cap is None

    def test_indicator_actor_with_null_process_fields(
        self, sample_indicator_v2: dict[str, Any]
    ) -> None:
        ind = Indicator.model_validate(
            {
                **sample_indicator_v2,
                "actor": {"image": "word.exe", "pid": None, "pidGen": None, "lineage": None},
                "target": {"kind": None, "value": None},
            }
        )
        assert ind.actor == IndicatorActor(image="word.exe")
        assert ind.target == IndicatorTarget()

    def test_indicator_overview_row_fields(self, sample_overview_indicator: dict[str, Any]) -> None:
        ind = Indicator.model_validate(sample_overview_indicator)
        assert ind.id == ""
        assert ind.finding_source == "dynamic_scan"
        assert ind.category == [ind.finding_source]
        assert ind.artifacts == ["507f1f77bcf86cd799439015"]
        assert ind.dynamic_indicator_id == "507f1f77bcf86cd799439011"

    def test_indicator_v2_round_trip(self, sample_indicator_v2: dict[str, Any]) -> None:
        first = Indicator.model_validate(sample_indicator_v2)
        second = Indicator.model_validate(first.model_dump(by_alias=True))
        assert second == first

    def test_indicators_response(self, sample_indicators_response: dict[str, Any]) -> None:
        resp = IndicatorsResponse.model_validate(sample_indicators_response)
        assert resp.total == 1
        assert resp.levels.malicious == 5
        assert isinstance(resp.items[0], Indicator)

    def test_ioc(self, sample_ioc: dict[str, Any]) -> None:
        ioc = IoC.model_validate(sample_ioc)
        assert ioc.type == "domain"
        assert ioc.artifacts == ["art-1"]

    def test_ioc_without_raw_type(self, sample_ioc: dict[str, Any]) -> None:
        assert IoC.model_validate(sample_ioc).raw_type is None

    def test_ioc_raw_type(self, sample_ioc: dict[str, Any]) -> None:
        ioc = IoC.model_validate({**sample_ioc, "type": "ip", "rawType": "IP"})
        assert ioc.type == "ip"
        assert ioc.raw_type == "IP"
        assert IoC.model_validate({**sample_ioc, "rawType": None}).raw_type is None

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

    def test_artifact_without_analysis_fields(self, sample_artifact: dict[str, Any]) -> None:
        artifact = Artifact.model_validate(sample_artifact)
        assert artifact.analysis_status is None
        assert artifact.analysis_trigger is None
        assert artifact.analysis_reason is None
        assert artifact.download_link is None

    def test_artifact_analysis_fields(self, sample_artifact_v2: dict[str, Any]) -> None:
        artifact = Artifact.model_validate(sample_artifact_v2)
        assert artifact.source == "dynamic_report"
        assert artifact.analysis_status == "skipped"
        assert artifact.analysis_trigger == "auto"
        assert artifact.analysis_reason == (
            "Artifact exceeds the maximum file size supported for engine analysis."
        )
        assert artifact.download_link == (
            "/public-api/submissions/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            "/download/artifact/507f1f77bcf86cd799439015"
        )

    def test_artifact_not_analyzed(self, sample_artifact_v2: dict[str, Any]) -> None:
        artifact = Artifact.model_validate(
            {
                **sample_artifact_v2,
                "analysisStatus": "not_analyzed",
                "analysisTrigger": None,
                "analysisReason": None,
            }
        )
        assert artifact.analysis_status == "not_analyzed"
        assert artifact.analysis_trigger is None
        assert artifact.analysis_reason is None

    def test_artifact_keeps_unknown_analysis_values(
        self, sample_artifact_v2: dict[str, Any]
    ) -> None:
        artifact = Artifact.model_validate(
            {
                **sample_artifact_v2,
                "source": "future_source",
                "analysisStatus": "future_status",
                "analysisTrigger": "future_trigger",
            }
        )
        assert artifact.source == "future_source"
        assert artifact.analysis_status == "future_status"
        assert artifact.analysis_trigger == "future_trigger"

    def test_artifact_job(self, sample_artifact_jobs_response: dict[str, Any]) -> None:
        jobs = [ArtifactJob.model_validate(item) for item in sample_artifact_jobs_response["items"]]
        assert [job.engine_type for job in jobs] == [
            "static_scan",
            "ioc_extractor",
            "config_extractor",
        ]
        assert [job.status for job in jobs] == ["success", "failed", "skipped"]
        assert [job.error_code for job in jobs] == [None, "JOB_DEAD_LETTERED", "JOB_SKIPPED"]

    def test_artifact_job_keeps_unknown_values(self) -> None:
        job = ArtifactJob.model_validate(
            {"engineType": "future_engine", "status": "future_status", "errorCode": "JOB_NEW"}
        )
        assert job.engine_type == "future_engine"
        assert job.status == "future_status"
        assert job.error_code == "JOB_NEW"

    def test_artifact_job_without_error_code(self) -> None:
        job = ArtifactJob.model_validate({"engineType": "static_scan", "status": "running"})
        assert job.error_code is None

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


class TestKillchainTypes:
    def test_killchain(self, sample_killchain: dict[str, Any]) -> None:
        kc = Killchain.model_validate(sample_killchain)
        assert kc.dump_collector_active is True
        coverage = kc.artifact_inventory_coverage
        assert coverage is not None
        assert coverage.source_status == "available"
        assert [(c.name, c.value) for c in coverage.counts] == [
            ("event_file_count", 3),
            ("sidecar_count", 2),
        ]
        assert coverage.unretained_rows_omitted == 0
        process = kc.created_processes[0]
        assert isinstance(process, KillchainProcess)
        assert (process.pid, process.pid_gen) == (1508, 4)
        assert process.process_name == "payload.exe"
        assert process.work_dir == "C:\\Users\\Public"
        assert process.exit_timestamp == 1790376284.1
        assert process.events.count == 87
        assert process.network.items[0].port == 443
        group = kc.dropped_files[0]
        assert group.executable_path == "C:\\Users\\analyst\\Desktop\\payload.exe"
        dropped = group.files[0]
        assert isinstance(dropped, KillchainDroppedFile)
        assert dropped.artifact_id == "65f0aa000000000000000001"
        assert dropped.analysis_status == "analyzed"
        assert dropped.path_authority == "verified_volume_map"
        assert dropped.capture_closed is True
        assert dropped.retention == "retained"
        assert dropped.event_seq == 1182
        region = kc.mem_dumps[0].regions[0]
        assert (region.offset_start, region.offset_end) == ("0x400000", "0x401000")
        dump = region.dumps[0]
        assert isinstance(dump, KillchainMemoryDump)
        assert dump.file_size == 4096
        assert dump.analysis_status == "not_analyzed"

    def test_v1_killchain_has_null_v2_fields(self, sample_killchain_v1: dict[str, Any]) -> None:
        kc = Killchain.model_validate(sample_killchain_v1)
        assert kc.artifact_inventory_coverage is None
        assert kc.mem_dumps == []
        process = kc.created_processes[0]
        assert process.pid_gen is None
        assert process.origin is None
        assert process.tid is None
        assert process.timestamp is None
        assert process.work_dir is None
        group = kc.dropped_files[0]
        assert group.pid_gen is None
        dropped = group.files[0]
        assert dropped.artifact_id is None
        assert dropped.analysis_status is None
        assert dropped.raw_path is None
        assert dropped.path_authority is None
        assert dropped.retention is None
        assert dropped.event_seq is None

    def test_killchain_keeps_unknown_enum_values(self, sample_killchain: dict[str, Any]) -> None:
        payload = sample_killchain
        payload["createdProcesses"][0]["origin"] = "scheduler"
        dropped = payload["droppedFiles"][0]["files"][0]
        dropped["pathAuthority"] = "future_authority"
        dropped["retention"] = "future_retention"
        dropped["analysisStatus"] = "future_status"
        payload["artifactInventoryCoverage"]["sourceStatus"] = "unavailable"
        payload["artifactInventoryCoverage"]["sourceError"] = "future_error"
        kc = Killchain.model_validate(payload)
        assert kc.created_processes[0].origin == "scheduler"
        file = kc.dropped_files[0].files[0]
        assert file.path_authority == "future_authority"
        assert file.retention == "future_retention"
        assert file.analysis_status == "future_status"
        assert kc.artifact_inventory_coverage is not None
        assert kc.artifact_inventory_coverage.source_error == "future_error"

    def test_killchain_round_trip(self, sample_killchain: dict[str, Any]) -> None:
        first = Killchain.model_validate(sample_killchain)
        dumped = first.model_dump(by_alias=True)
        assert dumped["droppedFiles"][0]["files"][0]["artifactId"] == "65f0aa000000000000000001"
        assert dumped["createdProcesses"][0]["workDir"] == "C:\\Users\\Public"
        assert Killchain.model_validate(dumped) == first

    def test_killchain_requires_the_process_lists(self, sample_killchain: dict[str, Any]) -> None:
        del sample_killchain["createdProcesses"]
        with pytest.raises(ValidationError):
            Killchain.model_validate(sample_killchain)


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

    def test_cdr_detail_from_an_older_server(self, sample_cdr_response: dict[str, Any]) -> None:
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.sanitized_file_info is not None
        detail = resp.sanitized_file_info.details[0]
        assert detail.count is None
        assert detail.sha256 is None
        assert detail.description is None
        assert detail.file_name is None
        assert detail.details == []

    def test_cdr_nested_details(self, sample_cdr_nested_response: dict[str, Any]) -> None:
        resp = CdrResponse.model_validate(sample_cdr_nested_response)
        assert resp.sanitized_file_info is not None
        [member] = resp.sanitized_file_info.details
        assert member.count == 2
        assert member.sha256 == ["cd" * 32]
        assert member.description == "Inner document"
        assert member.file_name == "invoice.docx"
        [nested] = member.details
        assert isinstance(nested, CdrSanitizedFileInfoDetail)
        assert nested.name == "Macros"
        assert nested.action == "removed"
        assert nested.data == ["AutoOpen"]
        assert nested.details == []

    def test_cdr_detail_keeps_an_unknown_action(self, sample_cdr_response: dict[str, Any]) -> None:
        sample_cdr_response["sanitizedFileInfo"]["details"] = [
            {"name": "macro", "action": "quarantined", "data": None}
        ]
        resp = CdrResponse.model_validate(sample_cdr_response)
        assert resp.sanitized_file_info is not None
        assert resp.sanitized_file_info.details[0].action == "quarantined"


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

    def test_static_scan_from_an_older_server(
        self, sample_static_scan_response: dict[str, Any]
    ) -> None:
        resp = StaticScanResponse.model_validate(sample_static_scan_response)
        assert resp.file_info is not None
        assert resp.file_info.real_filename is None
        assert resp.file_info.real_sha256 is None
        assert resp.one_note_embedded_files is None

    def test_static_scan_nsrl_file_info(
        self, sample_static_scan_onenote_response: dict[str, Any]
    ) -> None:
        resp = StaticScanResponse.model_validate(sample_static_scan_onenote_response)
        assert resp.file_info is not None
        assert resp.file_info.real_filename == "notepad.exe"
        assert resp.file_info.real_sha256 == "d" * 64

    def test_static_scan_onenote_embedded_files(
        self, sample_static_scan_onenote_response: dict[str, Any]
    ) -> None:
        resp = StaticScanResponse.model_validate(sample_static_scan_onenote_response)
        files = resp.one_note_embedded_files
        assert files is not None
        [embedded] = files
        assert isinstance(embedded, StaticScanOneNoteEmbeddedFile)
        assert embedded.artifact_id == "art-9"
        assert embedded.download_link == "/public-api/submissions/uuid-1/download/artifact/art-9"
        assert embedded.display_name == "click_me.exe"
        assert embedded.mime_type == "application/x-dosexec"
        assert embedded.extension == ".exe"
        assert embedded.identity == "{3F5A2B10-6C1D-4E7A-9B8C-0D1E2F3A4B5C}"
        assert embedded.filesize == "204800"
        assert embedded.entropy == 7.42
        assert embedded.last_modified_time == "2024-01-01T00:00:00Z"
        assert embedded.embedded_file_name == "click_me.exe"
        assert embedded.source_filepath == "C:\\Users\\analyst\\Desktop\\click_me.exe"
        assert resp.model_extra is not None
        assert resp.model_extra["oneNoteEmbeddedFiles"][0]["artifactId"] == "art-9"

    def test_static_scan_onenote_embedded_file_without_engine_fields(
        self, sample_static_scan_onenote_response: dict[str, Any]
    ) -> None:
        sample_static_scan_onenote_response["oneNoteEmbeddedFiles"] = [
            {
                "name": "a.exe",
                "size": 1,
                "type": "PE32",
                "md5": "1" * 32,
                "sha1": "2" * 40,
                "sha256": "3" * 64,
                "artifactId": "",
                "downloadLink": "",
                "displayName": "a.exe",
                "mimeType": "application/x-dosexec",
            }
        ]
        resp = StaticScanResponse.model_validate(sample_static_scan_onenote_response)
        files = resp.one_note_embedded_files
        assert files is not None
        assert files[0].extension is None
        assert files[0].entropy is None
        assert files[0].source_filepath is None


class TestStringFactsTypes:
    def test_string_facts_keep_secret_values_in_full(
        self, sample_string_facts: dict[str, Any]
    ) -> None:
        facts = StringFacts.model_validate(sample_string_facts)
        token, ip = facts.observables
        assert isinstance(token, StringObservable)
        raw = sample_string_facts["observables"][0]
        assert token.kind == "bot-token"
        assert token.secret is True
        assert token.value == raw["value"]
        assert token.display == raw["value"]
        assert token.source == raw["source"]
        assert "AAFabcdefghijklmnopqrstuvwxyz012345" in token.display
        assert token.host == "api.telegram.org"
        assert token.detail == "Telegram"
        assert ip.secret is False
        assert ip.detail is None
        [fact] = facts.facts
        assert isinstance(fact, StringFact)
        assert fact.code == "anti-debug"
        assert fact.capability == "anti-analysis"
        assert fact.matches == ["return kernel32.IsDebuggerPresent() != 0"]
        assert fact.names == []
        assert facts.total == 1423
        assert facts.truncated is False

    def test_string_observable_keeps_an_unknown_kind(
        self, sample_string_facts: dict[str, Any]
    ) -> None:
        sample_string_facts["observables"][0]["kind"] = "mutex"
        facts = StringFacts.model_validate(sample_string_facts)
        assert facts.observables[0].kind == "mutex"

    def test_string_facts_empty(self) -> None:
        facts = StringFacts.model_validate(
            {"observables": [], "facts": [], "total": 0, "truncated": False}
        )
        assert facts.observables == []
        assert facts.facts == []

    def test_strings_page(self, sample_strings_page: dict[str, Any]) -> None:
        page = StringsPage.model_validate(sample_strings_page)
        first, second = page.items
        assert isinstance(first, StringItem)
        assert first.value == "IsDebuggerPresent"
        assert first.from_source == "ascii"
        assert first.blacklist is True
        assert first.hint == "anti-debug"
        assert second.hint is None
        assert page.items_count == 1423
        assert page.start == 0
        assert page.end == 2
        assert page.download_link == "/public-api/submissions/uuid-1/static-scan/strings"

    def test_strings_page_requires_the_window(self) -> None:
        with pytest.raises(ValidationError):
            StringsPage.model_validate({"items": []})


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
        assert m.items is None

    def test_mitre_response_items(self, sample_mitre_response_with_items: dict[str, Any]) -> None:
        m = MitreResponse.model_validate(sample_mitre_response_with_items)
        assert m.items is not None
        assert len(m.items) == 2
        assert len(m.items) < len(m.techniques)
        first = m.items[0]
        assert isinstance(first, MitreTechniqueUsage)
        assert first.technique_id == "T1055"
        assert first.name == "Process Injection"
        assert first.tactic_ids == ["TA0004", "TA0005"]
        assert first.score == 85
        assert first.score_maximum == 100
        assert first.in_verdict_chain is True
        assert first.indicator_ids == ["665f1c2e9b1d4a0012ab34cd", "665f1c2e9b1d4a0012ab34ce"]
        assert m.items[1].score == 40.5
        assert m.items[1].in_verdict_chain is False

    def test_mitre_response_empty_items(self) -> None:
        m = MitreResponse.model_validate({"techniques": [], "total": 0, "items": []})
        assert m.items == []

    def test_mitre_item_keeps_an_unknown_score_maximum(
        self, sample_mitre_response_with_items: dict[str, Any]
    ) -> None:
        payload = dict(sample_mitre_response_with_items["items"][0], scoreMaximum=10)
        assert MitreTechniqueUsage.model_validate(payload).score_maximum == 10

    def test_mitre_item_populates_by_name(self) -> None:
        item = MitreTechniqueUsage(
            technique_id="T1055",
            name="Process Injection",
            tactic_ids=["TA0005"],
            score=70,
            score_maximum=100,
            in_verdict_chain=False,
            indicator_ids=[],
        )
        assert item.model_dump(by_alias=True)["techniqueId"] == "T1055"


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


class TestUrlAnalysisParityFields:
    def test_old_server_payload_has_no_job_id(
        self, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        sample_url_analysis_response.pop("jobId", None)
        assert UrlAnalysisResponse.model_validate(sample_url_analysis_response).job_id is None

    def test_job_id(self, sample_url_analysis_response: dict[str, Any]) -> None:
        sample_url_analysis_response["jobId"] = "6650f0a1c2d3e4f5a6b7c8db"
        report = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        assert report.job_id == "6650f0a1c2d3e4f5a6b7c8db"
        assert report.model_dump(by_alias=True)["jobId"] == "6650f0a1c2d3e4f5a6b7c8db"

    def test_a_removed_verdict_key_is_ignored(
        self, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        sample_url_analysis_response["verdictState"] = "final"
        report = UrlAnalysisResponse.model_validate(sample_url_analysis_response)
        assert "verdictState" not in report.model_dump(by_alias=True)

    def test_old_server_session_config_has_no_network_config_fields(
        self, url_analysis_session_payload: dict[str, Any]
    ) -> None:
        session = UrlAnalysisSession.model_validate(url_analysis_session_payload)
        assert session.session_config is not None
        assert session.session_config.network_config_source is None
        assert session.session_config.network_config_name is None

    def test_session_config_network_config_fields(
        self, url_analysis_session_payload: dict[str, Any]
    ) -> None:
        url_analysis_session_payload["sessionConfig"]["networkConfigSource"] = "admin-default"
        url_analysis_session_payload["sessionConfig"]["networkConfigName"] = "Tor exit"
        session = UrlAnalysisSession.model_validate(url_analysis_session_payload)
        assert session.session_config is not None
        assert session.session_config.network_config_source == "admin-default"
        assert session.session_config.network_config_name == "Tor exit"

    def test_session_config_keeps_an_unknown_network_config_source(
        self, url_analysis_session_payload: dict[str, Any]
    ) -> None:
        url_analysis_session_payload["sessionConfig"]["networkConfigSource"] = "workspace-default"
        session = UrlAnalysisSession.model_validate(url_analysis_session_payload)
        assert session.session_config is not None
        assert session.session_config.network_config_source == "workspace-default"


class TestUrlAnalysisIndicatorsTypes:
    def test_available_explanation(self, url_analysis_indicators_payload: dict[str, Any]) -> None:
        result = UrlAnalysisIndicators.model_validate(url_analysis_indicators_payload)
        assert result.state == "available"
        snapshot = result.snapshot
        assert snapshot is not None
        assert snapshot.schema_version == 1
        assert snapshot.pass_ == "final"
        assert snapshot.scored_at == "2026-10-01T09:30:00.000Z"
        assert snapshot.browser_snapshot is not None
        assert snapshot.browser_snapshot.manifest_hash.startswith("9f2c")
        indicator = snapshot.indicators[0]
        assert indicator.rule_id == "whois.domain_age"
        assert indicator.weighted_points == 20
        assert indicator.disposition == "contributing"
        assert indicator.evidence_refs[0].kind == "report"
        assert snapshot.aggregation.reputation_credits[0].eligible is False
        assert snapshot.aggregation.credit_scope == "heuristic"
        assert snapshot.verdict_adjustments[0].from_ == "malicious"
        assert snapshot.verdict_adjustments[0].to == "suspicious"

    def test_unavailable_explanation(self) -> None:
        result = UrlAnalysisIndicators.model_validate(
            {"state": "unavailable", "unavailableReason": "legacy", "snapshot": None}
        )
        assert result.unavailable_reason == "legacy"
        assert result.snapshot is None

    def test_pending_explanation_without_optional_keys(self) -> None:
        result = UrlAnalysisIndicators.model_validate({"state": "pending"})
        assert result.unavailable_reason is None
        assert result.snapshot is None

    def test_unknown_enum_values_are_kept(
        self, url_analysis_indicators_payload: dict[str, Any]
    ) -> None:
        url_analysis_indicators_payload["state"] = "rescoring"
        snapshot = url_analysis_indicators_payload["snapshot"]
        snapshot["pass"] = "replay"
        snapshot["verdict"] = "phishing"
        snapshot["aggregation"]["creditScope"] = "none"
        indicator = snapshot["indicators"][0]
        indicator["availability"] = "partial"
        indicator["confidence"] = "low"
        indicator["disposition"] = "capped"
        indicator["evidenceRefs"][0]["kind"] = "screenshot"
        result = UrlAnalysisIndicators.model_validate(url_analysis_indicators_payload)
        assert result.state == "rescoring"
        assert result.snapshot is not None
        assert result.snapshot.pass_ == "replay"
        assert result.snapshot.verdict == "phishing"
        assert result.snapshot.aggregation.credit_scope == "none"
        parsed = result.snapshot.indicators[0]
        assert (parsed.availability, parsed.confidence, parsed.disposition) == (
            "partial",
            "low",
            "capped",
        )
        assert parsed.evidence_refs[0].kind == "screenshot"

    def test_round_trip_keeps_the_aliases(
        self, url_analysis_indicators_payload: dict[str, Any]
    ) -> None:
        dumped = UrlAnalysisIndicators.model_validate(url_analysis_indicators_payload).model_dump(
            by_alias=True
        )
        assert dumped["snapshot"]["pass"] == "final"
        assert dumped["snapshot"]["verdictAdjustments"][0]["from"] == "malicious"
        assert dumped == url_analysis_indicators_payload

    def test_evidence(self, url_analysis_evidence_payload: dict[str, Any]) -> None:
        evidence = UrlAnalysisIndicatorEvidence.model_validate(url_analysis_evidence_payload)
        assert evidence.state == "available"
        assert evidence.text is not None
        assert evidence.truncated is False

    def test_unavailable_evidence(self) -> None:
        evidence = UrlAnalysisIndicatorEvidence.model_validate(
            {"state": "unavailable", "text": None, "truncated": False}
        )
        assert evidence.text is None

    def test_browser_section(self, url_analysis_browser_section_payload: dict[str, Any]) -> None:
        section = UrlAnalysisBrowserSection.model_validate(url_analysis_browser_section_payload)
        assert section.section == "tls"
        assert section.job_id == "6710a3f2c1d2e3f4a5b6c7d8"
        assert section.updated_at == 1760000000000
        assert section.data["tls"]["protocol"] == "TLS 1.3"

    def test_browser_section_keeps_an_unknown_section_name(
        self, url_analysis_browser_section_payload: dict[str, Any]
    ) -> None:
        url_analysis_browser_section_payload["section"] = "screenshots"
        url_analysis_browser_section_payload["updatedAt"] = None
        section = UrlAnalysisBrowserSection.model_validate(url_analysis_browser_section_payload)
        assert section.section == "screenshots"
        assert section.updated_at is None


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

    def test_user_info_reads_the_ai_quota_and_plan_permissions(
        self, sample_user_info: dict[str, Any]
    ) -> None:
        user = UserInfo.model_validate(sample_user_info)
        limits = user.user_info.limits_count
        assert limits.ai_report_count == 3
        assert limits.ai_report_resets_at is not None
        assert limits.ai_report_resets_at.isoformat() == "2026-10-15T00:00:00+00:00"
        assert user.ai_report_resets_at == limits.ai_report_resets_at
        assert user.plan.submission_limits.ai_report_limit == 20
        permissions = user.plan_permissions
        assert isinstance(permissions, PlanPermissions)
        assert permissions.download_sample is True
        assert permissions.html_report is True
        assert permissions.stix_report is False
        assert permissions.pdf_report is True
        assert permissions.download_report is False
        assert permissions.ai_report is True

    def test_user_info_accepts_an_old_server_payload(
        self, sample_user_info: dict[str, Any]
    ) -> None:
        limits_payload = sample_user_info["userInfo"]["limitsCount"]
        del limits_payload["aiReportCount"]
        del limits_payload["aiReportResetsAt"]
        del sample_user_info["plan"]["submissionLimits"]["aiReportLimit"]
        del sample_user_info["plan"]["permissions"]
        user = UserInfo.model_validate(sample_user_info)
        assert user.user_info.limits_count.ai_report_count is None
        assert user.ai_report_resets_at is None
        assert user.plan.submission_limits.ai_report_limit is None
        assert user.plan_permissions is None

    def test_plan_permissions_accept_a_partial_payload(self) -> None:
        permissions = PlanPermissions.model_validate({"aiReport": False})
        assert permissions.ai_report is False
        assert permissions.download_sample is None

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

    def test_completed_report_reads_the_run_fields(self, sample_ai_report: dict[str, Any]) -> None:
        report = AiReport.model_validate(sample_ai_report)
        assert report.reason == "finalized"
        assert report.error is None
        assert report.analysis_finalized is True

    def test_failed_report_has_only_the_error_code(
        self, sample_ai_report_failed: dict[str, Any]
    ) -> None:
        report = AiReport.model_validate(sample_ai_report_failed)
        assert report.status == "failed"
        assert report.report is None
        assert report.reason == "regenerate"
        assert report.error is not None
        assert report.error.code == "PIPELINE_TIMEOUT"
        assert "message" not in report.error.model_dump(by_alias=True)

    def test_report_from_an_old_server_has_no_run_fields(
        self, sample_ai_report: dict[str, Any]
    ) -> None:
        for key in ("reason", "error", "analysisFinalized"):
            del sample_ai_report[key]
        report = AiReport.model_validate(sample_ai_report)
        assert report.reason is None
        assert report.error is None
        assert report.analysis_finalized is None

    def test_report_keeps_unknown_run_values(self, sample_ai_report_failed: dict[str, Any]) -> None:
        sample_ai_report_failed["reason"] = "scheduled_refresh"
        sample_ai_report_failed["error"] = {"code": "FUTURE_FAILURE"}
        report = AiReport.model_validate(sample_ai_report_failed)
        assert report.reason == "scheduled_refresh"
        assert report.error is not None
        assert report.error.code == "FUTURE_FAILURE"

    def test_ioc_review_without_a_recorded_model_count(
        self, sample_ai_report: dict[str, Any]
    ) -> None:
        sample_ai_report["report"]["iocReview"]["summary"]["reviewedByModel"] = None
        report = AiReport.model_validate(sample_ai_report)
        assert report.report is not None
        assert report.report.ioc_review is not None
        assert report.report.ioc_review.summary is not None
        assert report.report.ioc_review.summary.reviewed_by_model is None

    def test_regenerate_result_is_a_pending_report(
        self, sample_ai_report_regenerate: dict[str, Any]
    ) -> None:
        result = AiReportRegenerateResult.model_validate(sample_ai_report_regenerate)
        assert isinstance(result, AiReportPending)
        assert result.status == "queued"
        assert result.message == "AI report regeneration queued"
        assert result.stage is None

    def test_regenerate_result_keeps_unknown_status(self) -> None:
        result = AiReportRegenerateResult.model_validate({"status": "deduplicated"})
        assert result.status == "deduplicated"
        assert result.message is None

    def test_pending_body_keeps_unknown_values(self) -> None:
        pending = AiReportPending.model_validate({"status": "throttled", "stage": "reviewing"})
        assert pending.status == "throttled"
        assert pending.stage == "reviewing"


class TestProcessIdentityFields:
    def test_old_process_has_no_identity_fields(self, sample_process: dict[str, Any]) -> None:
        p = Process.model_validate(sample_process)
        assert p.pid_gen is None
        assert p.origin is None
        assert p.image is None
        assert p.method is None
        assert p.timestamp is None
        assert p.exit_timestamp is None

    def test_process_reads_the_identity_fields(
        self, sample_windows_v2_process: dict[str, Any]
    ) -> None:
        p = Process.model_validate(sample_windows_v2_process)
        assert p.pid_gen == 4
        assert p.origin == "sample"
        assert p.image == "C:\\Users\\victim\\evil.exe"
        assert p.method == "NtCreateUserProcess"
        assert p.timestamp == 1790376279.55
        assert p.exit_timestamp == 1790376284.1
        dumped = p.model_dump(by_alias=True)
        assert dumped["pidGen"] == 4
        assert dumped["exitTimestamp"] == 1790376284.1

    def test_process_accepts_null_identity_fields(
        self, sample_windows_v2_process: dict[str, Any]
    ) -> None:
        p = Process.model_validate(
            {**sample_windows_v2_process, "pidGen": None, "origin": None, "exitTimestamp": None}
        )
        assert p.pid_gen is None
        assert p.origin is None
        assert p.exit_timestamp is None

    def test_process_keeps_an_unknown_origin(
        self, sample_windows_v2_process: dict[str, Any]
    ) -> None:
        p = Process.model_validate({**sample_windows_v2_process, "origin": "scheduler"})
        assert p.origin == "scheduler"

    def test_old_tree_node_has_no_identity_fields(
        self, sample_process_tree_response: dict[str, Any]
    ) -> None:
        root = ProcessTreeResponse.model_validate(sample_process_tree_response).nodes[0]
        assert root.pid_gen is None
        assert root.origin is None
        assert root.cwd is None

    def test_tree_node_reads_the_identity_fields(self) -> None:
        node = ProcessTreeNode.model_validate(
            {
                "pid": 1508,
                "ppid": 800,
                "pidGen": 2,
                "origin": "shell",
                "tid": 0,
                "name": "cmd.exe",
                "cmd": "cmd.exe",
                "cwd": "C:\\Users\\analyst",
                "children": [],
            }
        )
        assert node.pid_gen == 2
        assert node.origin == "shell"
        assert node.cwd == "C:\\Users\\analyst"


class TestBehaviourIndexTypes:
    def test_old_behaviour_event_has_no_pid_gen_or_subject(
        self, sample_behaviour_event: dict[str, Any]
    ) -> None:
        e = BehaviourEvent.model_validate(sample_behaviour_event)
        assert e.pid_gen is None
        assert e.subject is None

    def test_old_behaviours_response_has_no_index_fields(
        self, sample_behaviours_response: dict[str, Any]
    ) -> None:
        resp = BehavioursResponse.model_validate(sample_behaviours_response)
        assert resp.sorted_by is None
        assert resp.many_processes_match is None

    def test_indexed_behaviours_response(
        self, sample_indexed_behaviours_response: dict[str, Any]
    ) -> None:
        resp = BehavioursResponse.model_validate(sample_indexed_behaviours_response)
        assert resp.sorted_by == "time"
        assert resp.many_processes_match is False
        event = resp.items[0]
        assert event.pid_gen == 0
        assert event.subject == "C:\\evil.dll"

    def test_behaviours_response_keeps_an_unknown_page_order(
        self, sample_indexed_behaviours_response: dict[str, Any]
    ) -> None:
        resp = BehavioursResponse.model_validate(
            {**sample_indexed_behaviours_response, "sortedBy": "processName"}
        )
        assert resp.sorted_by == "processName"

    def test_behaviour_summary(self, sample_behaviour_summary_response: dict[str, Any]) -> None:
        summary = BehaviourSummary.model_validate(sample_behaviour_summary_response)
        assert summary.total_count == 1337
        assert summary.first_timestamp == 1712345678.901
        assert summary.by_type[0].value == "registry"
        assert summary.by_operation[0].count == 42
        process = summary.by_process[0]
        assert process.process_id == 1508
        assert process.process_name == "payload.exe"
        assert process.last_timestamp is None
        assert summary.exits[0].event_id == 2048
        assert summary.exits[0].status is None

    def test_empty_behaviour_summary(self) -> None:
        summary = BehaviourSummary.model_validate(
            {
                "totalCount": 0,
                "firstTimestamp": None,
                "lastTimestamp": None,
                "byType": [],
                "byOperation": [],
                "byProcess": [],
                "exits": [],
            }
        )
        assert summary.total_count == 0
        assert summary.first_timestamp is None

    def test_behaviour_summary_requires_the_counts(self) -> None:
        with pytest.raises(ValidationError):
            BehaviourSummary.model_validate({"totalCount": 1})

    def test_behaviour_facets(self, sample_behaviour_facets_response: dict[str, Any]) -> None:
        facets = BehaviourFacets.model_validate(sample_behaviour_facets_response)
        assert [item.value for item in facets.items] == ["RegSetValue", "WriteFile"]
        assert facets.complete is False
        assert facets.scanned_rows == 250000


class TestSyscallSearchTypes:
    def test_old_syscalls_response_has_no_first_line(
        self, sample_syscalls_response: dict[str, Any]
    ) -> None:
        assert SyscallsResponse.model_validate(sample_syscalls_response).first_line is None

    def test_syscalls_response_reads_the_first_line(
        self, sample_syscalls_response: dict[str, Any]
    ) -> None:
        resp = SyscallsResponse.model_validate({**sample_syscalls_response, "firstLine": 501})
        assert resp.first_line == 501

    def test_syscall_search_result(self, sample_syscall_search_response: dict[str, Any]) -> None:
        result = SyscallSearchResult.model_validate(sample_syscall_search_response)
        assert result.lines[0].line == 3000
        assert result.lines[0].raw.startswith("ntdll!NtCreateFile")
        assert result.next_from_line == 3000
        assert result.scanned_to == 3000
        assert result.total_count == 1500000
        assert result.done is False
        assert result.truncated is False
        assert result.busy is False

    def test_busy_syscall_search_result(self) -> None:
        result = SyscallSearchResult.model_validate(
            {
                "lines": [],
                "nextFromLine": 0,
                "scannedTo": 0,
                "totalCount": None,
                "done": False,
                "truncated": True,
                "busy": True,
            }
        )
        assert result.busy is True
        assert result.total_count is None


class TestNetworkSensorFields:
    def test_older_server_connection_has_no_sensor_fields(
        self, sample_tcp_connection: dict[str, Any]
    ) -> None:
        c = Connection.model_validate(sample_tcp_connection)
        assert c.source_ip is None
        assert c.source_port is None
        assert c.ptr_domain is None
        assert c.app_proto is None
        assert c.hostname is None
        assert c.pkts_to_server is None
        assert c.pkts_to_client is None
        assert c.bytes_to_server is None
        assert c.bytes_to_client is None
        assert c.packets_total is None
        assert c.packets_omitted is None

    def test_connection_reads_the_sensor_fields(
        self, sample_tcp_connection_full: dict[str, Any]
    ) -> None:
        c = Connection.model_validate(sample_tcp_connection_full)
        assert (c.source_ip, c.source_port) == ("192.0.2.86", 49712)
        assert c.domain == "dns.google"
        assert c.ptr_domain == "server-10.hosting.example.net"
        assert c.app_proto == "tls"
        assert c.hostname == "dns.google"
        assert (c.pkts_to_server, c.pkts_to_client) == (14, 11)
        assert (c.bytes_to_server, c.bytes_to_client) == (1832, 6120)
        assert (c.packets_total, c.packets_omitted) == (25, 0)

    def test_older_server_threat_has_no_source_or_level(
        self, sample_network_threat: dict[str, Any]
    ) -> None:
        t = NetworkThreat.model_validate(sample_network_threat)
        assert t.source_ip is None
        assert t.source_port is None
        assert t.severity_level is None

    def test_threat_reads_the_source_and_level(
        self, sample_network_threat_full: dict[str, Any]
    ) -> None:
        t = NetworkThreat.model_validate(sample_network_threat_full)
        assert t.severity_level == 1
        assert (t.source_ip, t.source_port) == ("192.0.2.86", 49712)

    def test_threat_keeps_an_unknown_level(self, sample_network_threat: dict[str, Any]) -> None:
        t = NetworkThreat.model_validate({**sample_network_threat, "severityLevel": 5})
        assert t.severity_level == 5

    def test_older_server_summary_has_no_new_fields(
        self, sample_network_summary: dict[str, Any]
    ) -> None:
        s = NetworkSummary.model_validate(sample_network_summary)
        assert s.https_pcap_available is None
        assert s.has_https_inspection is None
        assert s.unattributed_pcap_available is None
        assert s.attribution_counts is None
        assert s.unattributed_counts is None
        assert s.submission_only_alerts is None

    def test_summary_reads_the_new_fields(
        self, sample_network_summary_full: dict[str, Any]
    ) -> None:
        s = NetworkSummary.model_validate(sample_network_summary_full)
        assert s.https_pcap_available is True
        assert s.has_https_inspection is True
        assert s.unattributed_pcap_available is False
        assert s.attribution_counts is not None
        assert s.attribution_counts.tcp.sample == 30
        assert s.attribution_counts.dns.sample_child == 1
        assert s.attribution_counts.threats.windows_background == 2
        assert s.attribution_counts.udp.sensor_only == 0
        assert s.unattributed_counts is not None
        assert s.unattributed_counts.tcp == 3
        alerts = s.submission_only_alerts
        assert alerts is not None
        assert (alerts.scope, alerts.source, alerts.total, alerts.omitted) == (
            "submission_unattributed",
            "pinned_offline_eve",
            3,
            2,
        )
        [row] = alerts.rows
        assert row.line_number == 812
        assert row.sid == 2034567
        assert row.severity == 1
        assert (row.source_ip, row.destination_ip) == ("192.0.2.86", "192.0.2.10")


class TestNetworkPacketTypes:
    def test_packet_data_decodes_base64(self) -> None:
        data = NetworkPacketData.model_validate({"trimmed": False, "data": "dGVzdA=="})
        assert data.data == b"test"
        assert data.sha256 is None
        assert data.model_dump(mode="json", by_alias=True)["data"] == "dGVzdA=="

    def test_empty_payload_is_empty_bytes(self) -> None:
        assert NetworkPacketData.model_validate({"trimmed": False, "data": ""}).data == b""

    def test_packet_data_rejects_text_that_is_not_base64(self) -> None:
        with pytest.raises(ValidationError):
            NetworkPacketData.model_validate({"trimmed": False, "data": "not base64!"})

    def test_http_request_packets(self, sample_http_request_packets: dict[str, Any]) -> None:
        packets = NetworkHttpPackets.model_validate(sample_http_request_packets)
        [pair] = packets.items
        assert pair.method == "POST"
        assert pair.port_known is True
        assert pair.headers == {"Host": "malware-c2.example.com"}
        assert pair.body is not None
        assert pair.body.data == b"test"
        assert pair.body.sha256 is not None
        assert pair.response is not None
        assert pair.response.status_code == 200
        assert pair.response.body is None
        assert packets.truncated is False
        assert packets.source_scope is None

    def test_sensor_summary_record_has_no_headers_or_bodies(self) -> None:
        packets = NetworkHttpPackets.model_validate(
            {
                "items": [
                    {
                        "timeshift": 1.0,
                        "url": "/",
                        "method": "PROPFIND",
                        "destinationIp": "192.0.2.10",
                        "destinationPort": 0,
                        "portKnown": False,
                        "headers": None,
                        "body": None,
                        "response": None,
                    }
                ],
                "truncated": False,
                "sourceScope": None,
            }
        )
        [pair] = packets.items
        assert pair.method == "PROPFIND"
        assert pair.port_known is False
        assert pair.headers is None
        assert pair.response is None

    def test_connection_packets(self, sample_tcp_connection_packets: dict[str, Any]) -> None:
        packets = NetworkFlowPackets.model_validate(sample_tcp_connection_packets)
        assert packets.protocol == "tcp"
        assert (packets.source_ip, packets.source_port) == ("192.0.2.86", 49712)
        sent, received = packets.items
        assert sent.type == "send"
        assert sent.data is not None
        assert sent.data.data == b"\x16\x03\x01\x00\x01"
        assert sent.data.trimmed is True
        assert received.type == "receive"
        assert received.data is None
        assert packets.truncated is True
        assert packets.source_scope == "sample_attributed"

    def test_connection_packets_keep_an_unknown_direction(
        self, sample_tcp_connection_packets: dict[str, Any]
    ) -> None:
        payload = {
            **sample_tcp_connection_packets,
            "items": [{"type": "both", "data": None}],
        }
        assert NetworkFlowPackets.model_validate(payload).items[0].type == "both"


class TestNetworkEndpointTypes:
    def test_endpoints(self, sample_network_endpoints: dict[str, Any]) -> None:
        endpoints = NetworkEndpoints.model_validate(sample_network_endpoints)
        assert endpoints.total == 42
        assert endpoints.truncated is False
        [endpoint] = endpoints.items
        assert endpoint.key == "malware-c2.example.com"
        assert endpoint.ips == ["192.0.2.10"]
        assert endpoint.ports == [443]
        assert endpoint.source == "sample"
        assert endpoint.request_count == 14
        assert endpoint.alert_count == 1
        assert endpoint.max_alert_severity == "1"
        assert endpoint.process_ids == [1924]
        assert endpoint.attribution_note is None

    def test_endpoint_keyed_by_address(self, sample_network_endpoints: dict[str, Any]) -> None:
        [row] = sample_network_endpoints["items"]
        payload = {
            **sample_network_endpoints,
            "items": [
                {
                    **row,
                    "key": "192.0.2.10",
                    "host": None,
                    "source": "future_source",
                    "firstTimeshift": None,
                    "lastTimeshift": None,
                    "maxAlertSeverity": None,
                    "attributionNote": "Several names resolved to this address",
                }
            ],
        }
        [endpoint] = NetworkEndpoints.model_validate(payload).items
        assert endpoint.host is None
        assert endpoint.source == "future_source"
        assert endpoint.first_timeshift is None
        assert endpoint.attribution_note == "Several names resolved to this address"

    def test_host_flows(self, sample_network_host_flows: dict[str, Any]) -> None:
        page = NetworkHostFlows.model_validate(sample_network_host_flows)
        [flow] = page.flows
        assert flow.protocol == "HTTP"
        assert flow.remote_ip == "192.0.2.10"
        assert flow.local_port is None
        assert flow.bytes_sent is None
        assert flow.methods[0].method == "POST"
        assert flow.methods[0].count == 3
        assert flow.sample_paths == ["http://malware-c2.example.com/gate.php"]
        assert page.totals.http_requests == 3
        assert page.totals.udp_flows == 0
        [alert] = page.alerts
        assert alert.signature == "ET MALWARE Test beacon"
        assert alert.severity == 1
        assert alert.count == 3
        assert alert.first_timeshift == 2.5
        assert page.page_info.end_cursor == "aGYxOjI"
        assert page.page_info.has_next_page is True
        assert page.truncated is False

    def test_older_server_host_flows_have_no_alerts(
        self, sample_network_host_flows: dict[str, Any]
    ) -> None:
        payload = {k: v for k, v in sample_network_host_flows.items() if k != "alerts"}
        assert NetworkHostFlows.model_validate(payload).alerts == []

    def test_host_flows_keep_an_unknown_protocol_and_null_severity(
        self, sample_network_host_flows: dict[str, Any]
    ) -> None:
        [flow] = sample_network_host_flows["flows"]
        [alert] = sample_network_host_flows["alerts"]
        payload = {
            **sample_network_host_flows,
            "flows": [{**flow, "protocol": "QUIC"}],
            "alerts": [{**alert, "severity": None, "firstTimeshift": None}],
            "pageInfo": {"endCursor": None, "hasNextPage": False},
        }
        page = NetworkHostFlows.model_validate(payload)
        assert page.flows[0].protocol == "QUIC"
        assert page.alerts[0].severity is None
        assert page.page_info.end_cursor is None


class TestTotalCountList:
    def test_is_a_plain_list_with_the_total(self) -> None:
        page = TotalCountList([1, 2], total_count=128)
        assert isinstance(page, list)
        assert page == [1, 2]
        assert page.total_count == 128

    def test_total_defaults_to_none(self) -> None:
        assert TotalCountList[int]().total_count is None


class TestVerdictTypes:
    def test_verdict(self, sample_verdict: dict[str, Any]) -> None:
        verdict = Verdict.model_validate(sample_verdict)
        assert verdict.format == "windows-v2-worker-1"
        assert verdict.score == 45
        assert verdict.tier == "Suspicious"
        narrative = verdict.narrative
        assert isinstance(narrative, VerdictNarrative)
        assert narrative.sequence[0].t_offset_s == 1.2
        assert narrative.decisive[0].source == "policy:win.collect.clipboard_policy"
        assert narrative.tier_reason.startswith("Owner policy floor")
        assert narrative.would_raise == ["an upload of the clipboard data"]
        assert narrative.coverage_note is None
        story = verdict.story
        assert isinstance(story, VerdictStory)
        assert story.truncated is False
        assert story.headline is not None
        assert story.headline.parts[0].type == "process"
        step = story.steps[0]
        assert isinstance(step, VerdictStoryStep)
        assert (step.process.image, step.process.pid) == ("invoice.exe", 1924)
        assert step.category == "network"
        assert step.evidence_seqs == [12, 13]
        assert step.key is True
        assert step.reason is None

    def test_legacy_verdict_is_all_none(self, sample_verdict_legacy: dict[str, Any]) -> None:
        verdict = Verdict.model_validate(sample_verdict_legacy)
        assert verdict.model_dump() == {
            "format": None,
            "score": None,
            "tier": None,
            "summary": None,
            "narrative": None,
            "story": None,
        }

    def test_older_server_without_fields(self) -> None:
        verdict = Verdict.model_validate({})
        assert verdict.tier is None

    def test_step_without_optional_fields(self, sample_verdict: dict[str, Any]) -> None:
        step = dict(sample_verdict["story"]["steps"][0])
        for key in ("key", "parts", "command"):
            del step[key]
        parsed = VerdictStoryStep.model_validate(step)
        assert parsed.key is None
        assert parsed.parts is None
        assert parsed.command is None

    def test_unknown_enum_values_are_kept(self, sample_verdict: dict[str, Any]) -> None:
        payload = dict(sample_verdict)
        payload["tier"] = "Critical"
        story = dict(payload["story"])
        step = dict(story["steps"][0])
        step["category"] = "exfiltration"
        step["parts"] = [{"type": "registry_key", "value": "HKCU\\Run"}]
        story["steps"] = [step]
        payload["story"] = story
        verdict = Verdict.model_validate(payload)
        assert verdict.tier == "Critical"
        assert verdict.story is not None
        assert verdict.story.steps[0].category == "exfiltration"
        parts = verdict.story.steps[0].parts
        assert parts is not None
        assert parts[0].type == "registry_key"


class TestRunNotesTypes:
    def test_run_notes(self, sample_run_notes: dict[str, Any]) -> None:
        notes = RunNotes.model_validate(sample_run_notes)
        java = notes.java_output
        assert isinstance(java, RunJavaOutput)
        assert "123456:AAH-secret-value" in java.text
        assert java.size == 120
        assert java.truncated is False
        cut_short = notes.analysis_cut_short
        assert cut_short is not None
        assert cut_short.basis == "unfinished_download"
        assert cut_short.ended_at_s == 540
        assert cut_short.transfer is not None
        assert cut_short.transfer.declared_bytes == 4194304
        assert notes.network_notes == ["The sandbox network refused 3 outgoing mail connections."]
        assert notes.submission_hints == []
        assert isinstance(notes.run_notes[0], RunNote)
        assert notes.run_notes[0].code == "sample_exited_early"
        assert notes.is_dump_collector_activated is True

    def test_legacy_run_notes(self, sample_run_notes_legacy: dict[str, Any]) -> None:
        notes = RunNotes.model_validate(sample_run_notes_legacy)
        assert notes.java_output is None
        assert notes.analysis_cut_short is None
        assert notes.run_notes == []
        assert notes.is_dump_collector_activated is False

    def test_unknown_basis_is_kept(self, sample_run_notes: dict[str, Any]) -> None:
        payload = dict(sample_run_notes)
        payload["analysisCutShort"] = {
            **payload["analysisCutShort"],
            "basis": "vm_crashed",
            "transfer": None,
        }
        notes = RunNotes.model_validate(payload)
        assert notes.analysis_cut_short is not None
        assert notes.analysis_cut_short.basis == "vm_crashed"
        assert notes.analysis_cut_short.transfer is None


class TestAnnotationTypes:
    def test_annotations(self, sample_annotations: dict[str, Any]) -> None:
        annotations = Annotations.model_validate(sample_annotations)
        assert annotations.submission_uuid == "a1b2c3d4-e5f6-4789-abcd-ef1234567890"
        pin = annotations.pins[0]
        assert isinstance(pin, AnnotationPin)
        assert (pin.kind, pin.ref, pin.label) == ("process", "process:pid-4120", "payload.exe")
        assert pin.created_by == "64a000000000000000000001"
        assert pin.created_at.year == 2026
        note = annotations.note
        assert isinstance(note, AnnotationNote)
        assert note.text == "The sample drops a second stage."

    def test_empty_annotations(self) -> None:
        annotations = Annotations.model_validate(
            {"submissionUuid": "a1b2c3d4-e5f6-4789-abcd-ef1234567890", "pins": [], "note": None}
        )
        assert annotations.pins == []
        assert annotations.note is None

    def test_unknown_pin_kind_is_kept(self, sample_annotations: dict[str, Any]) -> None:
        payload = dict(sample_annotations)
        payload["pins"] = [{**payload["pins"][0], "kind": "screenshot"}]
        annotations = Annotations.model_validate(payload)
        assert annotations.pins[0].kind == "screenshot"

    def test_round_trip_uses_api_names(self, sample_annotations: dict[str, Any]) -> None:
        dumped = Annotations.model_validate(sample_annotations).model_dump(
            mode="json", by_alias=True
        )
        assert set(dumped) == {"submissionUuid", "pins", "note"}
        assert set(dumped["pins"][0]) == {"id", "kind", "ref", "label", "createdBy", "createdAt"}


class TestRunCompareTypes:
    def test_run_comparison(self, sample_run_comparison: dict[str, Any]) -> None:
        comparison = RunComparison.model_validate(sample_run_comparison)
        assert comparison.other_submission_uuid == "b1b2c3d4-e5f6-4789-abcd-ef1234567891"
        assert isinstance(comparison.detections.added[0], CompareDetection)
        assert comparison.detections.removed[0].level == "suspicious"
        assert comparison.techniques.added == ["T1059"]
        assert comparison.techniques.removed_total == 1
        assert isinstance(comparison.iocs.added[0], CompareIoc)
        assert comparison.iocs.added[0].category == "ip"
        dropped = comparison.dropped_files
        assert isinstance(dropped.added[0], CompareDroppedFile)
        assert dropped.added[1].sha256 is None
        assert (dropped.added_total, dropped.removed_total) == (2, 0)

    def test_previous_run(self) -> None:
        assert PreviousRun.model_validate({"previousRunUuid": "b1"}).previous_run_uuid == "b1"
        assert PreviousRun.model_validate({"previousRunUuid": None}).previous_run_uuid is None
        assert PreviousRun.model_validate({}).previous_run_uuid is None


class TestAnnotationErrorCodes:
    @pytest.mark.parametrize(
        "code",
        ["ANNOTATION_PIN_LIMIT_REACHED", "ANNOTATION_PIN_NOT_FOUND", "NOT_FOUND", "FORBIDDEN"],
    )
    def test_codes_are_known(self, code: str) -> None:
        err = ApiError.model_validate(
            {"status_code": 400, "error": "Bad Request", "message": "m", "code": code}
        )
        assert err.code == code
