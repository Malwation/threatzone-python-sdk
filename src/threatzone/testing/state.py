"""Submission state machine for the in-process fake Threat.Zone API.

Holds the per-submission state that the fake API mutates as the SDK polls it.
The fake builds Pydantic responses on demand from this state, so the wire
contract automatically tracks the SDK types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

SubmissionKind = Literal["file", "url"]
ThreatLevelStr = Literal["unknown", "benign", "suspicious", "malicious"]
StatusStr = Literal["accepted", "in_progress", "completed"]


@dataclass
class IndicatorSeed:
    """Seed data for a single behavioural indicator."""

    attack_code: str
    level: Literal["malicious", "suspicious", "benign"]
    pids: list[int]


@dataclass
class NetworkThreatSeed:
    """Seed data for a single Suricata network alert."""

    signature: str
    severity: Literal["high", "low"]
    app_proto: Literal["HTTP", "TLS", "DNS"]


@dataclass
class YaraRuleSeed:
    """Seed data for a single matched YARA rule."""

    rule: str
    category: Literal["malicious", "suspicious", "benign"]


@dataclass
class IocSeed:
    """Seed data for a single IoC."""

    type: str
    value: str


@dataclass
class SubmissionState:
    """Mutable per-submission state owned by the fake."""

    uuid: str
    sha256: str
    type: SubmissionKind
    filename: str
    level: ThreatLevelStr
    polls_seen: int = 0
    advance_after_polls: int = 2
    private: bool = False
    owning_workspace: str = "test-workspace"
    indicators: list[IndicatorSeed] = field(default_factory=list)
    network_threats: list[NetworkThreatSeed] = field(default_factory=list)
    yara_rules: list[YaraRuleSeed] = field(default_factory=list)
    iocs: list[IocSeed] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    has_static_report: bool = False
    has_cdr_report: bool = False
    has_dynamic_report: bool = True
    has_url_analysis_report: bool = False
    report_status_overrides: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    final_url: str | None = None
    screenshot_available: bool = True
    threat_analysis_summary: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    artifact_ids: list[str] = field(default_factory=list)
    media_ids: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def current_status(self) -> StatusStr:
        """Derive the overall status from poll count + advance_after_polls."""
        if self.polls_seen == 0:
            return "accepted"
        if self.polls_seen >= self.advance_after_polls:
            return "completed"
        return "in_progress"

    def bump_poll(self) -> None:
        """Advance the poll counter and refresh the updated-at timestamp."""
        self.polls_seen += 1
        self.updated_at = datetime.now(timezone.utc)

    def report_types(self) -> list[str]:
        """Return the list of report types this submission supports."""
        types: list[str] = []
        if self.type == "url":
            if self.has_url_analysis_report:
                types.append("url_analysis")
        else:
            if self.has_dynamic_report:
                types.append("dynamic")
            if self.has_static_report:
                types.append("static")
            if self.has_cdr_report:
                types.append("cdr")
        return types

    def available_reports(self) -> list[str]:
        """Return the report types currently in a completed state.

        Mirrors the `details.availableReports` field on report-unavailable
        409 errors emitted by the real public API.
        """
        status = self.current_status()
        if status != "completed":
            return []
        return self.report_types()

    def report_status_for(self, report_type: str) -> str:
        """Return the per-report status for the given report type."""
        if report_type in self.report_status_overrides:
            return self.report_status_overrides[report_type]
        return self.current_status()
