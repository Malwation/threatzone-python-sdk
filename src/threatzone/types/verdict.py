"""Dynamic verdict and run note type definitions.

Mirrors the `verdict.response.dto.ts` and `run.response.dto.ts` DTOs in the Threat.Zone
Public API. The framework writes every text field. The text can change between releases:
show it to people, do not parse it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

VerdictTier = Literal["Malicious", "Suspicious", "Benign", "Not Measured"] | str
"""Tier of the Windows V2 verdict. A newer server can send another value."""

VerdictStoryCategory = (
    Literal[
        "execution",
        "persistence",
        "network",
        "credential",
        "evasion",
        "injection",
        "file",
        "registry",
        "discovery",
        "other",
    ]
    | str
)
"""Category of a story step. A newer server can send another value."""

VerdictStoryPartType = Literal["text", "process", "path", "api", "constant"] | str
"""Type of a typed text segment. A newer server can send another value."""

RunCutShortBasis = Literal["monitor_stopped", "unfinished_download", "manual_stop"] | str
"""Why the analysis did not see the sample finish. A newer server can send another value."""


class VerdictSequenceEntry(BaseModel):
    """An observed action that led to the verdict."""

    model_config = ConfigDict(populate_by_name=True)

    seq: int | None = None
    """Framework evidence sequence number of the action."""
    t_offset_s: float | None = Field(default=None, alias="tOffsetS")
    """Seconds from the sample start."""
    pid: int | None = None
    image: str | None = None
    text: str


class VerdictDecisive(BaseModel):
    """An indicator row that decided the tier."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    """Source of the indicator row, for example ``policy:win.collect.clipboard_policy``."""
    text: str


class VerdictNarrative(BaseModel):
    """Analyst explanation of a schema 2.1 verdict."""

    model_config = ConfigDict(populate_by_name=True)

    headline: str
    sequence: list[VerdictSequenceEntry]
    """The observed actions that led to the verdict, in order."""
    decisive: list[VerdictDecisive]
    tier_reason: str = Field(alias="tierReason")
    not_observed: list[str] = Field(alias="notObserved")
    """Behaviour the analysis looked for and did not see."""
    would_raise: list[str] = Field(alias="wouldRaise")
    would_lower: list[str] = Field(alias="wouldLower")
    coverage_note: str | None = Field(default=None, alias="coverageNote")
    """A note about what the sensors did not cover. ``None`` when coverage was complete."""
    text: str
    """The full narrative as one text."""


class VerdictStoryPart(BaseModel):
    """A typed segment of a story text."""

    model_config = ConfigDict(populate_by_name=True)

    type: VerdictStoryPartType
    value: str


class VerdictStoryHeadline(BaseModel):
    """The headline of the story."""

    model_config = ConfigDict(populate_by_name=True)

    text: str
    parts: list[VerdictStoryPart]
    """``text`` split into typed segments."""
    detail: str | None = None


class VerdictStoryProcess(BaseModel):
    """The process of a story step."""

    model_config = ConfigDict(populate_by_name=True)

    image: str
    pid: int


class VerdictStoryStep(BaseModel):
    """One step of the story, in order."""

    model_config = ConfigDict(populate_by_name=True)

    t_offset_s: float = Field(alias="tOffsetS")
    """Seconds from the sample start."""
    process: VerdictStoryProcess
    category: VerdictStoryCategory
    text: str
    count: int
    """The number of times the behaviour repeated in this step."""
    evidence_seqs: list[int] = Field(alias="evidenceSeqs")
    """Framework evidence sequence numbers that support the step."""
    key: bool | None = None
    """``True`` when the step is one of the summary lines. ``None`` when the framework did not
    write it."""
    parts: list[VerdictStoryPart] | None = None
    """``text`` split into typed segments. ``None`` when the framework did not write them."""
    command: str | None = None
    """The full command line, not shortened."""
    reason: str | None = None
    caveat: str | None = None


class VerdictStory(BaseModel):
    """The ordered account of what the sample did."""

    model_config = ConfigDict(populate_by_name=True)

    summary: list[str]
    truncated: bool
    """``True`` when the framework shortened the story."""
    steps: list[VerdictStoryStep]
    headline: VerdictStoryHeadline | None = None
    """``None`` on stories from before the typed segments."""


class Verdict(BaseModel):
    """Dynamic verdict of a Windows V2 report with its narrative and story.

    Every field is ``None`` for a legacy report, and for a stored verdict that does not belong
    to the committed analysis attempt.
    """

    model_config = ConfigDict(populate_by_name=True)

    format: str | None = None
    """Report format of the verdict, for example ``windows-v2-worker-1``."""
    score: float | None = None
    """Dynamic verdict score from 0 to 100."""
    tier: VerdictTier | None = None
    """Older reports stored ``Informative``; the API returns ``Benign`` for them."""
    summary: str | None = None
    """Verdict summary. ``None`` on reports older than schema 2.1."""
    narrative: VerdictNarrative | None = None
    """``None`` on reports older than schema 2.1."""
    story: VerdictStory | None = None
    """``None`` on older reports and on runs that were not measured."""


class RunJavaOutput(BaseModel):
    """What a JAR sample wrote to its Java console."""

    model_config = ConfigDict(populate_by_name=True)

    summary: str
    error: str | None = None
    """The uncaught exception, when the program stopped with one."""
    cause: str | None = None
    """The last cause of that exception."""
    text: str
    """The full stored console text. The sandbox worker stores only the start of a long
    output; ``truncated`` tells if it did."""
    size: int
    """The number of bytes the program wrote."""
    truncated: bool


class RunUnfinishedTransfer(BaseModel):
    """A download that was still running when the analysis ended."""

    model_config = ConfigDict(populate_by_name=True)

    url: str
    """Host and path of the download."""
    received_bytes: int = Field(alias="receivedBytes")
    declared_bytes: int = Field(alias="declaredBytes")


class RunAnalysisCutShort(BaseModel):
    """The framework is certain that the analysis did not see the sample finish."""

    model_config = ConfigDict(populate_by_name=True)

    basis: RunCutShortBasis
    """Show ``text``, not this code."""
    ended_at_s: float = Field(alias="endedAtS")
    """Seconds into the run when observation ended."""
    requested_window_s: float = Field(alias="requestedWindowS")
    """The requested window in seconds, extensions included."""
    text: str
    transfer: RunUnfinishedTransfer | None = None
    """Set only for the ``unfinished_download`` basis."""


class RunNote(BaseModel):
    """A framework sentence with a stable code."""

    model_config = ConfigDict(populate_by_name=True)

    code: str
    """A stable snake_case code, for example ``sample_exited_early``. New codes can appear;
    show ``text``, not this code."""
    text: str


class RunNotes(BaseModel):
    """The facts that a Windows V2 analysis states about its run.

    For a legacy report, ``java_output`` and ``analysis_cut_short`` are ``None`` and the lists
    are empty. The API returns every value in full. It does not mask secrets that the sample
    wrote.
    """

    model_config = ConfigDict(populate_by_name=True)

    java_output: RunJavaOutput | None = Field(default=None, alias="javaOutput")
    """``None`` when the run wrote no Java output."""
    analysis_cut_short: RunAnalysisCutShort | None = Field(default=None, alias="analysisCutShort")
    network_notes: list[str] = Field(alias="networkNotes")
    """The framework sentences about the sandbox network, for example refused outgoing mail."""
    submission_hints: list[RunNote] = Field(alias="submissionHints")
    """Advice on what to submit instead when the sample did not run."""
    run_notes: list[RunNote] = Field(alias="runNotes")
    """Notes on how the run went, for example that the sample exited early."""
    is_dump_collector_activated: bool = Field(alias="isDumpCollectorActivated")
    """``True`` when the submission turned on the ``dump_collector`` metafield. It applies to
    legacy reports too."""
