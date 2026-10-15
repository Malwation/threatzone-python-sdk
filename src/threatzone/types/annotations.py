"""Submission annotation type definitions.

Mirrors the `annotations.response.dto.ts` DTO in the Threat.Zone Public API. Pins and the note
belong to the workspace of the API token. A caller never reads or changes the annotations of
another workspace.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AnnotationPinKind = (
    Literal[
        "finding",
        "finding-group",
        "process",
        "endpoint",
        "technique",
        "tactic",
        "events",
        "moment",
        "syscalls",
        "file",
        "indicator",
        "artifacts",
        "mail-attachment",
        "mail-link",
        "view",
        "preview",
        "family",
    ]
    | str
)
"""Kind of the pinned evidence. A newer server can send another value."""


class AnnotationPin(BaseModel):
    """An evidence pin of the caller workspace."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    """Pin ID (UUID v4). Pass it to ``unpin_evidence()``."""
    kind: AnnotationPinKind
    ref: str
    """The value that identifies the evidence in the report. The web UI can open the evidence
    only when ``ref`` uses the web UI format, for example ``technique:T1055``."""
    label: str
    created_by: str = Field(alias="createdBy")
    """ID of the user who added the pin."""
    created_at: datetime = Field(alias="createdAt")


class AnnotationNote(BaseModel):
    """The note of the caller workspace."""

    model_config = ConfigDict(populate_by_name=True)

    text: str
    updated_by: str = Field(alias="updatedBy")
    """ID of the user who saved the note last."""
    updated_at: datetime = Field(alias="updatedAt")


class Annotations(BaseModel):
    """The evidence pins and the note that the caller workspace keeps on a submission."""

    model_config = ConfigDict(populate_by_name=True)

    submission_uuid: str = Field(alias="submissionUuid")
    pins: list[AnnotationPin]
    """The pins of the caller workspace, in the order they were added."""
    note: AnnotationNote | None = None
    """``None`` when the caller workspace has no note."""
