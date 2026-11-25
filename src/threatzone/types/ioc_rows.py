"""IoC row type definitions shared by ``/iocs`` and ``/network/endpoints``.

Mirrors the `ioc-row.dto.ts` DTO and the IoC row fields of `indicators.response.dto.ts` and
`network-endpoints.response.dto.ts` in the Threat.Zone Public API. Every literal also accepts
any other string, so a new server value does not fail the parse.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

IoCSource = Literal["network", "file", "host", "config", "url_analysis", "static"] | str
"""Source of the evidence for a value."""

IoCState = (
    Literal[
        "contacted",
        "attempted",
        "looked_up",
        "resolved_only",
        "configured",
        "static",
        "submitted",
        "ran",
        "written",
        "downloaded",
        "created",
    ]
    | str
)
"""How the analysis saw a value."""

IoCBinding = Literal["exact", "actor", "inferred"] | str
"""How the network evidence ties a value to the sample."""

IoCGrade = Literal["high", "medium", "low"] | str
"""How much a value is worth reviewing. On ``/network/endpoints`` it is the host priority."""

IoCLabel = (
    Literal[
        "shared_infrastructure",
        "known_component",
        "partial_capture",
        "unattributed",
        "dead_drop_text",
        "package_file",
    ]
    | str
)
"""Why a value is not graded."""

IoCInfraCategory = (
    Literal[
        "certificate",
        "os_service",
        "telemetry",
        "public_dns",
        "cdn",
        "ip_lookup",
        "file_sharing",
        "tenant_hosting",
        "package_repository",
        "mail_provider",
        "reference",
    ]
    | str
)
"""The kind of shared infrastructure of a ``shared_infrastructure`` value."""

IoCNotExportedReason = (
    Literal[
        "strings",
        "shared_infrastructure",
        "known_component",
        "partial_capture",
        "unattributed",
        "dead_drop_text",
        "package_file",
        "type_not_exported",
        "recipient_list",
        "target_list",
        "not_stored",
        "third_party_text",
        "not_public_host",
    ]
    | str
)
"""Why a value is not in the IoC exports."""

IoCReasonCode = (
    Literal[
        "config_c2",
        "dead_drop_server",
        "config_hash",
        "detection",
        "yara",
        "alert",
        "contacted",
        "beacon",
        "injected_process",
        "config_value",
        "file_ran",
        "file_downloaded",
        "file_written",
        "host_created",
        "static_string",
        "static_in_rated_file",
        "submitted_file",
        "host_grade",
        "host_port",
        "refused_mail",
        "mx_lookup",
        "crash_reporter",
        "dependency_install",
        "carrier",
        "victim_list",
        "shared_hosting",
        "label_shared_infrastructure",
        "label_known_component",
        "label_partial_capture",
        "label_unattributed",
        "label_dead_drop_text",
        "label_package_file",
        "not_seen_in_run",
        "not_run",
        "abusable_service",
        "nxdomain",
        "no_signal",
    ]
    | str
)
"""Machine code of an IoC reason. The API guide (``iocs.md``) documents each code."""

IoCReasonEffect = Literal["raises", "lowers", "note"] | str
"""``raises`` for evidence that raises the grade, ``lowers`` for context that caps it or a
label, ``note`` for a note with no effect on the grade."""


class IoCReason(BaseModel):
    """Why a value or a host has its grade."""

    model_config = ConfigDict(populate_by_name=True)

    code: IoCReasonCode
    """Read this code instead of parsing ``text``."""
    text: str | None = None
    """The sentence the report shows. ``None`` when the sentence needs a fact the run did not
    record, such as the process that wrote a file."""
    effect: IoCReasonEffect
