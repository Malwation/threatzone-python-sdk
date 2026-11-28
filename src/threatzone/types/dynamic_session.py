"""Live sandbox view type definitions.

Mirrors the ``dynamic-session.response.dto.ts`` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DynamicSessionState = Literal["running", "unavailable"] | str
"""``running`` while the dynamic report is ``in_progress`` and the sandbox VM of the run is
live, ``unavailable`` before the VM starts and after the run ends. A newer server can send
another value."""


class DynamicSession(BaseModel):
    """State of the live VNC view of the sandbox VM that runs a file submission."""

    model_config = ConfigDict(populate_by_name=True)

    state: DynamicSessionState
    vnc_available: bool = Field(alias="vncAvailable")
    """``True`` when the live view of the VM is up. It does not depend on the caller: a caller
    without access to the view gets ``True`` with ``link`` ``None``."""
    link: str | None = None
    """``wss://`` URL of the live VNC view (RFB over WebSocket). The token in it is a random
    secret for this run, so treat the link as a credential: anyone who has it can open the VM
    while the run is in progress. Only the user who submitted the file and the admins of its
    workspace get it. ``None`` for every other caller and when ``state`` is ``unavailable``."""
    expires_at: int | None = Field(default=None, alias="expiresAt")
    """Unix milliseconds when the analysis ends and the VM stops. Extend Time and Human
    Simulation can move it later. ``None`` when the end time is not recorded."""
