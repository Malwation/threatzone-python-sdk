"""Network configuration type definitions.

Mirrors the `network-configs.response.dto.ts` DTO in the Threat.Zone Public API.
Secrets (passwords, VPN config file contents) are never part of this contract —
only `has_config_file` indicates whether a file has been uploaded.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class NetworkConfigListItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: str
    name: str
    type: str
    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    has_config_file: bool = Field(alias="hasConfigFile")
    created_at: str = Field(alias="createdAt")
    updated_at: str = Field(alias="updatedAt")


class NetworkConfigListResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    items: list[NetworkConfigListItem] = Field(default_factory=list)
