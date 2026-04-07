"""Configuration type definitions."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class MetafieldOptionValue(BaseModel):
    """A metafield option value (for select-type metafields)."""

    model_config = ConfigDict(populate_by_name=True)

    value: bool | int | str
    label: str


class MetafieldOption(BaseModel):
    """A metafield configuration option."""

    model_config = ConfigDict(populate_by_name=True)

    key: str
    label: str
    description: str
    type: Literal["boolean", "number", "string", "select"]
    default: bool | int | str
    options: list[MetafieldOptionValue] | None = None


class Metafields(BaseModel):
    """Metafields grouped by scan type."""

    model_config = ConfigDict(populate_by_name=True)

    sandbox: list[MetafieldOption]
    static: list[MetafieldOption]
    cdr: list[MetafieldOption]
    url: list[MetafieldOption]
    open_in_browser: list[MetafieldOption]


class EnvironmentOption(BaseModel):
    """An available operating system environment."""

    model_config = ConfigDict(populate_by_name=True)

    key: str
    name: str
    platform: Literal["windows", "linux", "macos", "android"]
    default: bool
