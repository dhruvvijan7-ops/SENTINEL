"""Typed detector configuration models.

A ``DetectorConfigSchema`` describes the parameters a detector accepts,
their types, ranges, and defaults. It is the single source of truth for
*what* a detector can be configured with. Default values live in
``configuration.defaults``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ConfigParameter:
    """A single typed, validated configuration parameter."""

    name: str
    default: Any
    value_type: type
    description: str = ""
    min_value: Any | None = None
    max_value: Any | None = None
    required: bool = True


@dataclass(frozen=True)
class DetectorConfigSchema:
    """Typed configuration schema for one detector.

    ``defaults()`` returns the authoritative default values for every
    parameter, used by configuration.defaults and by validation when a
    parameter is absent.
    """

    detector_id: str
    parameters: tuple[ConfigParameter, ...] = field(default_factory=tuple)

    def defaults(self) -> dict[str, Any]:
        return {p.name: p.default for p in self.parameters}

    def parameter_names(self) -> set[str]:
        return {p.name for p in self.parameters}

    def get_parameter(self, name: str) -> ConfigParameter | None:
        for p in self.parameters:
            if p.name == name:
                return p
        return None
