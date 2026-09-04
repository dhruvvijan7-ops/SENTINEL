"""IOC (Indicator of Compromise) data model.

An IOC is typed, normalized, and carries provenance (source, confidence,
description). IOC confidence is DISTINCT from detection confidence.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class IOCType(str, enum.Enum):
    """Supported IOC categories."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    PROCESS = "process"


@dataclass(frozen=True)
class IOC:
    """A single indicator of compromise.

    ``value`` is the raw value; ``normalized_value`` is produced by the
    normalizer and is what the matcher indexes on.
    """

    type: IOCType
    value: str
    normalized_value: str | None = None
    source: str = "internal"
    confidence: float | None = None
    description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "source": self.source,
            "confidence": self.confidence,
            "description": self.description,
            "enabled": self.enabled,
        }
