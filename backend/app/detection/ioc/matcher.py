"""Efficient IOC matcher.

Indexes enabled IOCs by ``(ioc_type, normalized_value)`` so per-event lookup is
O(1) rather than O(number of IOCs). Returns explainable match information.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from app.detection.ioc.models import IOC, IOCType


@dataclass(frozen=True)
class IOCMatch:
    """A single IOC match result."""

    ioc: IOC
    normalized_value: str
    matched_field: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc.type.value,
            "ioc_value": self.ioc.value,
            "normalized_value": self.normalized_value,
            "matched_field": self.matched_field,
            "source": self.ioc.source,
            "ioc_confidence": self.ioc.confidence,
            "description": self.ioc.description,
        }


class IOCMatcher:
    """Indexed matcher over a set of IOCs."""

    def __init__(self, iocs: Iterable[IOC] = ()) -> None:
        self._index: dict[tuple[IOCType, str], list[IOC]] = {}
        for ioc in iocs:
            self.add(ioc)

    def add(self, ioc: IOC) -> None:
        if not ioc.enabled:
            return
        norm = ioc.normalized_value
        if norm is None:
            return
        self._index.setdefault((ioc.type, norm), []).append(ioc)

    def lookup(self, ioc_type: IOCType, normalized_value: str) -> list[IOC]:
        return list(self._index.get((ioc_type, normalized_value), []))

    def match_field(
        self,
        ioc_type: IOCType,
        candidate: str | None,
        field_name: str,
    ) -> list[IOCMatch]:
        """Return matches for a single raw event field value."""
        if not candidate:
            return []
        normalized = _best_effort_normalize(ioc_type, candidate)
        if normalized is None:
            return []
        matched = self.lookup(ioc_type, normalized)
        return [
            IOCMatch(ioc=ioc, normalized_value=normalized, matched_field=field_name)
            for ioc in matched
        ]

    def __len__(self) -> int:
        return sum(len(v) for v in self._index.values())


def _best_effort_normalize(ioc_type: IOCType, candidate: str) -> str | None:
    from app.detection.ioc.normalize import IOCNormalizationError, normalize_ioc

    try:
        return normalize_ioc(ioc_type, candidate)
    except IOCNormalizationError:
        return None
