"""Ordered predicate-sequence matching.

Given an ordered list of canonical events and a :class:`SequenceDefinition`,
finds non-overlapping occurrences of the pattern while preserving order and
(optionally) a time window.

Complexity: a single left-to-right greedy pass over the events is O(n * k) where
k is the pattern length — near-linear, never naive O(n²) pair-wise scanning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from app.detection.sequence.models import SequenceDefinition


@dataclass(frozen=True)
class SequenceMatch:
    """A concrete ordered-pattern match."""

    definition: SequenceDefinition
    matched_indexes: tuple[int, ...] = field(default_factory=tuple)
    ordering_basis: str = "event_index"
    temporal_constraint_applied: bool = False
    start_timestamp: datetime | None = None
    end_timestamp: datetime | None = None
    span_seconds: float | None = None

    def to_dict(self) -> dict:
        return {
            "sequence_id": self.definition.id,
            "sequence_name": self.definition.name,
            "matched_event_indexes": list(self.matched_indexes),
            "ordering_basis": self.ordering_basis,
            "temporal_constraint_applied": self.temporal_constraint_applied,
            "start_timestamp": self.start_timestamp.isoformat() if self.start_timestamp else None,
            "end_timestamp": self.end_timestamp.isoformat() if self.end_timestamp else None,
            "span_seconds": self.span_seconds,
        }


def _event_order_key(event, fallback: Sequence, index: int) -> tuple:
    """Deterministic ordering basis: event_index attribute, else input position."""
    ordering = getattr(event, "attributes", None) or {}
    ei = ordering.get("event_index")
    si = ordering.get("sequence_index")
    if ei is not None and si is not None:
        return (int(si), int(ei))
    if ei is not None:
        return (0, int(ei))
    return (0, index)


def find_matches(
    events: Sequence,
    definition: SequenceDefinition,
    *,
    max_matches: int = 50,
) -> list[SequenceMatch]:
    """Find non-overlapping ordered matches of ``definition`` in ``events``.

    The ``definition.time_window_seconds`` is enforced only when every matched
    event carries a real timestamp; otherwise ordering-only matching is used and
    ``temporal_constraint_applied`` is reported as False.
    """
    if not definition.predicates:
        return []
    ordered = list(events)
    if not ordered:
        return []

    pattern = definition.predicates
    n = len(pattern)
    m = len(ordered)
    results: list[SequenceMatch] = []

    i = 0
    while i < m:
        if not pattern[0].matches(ordered[i]):
            i += 1
            continue
        # Try to complete the pattern starting from i with a greedy forward pass.
        match_idx = [i]
        cursor = i + 1
        step = 1
        while step < n and cursor < m:
            if pattern[step].matches(ordered[cursor]):
                match_idx.append(cursor)
                cursor += 1
                step += 1
            else:
                cursor += 1
        if step == n:
            results.append(_build_match(ordered, definition, match_idx))
            if len(results) >= max_matches:
                break
            i = match_idx[0] + 1
        else:
            i += 1

    return results


def _build_match(
    ordered: Sequence,
    definition: SequenceDefinition,
    match_idx: list[int],
) -> SequenceMatch:
    matched = [ordered[idx] for idx in match_idx]

    # Determine honest ordering basis: "timestamp" if every matched event has a
    # real timestamp, otherwise "event_index" (ordering-only, no fabricated time).
    timestamps = [ev.timestamp for ev in matched if ev.timestamp is not None]
    basis = "timestamp" if len(timestamps) == len(matched) else "event_index"

    start_ts: datetime | None = None
    end_ts: datetime | None = None
    span: float | None = None
    temporal_applied = False

    if timestamps:
        start_ts = min(timestamps)
        end_ts = max(timestamps)
        span = (end_ts - start_ts).total_seconds()
        if definition.time_window_seconds is not None:
            temporal_applied = span <= definition.time_window_seconds

    return SequenceMatch(
        definition=definition,
        matched_indexes=tuple(match_idx),
        ordering_basis=basis,
        temporal_constraint_applied=temporal_applied,
        start_timestamp=start_ts,
        end_timestamp=end_ts,
        span_seconds=span,
    )
