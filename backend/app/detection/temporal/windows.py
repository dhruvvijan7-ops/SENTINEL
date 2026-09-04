"""Reusable temporal (rate/window) primitives.

Provides near-linear sliding-window functions over timestamped events without
fabricating time. Events without a timestamp are never given an invented
timestamp — they are simply excluded from temporal windows.

Primary primitive: :func:`grouped_max_in_window`.

Complexity: each group's events are sorted by timestamp and scanned with a
two-pointer window, so the work is O(n log n) for sorting plus O(n) scanning
per group — NOT O(n²).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence


@dataclass(frozen=True)
class WindowObservation:
    """Result of a grouped sliding-window analysis for one group."""

    group_key: str
    group_value: Any
    observed_count: int
    threshold: int | None
    window_seconds: int
    window_start: datetime | None
    window_end: datetime | None
    matched_event_ids: tuple[str, ...] = ()


def _default_group_key(event: Any) -> Any:
    """Default grouping key extracts 'group_value' from attributes if present."""
    attrs = getattr(event, "attributes", {}) or {}
    return attrs.get("group_value", None)


def grouped_max_in_window(
    events: Sequence[Any],
    *,
    window_seconds: int,
    timestamp_attr: str = "timestamp",
    group_key: Callable[[Any], Any] | None = None,
    event_id_attr: str | None = "event_id",
    max_matched_events: int = 20,
) -> dict[Any, WindowObservation]:
    """Return, per group, the maximum event count within any ``window_seconds`` span.

    Timestamped events are sorted and scanned with a two-pointer window. Events
    whose timestamp is ``None`` are ignored (never fabricated).

    Returns a dict mapping group_key -> :class:`WindowObservation` describing the
    densest window found for that group.
    """
    group_key_fn = group_key or _default_group_key
    buckets: dict[Any, list[Any]] = defaultdict(list)
    for ev in events:
        ts = getattr(ev, timestamp_attr, None)
        if ts is None:
            continue
        buckets[group_key_fn(ev)].append(ev)

    results: dict[Any, WindowObservation] = {}

    for group, evts in buckets.items():
        if not evts:
            continue
        # Stable sort by timestamp; equal timestamps keep input order.
        ordered = sorted(evts, key=lambda e: (getattr(e, timestamp_attr), id(e)))
        left = 0
        best_count = 0
        best_start: datetime | None = None
        best_end: datetime | None = None
        best_ids: tuple[str, ...] = ()

        for right, ev in enumerate(ordered):
            ts_right = getattr(ev, timestamp_attr)
            # Advance the left pointer until the window is within window_seconds.
            while left < right:
                ts_left = getattr(ordered[left], timestamp_attr)
                if (ts_right - ts_left).total_seconds() > window_seconds:
                    left += 1
                else:
                    break
            count = right - left + 1
            if count > best_count:
                best_count = count
                best_start = getattr(ordered[left], timestamp_attr)
                best_end = ts_right
                best_ids = _collect_ids(ordered, left, right, event_id_attr, max_matched_events)

        results[group] = WindowObservation(
            group_key=_repr_group(group),
            group_value=_safe_group_value(group),
            observed_count=best_count,
            threshold=None,
            window_seconds=window_seconds,
            window_start=best_start,
            window_end=best_end,
            matched_event_ids=best_ids,
        )

    return results


def _collect_ids(
    ordered: list[Any],
    left: int,
    right: int,
    event_id_attr: str | None,
    max_matched_events: int,
) -> tuple[str, ...]:
    ids: list[str] = []
    for i in range(left, right + 1):
        ev = ordered[i]
        eid = getattr(ev, event_id_attr, None) if event_id_attr else getattr(ev, "event_id", None)
        if eid is not None:
            ids.append(str(eid))
        if len(ids) >= max_matched_events:
            break
    return tuple(ids)


def _repr_group(group: Any) -> str:
    return str(group)


def _safe_group_value(group: Any) -> Any:
    if isinstance(group, (str, int, float, bool)) or group is None:
        return group
    return str(group)


# Alias matching the naming used in documentation/tests.
CountInWindow = WindowObservation
