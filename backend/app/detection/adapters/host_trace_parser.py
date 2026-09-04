"""Host trace parser adapter facade.

Re-exports the public parsing surface:
- Raw trace parsing -> TraceSummary (from app.services.host_trace)
- TraceSummary -> CanonicalEvent[] (from app.detection.adapters.host_trace)

Kept as a thin facade so callers can address a single adapter entry point.
"""
from __future__ import annotations

from app.detection.adapters.host_trace import (
    network_event_data_to_canonical_events,
    syscall_calls_to_canonical_events,
    trace_summary_to_canonical_events,
)
from app.services.host_trace import TraceSummary, summarize_host_trace

__all__ = [
    "TraceSummary",
    "summarize_host_trace",
    "trace_summary_to_canonical_events",
    "syscall_calls_to_canonical_events",
    "network_event_data_to_canonical_events",
]
