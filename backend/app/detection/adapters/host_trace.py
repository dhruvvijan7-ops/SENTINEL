"""Host trace input adapter.

Converts parsed host trace data (TraceSummary) into CanonicalEvents.
Preserves all existing parsing behavior from host_trace.py.
"""
from __future__ import annotations

from uuid import uuid4

from app.detection.contracts.core import (
    CanonicalEvent,
    EventType,
    EventProvenance,
)
from app.services.host_trace import TraceSummary


def _make_event_id(analysis_run_id: str | None, prefix: str, index: int) -> str:
    if analysis_run_id:
        return f"{analysis_run_id}:{prefix}:{index}"
    return str(uuid4())


def _host_provenance(analysis_run_id: str | None) -> EventProvenance:
    return EventProvenance(
        source_type="host_trace",
        source_adapter="host_trace_json_csv",
        analysis_run_id=analysis_run_id,
    )


def syscall_calls_to_canonical_events(
    all_calls: list[str],
    analysis_run_id: str | None = None,
) -> list[CanonicalEvent]:
    """Build SYSTEM_CALL canonical events from a flat list of syscall names."""
    provenance = _host_provenance(analysis_run_id)
    return [
        CanonicalEvent(
            event_id=_make_event_id(analysis_run_id, "syscall", idx),
            timestamp=None,
            event_type=EventType.SYSTEM_CALL,
            source_type="host_trace",
            syscall=call_name,
            provenance=provenance,
        )
        for idx, call_name in enumerate(all_calls)
    ]


def network_event_data_to_canonical_events(
    network_events: Sequence[NetworkEventData],
    analysis_run_id: str | None = None,
) -> list[CanonicalEvent]:
    """Build NETWORK canonical events from NetworkEventData objects."""
    events: list[CanonicalEvent] = []
    for idx, ne in enumerate(network_events):
        events.append(CanonicalEvent(
            event_id=_make_event_id(analysis_run_id, "net", idx),
            timestamp=ne.timestamp,
            event_type=EventType.NETWORK,
            source_type="host_trace",
            source_ip=ne.source_ip,
            destination_ip=ne.destination_ip,
            source_port=ne.source_port,
            destination_port=ne.destination_port,
            protocol=ne.protocol,
            connection_id=ne.connection_id,
            syscall=ne.syscall_name,
            attributes={
                "sequence_index": ne.sequence_index,
                "event_index": ne.event_index,
                "description": ne.description,
            },
            provenance=EventProvenance(
                source_type="host_trace",
                source_adapter="host_trace_json_csv",
                source_event_id=f"{ne.sequence_index}:{ne.event_index}" if ne.sequence_index is not None else None,
                analysis_run_id=analysis_run_id,
            ),
        ))
    return events


def trace_summary_to_canonical_events(
    summary: TraceSummary,
    analysis_run_id: str | None = None,
) -> list[CanonicalEvent]:
    """Convert a TraceSummary into a list of CanonicalEvents.

    Produces:
    - One SYSTEM_CALL event per syscall in all_calls
    - One NETWORK event per network event in summary.network_events
    """
    events: list[CanonicalEvent] = []

    provenance = EventProvenance(
        source_type="host_trace",
        source_adapter="host_trace_json_csv",
        analysis_run_id=analysis_run_id,
    )

    for idx, call_name in enumerate(summary.all_calls):
        events.append(CanonicalEvent(
            event_id=_make_event_id(analysis_run_id, "syscall", idx),
            timestamp=None,
            event_type=EventType.SYSTEM_CALL,
            source_type="host_trace",
            syscall=call_name,
            provenance=provenance,
        ))

    for idx, ne in enumerate(summary.network_events):
        events.append(CanonicalEvent(
            event_id=_make_event_id(analysis_run_id, "net", idx),
            timestamp=ne.timestamp,
            event_type=EventType.NETWORK,
            source_type="host_trace",
            source_ip=ne.source_ip,
            destination_ip=ne.destination_ip,
            source_port=ne.source_port,
            destination_port=ne.destination_port,
            protocol=ne.protocol,
            connection_id=ne.connection_id,
            syscall=ne.syscall_name,
            attributes={
                "sequence_index": ne.sequence_index,
                "event_index": ne.event_index,
                "description": ne.description,
            },
            provenance=EventProvenance(
                source_type="host_trace",
                source_adapter="host_trace_json_csv",
                source_event_id=f"{ne.sequence_index}:{ne.event_index}",
                analysis_run_id=analysis_run_id,
            ),
        ))

    return events
