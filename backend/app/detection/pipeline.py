"""High-level detection analysis pipeline.

Composes the canonical-event flow for the analysis route:

    raw trace -> TraceSummary -> CanonicalEvent[]
    -> DetectionContext -> DetectionOrchestrator -> DetectionResult[]
    -> persist -> (Detection[], Alert[])

It exposes two pipeline entry points used by the analysis route:

- ``analyse_trace``: runs the host-scoped detectors (SYSTEM_CALL events)
- ``analyse_network_events``: runs the network-scoped detectors (NETWORK events)

Both keep the same names and call signatures that the analysis route and
the audit-driven failure tests depend on, but internally they use the
modular architecture instead of the legacy monolithic engine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.orm import Session

from app.detection.adapters.host_trace import (
    network_event_data_to_canonical_events,
    syscall_calls_to_canonical_events,
)
from app.detection.configuration.provider import DetectorConfigurationProvider
from app.detection.contracts.core import (
    CanonicalEvent,
    DetectionContext,
    EventProvenance,
    EventType,
)
from app.detection.ioc.provider import IOCProvider
from app.detection.orchestration.orchestrator import DetectionOrchestrator
from app.detection.persistence.mapping import persist_detections
from app.detection.registry.bootstrap import build_orchestrator
from app.models.alert import Alert
from app.models.detection import Detection
from app.models.network_event import NetworkEvent

# Scope filters: host detectors consume SYSTEM_CALL events, network
# detectors consume NETWORK events. The shared orchestrator scopes its
# run via these event types so the two phases stay decoupled.
_HOST_EVENT_TYPES = {EventType.SYSTEM_CALL}
_NETWORK_EVENT_TYPES = {EventType.NETWORK}


def analyse_trace(
    *,
    event_count: int,
    sequence_count: int,
    unique_system_calls: int,
    all_calls: list[str],
    db: Session,
    analysis_run_id: str | None = None,
) -> tuple[list[Detection], list[Alert]]:
    """Run the host-scoped detectors over the trace's system calls."""
    events = syscall_calls_to_canonical_events(all_calls, analysis_run_id)
    context = DetectionContext(
        analysis_run_id=analysis_run_id,
        event_count=event_count,
        sequence_count=sequence_count,
        unique_system_calls=unique_system_calls,
    )

    orchestrator = _build_orchestrator()
    result = orchestrator.execute(events, context, event_types=_HOST_EVENT_TYPES)
    _log_orchestrator_errors(result.errors)

    return persist_detections(result.results, db=db, analysis_run_id=analysis_run_id)


def analyse_network_events(
    *,
    network_events: Sequence[NetworkEvent],
    analysis_run_id: str | None = None,
    db: Session,
) -> tuple[list[Detection], list[Alert]]:
    """Run the network-scoped detectors over the persisted network events."""
    events = _network_orm_to_canonical(network_events, analysis_run_id)
    context = DetectionContext(
        analysis_run_id=analysis_run_id,
        event_count=len(events),
        sequence_count=len({getattr(e, "attributes", {}).get("sequence_index") for e in events}),
    )

    orchestrator = _build_orchestrator()
    result = orchestrator.execute(events, context, event_types=_NETWORK_EVENT_TYPES)
    _log_orchestrator_errors(result.errors)

    return persist_detections(result.results, db=db, analysis_run_id=analysis_run_id)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# The IOCProvider is injectable so test/ops code can supply IOCs without
# touching the detector contract. The default is an empty provider — no IOC is
# fabricated; with no configured IOCs each analysis produces zero IOC matches.
_ioc_provider = IOCProvider()
_config_provider = DetectorConfigurationProvider()


def set_ioc_provider(provider: IOCProvider) -> None:
    """Install an IOC provider used by subsequent pipeline executions."""
    global _ioc_provider
    _ioc_provider = provider


def get_ioc_provider() -> IOCProvider:
    """Return the currently installed IOC provider."""
    return _ioc_provider


def set_config_provider(provider: DetectorConfigurationProvider) -> None:
    """Install a detector-configuration provider for subsequent executions."""
    global _config_provider
    _config_provider = provider


def _build_orchestrator() -> DetectionOrchestrator:
    """Build a fresh orchestrator per call — no stale cross-run state."""
    return build_orchestrator(_config_provider, _ioc_provider)


def _log_orchestrator_errors(errors: list[dict[str, str]]) -> None:
    if not errors:
        return
    # Failures are isolated per-detector by the orchestrator; log without
    # leaking stack traces.
    import logging

    logger = logging.getLogger(__name__)
    for err in errors:
        logger.error(
            "Detector %s v%s failed with %s: %s",
            err.get("detector_id"),
            err.get("detector_version"),
            err.get("error_type"),
            err.get("error_message"),
        )


def _network_orm_to_canonical(
    network_events: Sequence[NetworkEvent],
    analysis_run_id: str | None,
) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for idx, ne in enumerate(network_events):
        events.append(
            CanonicalEvent(
                event_id=f"{analysis_run_id}:net:{idx}" if analysis_run_id else str(idx),
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
            )
        )
    return events
