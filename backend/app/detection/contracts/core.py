"""Core detection architecture contracts.

Defines the canonical event model, detection context, detection result,
evidence model, detector protocol, and risk assessment boundary.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, Sequence, runtime_checkable


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

class EventType(str, enum.Enum):
    """Extensible event-type system.

    Only SYSTEM_CALL and NETWORK are actively produced today.
    Other categories exist as architectural types for future adapters.
    """
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    DNS = "dns"
    AUTHENTICATION = "authentication"
    SYSTEM_CALL = "system_call"
    SERVICE = "service"
    PERSISTENCE = "persistence"
    REGISTRY = "registry"
    MODULE = "module"
    USER = "user"
    HOST = "host"
    SECURITY = "security"


class DetectorCategory(str, enum.Enum):
    RULE = "rule"
    SIGNATURE = "signature"
    IOC = "ioc"
    THRESHOLD = "threshold"
    STATISTICAL = "statistical"
    BASELINE = "baseline"
    UNSUPERVISED_ML = "unsupervised_ml"
    SUPERVISED_ML = "supervised_ml"
    LIGHT_HIDS = "light_hids"
    CORRELATION = "correlation"


class DetectorScope(str, enum.Enum):
    EVENT = "event"
    PROCESS = "process"
    USER = "user"
    HOST = "host"
    NETWORK_FLOW = "network_flow"
    ANALYSIS_RUN = "analysis_run"
    INCIDENT = "incident"


# ---------------------------------------------------------------------------
# Event provenance
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EventProvenance:
    """Traceability: where did this event come from?"""
    source_type: str
    source_adapter: str
    source_event_id: str | None = None
    source_record_index: int | None = None
    analysis_run_id: str | None = None
    original_timestamp: datetime | None = None
    ingestion_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Canonical event
# ---------------------------------------------------------------------------

@dataclass
class CanonicalEvent:
    """Type-safe canonical event representation.

    Designed to be independent of any specific telemetry source.
    Future adapters (PCAP, Zeek, Suricata, endpoint) will produce
    these from their own schemas.
    """
    event_id: str
    timestamp: datetime | None
    event_type: EventType
    source_type: str

    # Optional identity fields — not every event has all of these
    host_id: str | None = None
    tenant_id: str | None = None
    user_id: str | None = None

    # Process context
    process_id: int | None = None
    parent_process_id: int | None = None
    process_name: str | None = None
    command_line: str | None = None

    # File context
    file_path: str | None = None
    file_hash: str | None = None

    # Network context
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    connection_id: str | None = None

    # Syscall context
    syscall: str | None = None
    syscall_id: int | None = None

    # Generic action / direction
    action: str | None = None
    direction: str | None = None
    status: str | None = None

    # Extensible attributes for source-specific data that doesn't fit typed fields
    attributes: dict[str, Any] = field(default_factory=dict)

    # Provenance
    provenance: EventProvenance = field(default_factory=lambda: EventProvenance(source_type="unknown", source_adapter="unknown"))


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """Structured, machine-readable evidence for a detection.

    Answers: why did the detector fire?
    """
    rule: str
    observed_values: dict[str, Any] = field(default_factory=dict)
    matched_events: list[str] = field(default_factory=list)
    matched_fields: list[str] = field(default_factory=list)
    threshold: Any = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"rule": self.rule}
        if self.observed_values:
            result.update(self.observed_values)
        if self.threshold is not None:
            result["threshold"] = self.threshold
        if self.matched_events:
            result["matched_events"] = self.matched_events
        if self.matched_fields:
            result["matched_fields"] = self.matched_fields
        if self.description:
            result["description"] = self.description
        return result


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class DetectionScores:
    """Separated scoring concepts.

    These are fundamentally different and must not be collapsed into one number.
    """
    detection_confidence: float | None = None
    anomaly_score: float | None = None
    model_score: float | None = None
    threat_intelligence_confidence: float | None = None
    contextual_risk: float | None = None
    heuristic_score: int | None = None


@dataclass
class DetectionResult:
    """Structured output from a detector.

    This is the primary contract between detectors and the orchestration layer.
    Detectors produce these. The orchestrator persists them.
    """
    detector_id: str
    detector_version: str
    detection_type: str
    title: str
    description: str
    severity: str
    evidence: Evidence
    scores: DetectionScores = field(default_factory=DetectionScores)

    # Source information
    source_events: list[str] = field(default_factory=list)
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Detection context
# ---------------------------------------------------------------------------

@dataclass
class DetectionContext:
    """Explicit context passed to detectors.

    Decouples detectors from infrastructure (FastAPI, SQLAlchemy, etc.)
    """
    analysis_run_id: str | None = None
    tenant_id: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)
    event_count: int = 0
    sequence_count: int = 0
    unique_system_calls: int = 0


# ---------------------------------------------------------------------------
# Risk assessment boundary
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    """Risk engine output boundary.

    Phase 1: This is a transitional interface.
    The current implementation maps severity to risk as a placeholder.
    Future phases will implement contextual risk scoring.
    """
    risk_score: float
    risk_factors: dict[str, Any] = field(default_factory=dict)
    risk_version: str = "1.0"
    explanation: str | None = None


# ---------------------------------------------------------------------------
# Detector protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class Detector(Protocol):
    """Detector interface contract.

    Detectors must be testable without a database.
    They receive canonical events and context, return detection results.
    """
    @property
    def detector_id(self) -> str: ...

    @property
    def detector_version(self) -> str: ...

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def category(self) -> DetectorCategory: ...

    @property
    def scope(self) -> DetectorScope: ...

    @property
    def supported_event_types(self) -> tuple[EventType, ...]: ...

    @property
    def enabled(self) -> bool: ...

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]: ...
