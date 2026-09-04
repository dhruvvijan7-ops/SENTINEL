"""Tests for the modular detection architecture (Phase 1).

Covers:
- Canonical event adapters (raw -> CanonicalEvent)
- Detector registry bootstrap (10 detectors)
- Orchestrator execution, event-type scoping, and failure isolation
- Detector independence (no DB required)
- Pipeline persistence (DetectionResult -> Detection + Alert)
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.detection.adapters.host_trace import (
    network_event_data_to_canonical_events,
    syscall_calls_to_canonical_events,
    trace_summary_to_canonical_events,
)
from app.detection.contracts.core import (
    CanonicalEvent,
    DetectionContext,
    DetectionResult,
    DetectionScores,
    Detector,
    DetectorCategory,
    DetectorScope,
    Evidence,
    EventType,
)
from app.detection.detectors.host_detectors import (
    ExcessiveSequenceDetector,
    HighEventVolumeDetector,
    HighSyscallDiversityDetector,
    PrivilegeEscalationDetector,
    SensitiveFileOperationDetector,
    SuspiciousNetworkPatternDetector,
)
from app.detection.detectors.network_detectors import (
    ConnectionFrequencyDetector,
    ExcessiveConnectionDetector,
    PortScanDetector,
    RepeatedConnectionDetector,
)
from app.detection.orchestration.orchestrator import DetectionOrchestrator, OrchestratorResult
from app.detection.pipeline import analyse_network_events, analyse_trace
from app.detection.registry.bootstrap import build_registry, build_orchestrator
from app.detection.registry.registry import DetectorRegistry
from app.models.alert import Alert
from app.models.detection import Detection


# ---------------------------------------------------------------------------
# Canonical event adapters
# ---------------------------------------------------------------------------

def _syscall(name: str, idx: int) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"ev-{idx}",
        timestamp=None,
        event_type=EventType.SYSTEM_CALL,
        source_type="host_trace",
        syscall=name,
    )


def _net_event(
    si: str | None,
    di: str | None,
    sp: int | None,
    dp: int | None,
    idx: int,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"net-{idx}",
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.NETWORK,
        source_type="host_trace",
        source_ip=si,
        destination_ip=di,
        source_port=sp,
        destination_port=dp,
        protocol="tcp",
        syscall="connect",
    )


class TestCanonicalEventAdapters:
    def test_syscall_calls_become_system_call_events(self) -> None:
        events = syscall_calls_to_canonical_events(["openat", "read", "close"], "run-1")
        assert len(events) == 3
        assert all(e.event_type == EventType.SYSTEM_CALL for e in events)
        assert [e.syscall for e in events] == ["openat", "read", "close"]
        assert all(e.provenance.analysis_run_id == "run-1" for e in events)

    def test_trace_summary_round_trip(self) -> None:
        from app.services.host_trace import TraceSummary

        summary = TraceSummary(
            event_count=3,
            sequence_count=1,
            unique_system_calls=3,
            all_calls=["openat", "read", "close"],
        )
        events = trace_summary_to_canonical_events(summary, "run-1")
        assert len(events) == 3
        assert all(e.event_type == EventType.SYSTEM_CALL for e in events)

    def test_network_event_data_to_canonical(self) -> None:
        from app.services.host_trace import NetworkEventData

        data = NetworkEventData(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            source_port=1234,
            destination_port=80,
            protocol="tcp",
            connection_id="c1",
            syscall_name="connect",
            sequence_index=0,
            event_index=1,
            description="connect request",
        )
        events = network_event_data_to_canonical_events([data], "run-1")
        assert len(events) == 1
        assert events[0].event_type == EventType.NETWORK
        assert events[0].source_ip == "10.0.0.1"
        assert events[0].destination_port == 80
        assert events[0].connection_id == "c1"


# ---------------------------------------------------------------------------
# Registry bootstrap
# ---------------------------------------------------------------------------

class TestRegistryBootstrap:
    def test_all_detectors_registered(self) -> None:
        registry = build_registry()
        ids = {d.detector_id for d in registry.get_all()}
        assert ids == {
            "host.high_event_volume",
            "host.excessive_sequences",
            "host.suspicious_network_pattern",
            "host.privilege_escalation",
            "host.suspicious_file_operations",
            "host.high_syscall_diversity",
            "network.excessive_connection_attempts",
            "network.port_scan_detected",
            "network.high_connection_frequency",
            "network.repeated_connection_attempts",
            "network.event_rate_window",
            "host.syscall_sequence",
            "network.ioc_match",
        }

    def test_registry_lookup_and_enable(self) -> None:
        registry = DetectorRegistry()
        d = HighEventVolumeDetector()
        registry.register(d)
        assert registry.get("host.high_event_volume") is d
        registry.set_enabled("host.high_event_volume", False)
        assert d not in registry.get_enabled()
        registry.set_enabled("host.high_event_volume", True)
        assert d in registry.get_enabled()

    def test_build_orchestrator_returns_usable_orchestrator(self) -> None:
        orch = build_orchestrator()
        events = [_syscall("openat", 0)]
        ctx = DetectionContext(event_count=1, sequence_count=1, unique_system_calls=1)
        result = orch.execute(events, ctx)
        assert isinstance(result, OrchestratorResult)


# ---------------------------------------------------------------------------
# Host detectors
# ---------------------------------------------------------------------------

class TestHostDetectors:
    def test_high_event_volume_fires_over_500(self) -> None:
        det = HighEventVolumeDetector()
        ctx = DetectionContext(event_count=600, sequence_count=1, unique_system_calls=5)
        results = det.detect([], ctx)
        assert len(results) == 1
        assert results[0].detection_type == "high_event_volume"
        assert results[0].severity == "medium"

    def test_high_event_volume_does_not_fire_at_500(self) -> None:
        det = HighEventVolumeDetector()
        ctx = DetectionContext(event_count=500, sequence_count=1, unique_system_calls=5)
        assert det.detect([], ctx) == []

    def test_excessive_sequences_fires_over_50(self) -> None:
        det = ExcessiveSequenceDetector()
        ctx = DetectionContext(event_count=1, sequence_count=60, unique_system_calls=1)
        results = det.detect([], ctx)
        assert len(results) == 1
        assert results[0].detection_type == "excessive_sequences"

    def test_suspicious_network_pattern_three_distinct(self) -> None:
        det = SuspiciousNetworkPatternDetector()
        events = [_syscall("socket", 0), _syscall("connect", 1), _syscall("sendto", 2)]
        results = det.detect(events, DetectionContext(event_count=3, sequence_count=1, unique_system_calls=3))
        assert len(results) == 1
        assert results[0].detection_type == "suspicious_network_pattern"
        assert results[0].severity == "high"

    def test_suspicious_network_pattern_two_distinct_no_fire(self) -> None:
        det = SuspiciousNetworkPatternDetector()
        events = [_syscall("socket", 0), _syscall("connect", 1)]
        assert det.detect(events, DetectionContext(event_count=2, sequence_count=1, unique_system_calls=2)) == []

    def test_privilege_escalation_fires(self) -> None:
        det = PrivilegeEscalationDetector()
        events = [_syscall("setuid", 0)]
        results = det.detect(events, DetectionContext(event_count=1, sequence_count=1, unique_system_calls=1))
        assert len(results) == 1
        assert results[0].detection_type == "privilege_escalation"
        assert results[0].severity == "critical"

    def test_sensitive_file_operations_fires(self) -> None:
        det = SensitiveFileOperationDetector()
        events = [_syscall("openat", 0), _syscall("unlink", 1)]
        results = det.detect(events, DetectionContext(event_count=2, sequence_count=1, unique_system_calls=2))
        assert len(results) == 1
        assert results[0].detection_type == "suspicious_file_operations"

    def test_high_syscall_diversity_fires_over_30(self) -> None:
        det = HighSyscallDiversityDetector()
        ctx = DetectionContext(event_count=100, sequence_count=1, unique_system_calls=31)
        results = det.detect([], ctx)
        assert len(results) == 1
        assert results[0].detection_type == "high_syscall_diversity"
        assert results[0].severity == "low"

    def test_does_not_fire_on_unrelated_events(self) -> None:
        det = PrivilegeEscalationDetector()
        events = [_syscall("openat", 0), _syscall("read", 1)]
        assert det.detect(events, DetectionContext(event_count=2, sequence_count=1, unique_system_calls=2)) == []


# ---------------------------------------------------------------------------
# Network detectors
# ---------------------------------------------------------------------------

class TestNetworkDetectors:
    def _many_connections(self, src: str, dsts: list[str]) -> list[CanonicalEvent]:
        return [_net_event(src, d, 1000 + i, 80, i) for i, d in enumerate(dsts)]

    def test_excessive_connections_fires(self) -> None:
        det = ExcessiveConnectionDetector()
        events = self._many_connections("10.0.0.1", [f"10.0.1.{i}" for i in range(10)])
        results = det.detect(events, DetectionContext(event_count=len(events)))
        assert len(results) == 1
        assert results[0].detection_type == "excessive_connection_attempts"

    def test_excessive_connections_below_threshold(self) -> None:
        det = ExcessiveConnectionDetector()
        events = self._many_connections("10.0.0.1", [f"10.0.1.{i}" for i in range(5)])
        assert det.detect(events, DetectionContext(event_count=5)) == []

    def test_port_scan_fires(self) -> None:
        det = PortScanDetector()
        events = [_net_event(f"10.0.0.{i}", "9.9.9.9", 1000 + i, 22, i) for i in range(5)]
        results = det.detect(events, DetectionContext(event_count=5))
        assert len(results) == 1
        assert results[0].detection_type == "port_scan_detected"

    def test_high_connection_frequency_fires(self) -> None:
        det = ConnectionFrequencyDetector()
        events = [_net_event("10.0.0.1", "10.0.0.2", 1000, 443, i) for i in range(50)]
        results = det.detect(events, DetectionContext(event_count=50))
        assert len(results) == 1
        assert results[0].detection_type == "high_connection_frequency"
        assert results[0].severity == "medium"

    def test_repeated_connections_fires(self) -> None:
        det = RepeatedConnectionDetector()
        events = self._many_connections("10.0.0.1", [f"10.0.2.{i}" for i in range(20)])
        results = det.detect(events, DetectionContext(event_count=len(events)))
        assert len(results) == 1
        assert results[0].detection_type == "repeated_connection_attempts"
        assert results[0].severity == "critical"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class _ExplodingDetector:
    """Detector that always raises, to exercise failure isolation."""

    @property
    def detector_id(self) -> str:
        return "test.exploding"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Exploding"

    @property
    def description(self) -> str:
        return "Raises on detect."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.RULE

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.ANALYSIS_RUN

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.SYSTEM_CALL,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(self, events, context):
        raise RuntimeError("boom")


class _ReturnDetector:
    """Detector that returns one canonical detection result."""

    @property
    def detector_id(self) -> str:
        return "test.returns"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Returns"

    @property
    def description(self) -> str:
        return "Returns a detection."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.RULE

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.ANALYSIS_RUN

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.SYSTEM_CALL,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(self, events, context):
        return [
            DetectionResult(
                detector_id=self.detector_id,
                detector_version="1.0",
                detection_type="test.returned",
                title="Returned",
                description="A detection.",
                severity="medium",
                evidence=Evidence(rule="test.returned"),
                scores=DetectionScores(heuristic_score=50),
            )
        ]


class TestOrchestrator:
    def test_executes_applicable_detectors(self) -> None:
        registry = DetectorRegistry()
        ret = _ReturnDetector()
        registry.register(ret)
        orch = DetectionOrchestrator(registry)
        result = orch.execute([_syscall("openat", 0)], DetectionContext(event_count=1))
        assert [r.detection_type for r in result.results] == ["test.returned"]
        assert result.errors == []

    def test_scoping_filters_by_event_type(self) -> None:
        registry = DetectorRegistry()
        ret = _ReturnDetector()  # supports SYSTEM_CALL
        registry.register(ret)
        orch = DetectionOrchestrator(registry)
        # NETWORK scope -> SYSTEM_CALL-only detector excluded
        net_events = [_net_event("1.1.1.1", "2.2.2.2", 1, 80, 0)]
        result = orch.execute(net_events, DetectionContext(event_count=1), event_types={EventType.NETWORK})
        assert result.results == []
        # SYSTEM_CALL scope -> included (even on no syscall events, detector runs)
        result2 = orch.execute([], DetectionContext(event_count=1), event_types={EventType.SYSTEM_CALL})
        assert [r.detection_type for r in result2.results] == ["test.returned"]

    def test_detector_failure_is_isolated(self) -> None:
        registry = DetectorRegistry()
        registry.register(_ExplodingDetector())
        registry.register(_ReturnDetector())
        orch = DetectionOrchestrator(registry)
        result = orch.execute([_syscall("openat", 0)], DetectionContext(event_count=1))
        # The exploding detector's failure is captured, not raised
        assert [r.detection_type for r in result.results] == ["test.returned"]
        assert len(result.errors) == 1
        assert result.errors[0]["detector_id"] == "test.exploding"
        assert result.errors[0]["error_type"] == "RuntimeError"

    def test_failure_does_not_block_other_detectors(self) -> None:
        registry = DetectorRegistry()
        registry.register(_ExplodingDetector())
        orch = DetectionOrchestrator(registry)
        result = orch.execute([_syscall("openat", 0)], DetectionContext(event_count=1))
        assert result.results == []
        assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# Pipeline persistence
# ---------------------------------------------------------------------------

class TestPipelinePersistence:
    def test_analyse_trace_persists_host_detections(
        self, client, db: Session
    ) -> None:
        # Grant dangling role usage; upload path not used here, direct pipeline call.
        results, alerts = analyse_trace(
            event_count=600,
            sequence_count=1,
            unique_system_calls=5,
            all_calls=["openat", "read", "close"] * 200,
            db=db,
            analysis_run_id="run-host",
        )
        assert results
        types = {d.detection_type for d in results}
        assert "high_event_volume" in types

    def test_analyse_network_events_persists_excessive(
        self, client, db: Session
    ) -> None:
        from app.models.network_event import NetworkEvent

        events = []
        for i in range(10):
            events.append(
                NetworkEvent(
                    analysis_run_id="run-net",
                    source_ip="10.0.0.1",
                    destination_ip=f"10.0.1.{i}",
                    source_port=1000 + i,
                    destination_port=80,
                    protocol="tcp",
                    syscall_name="connect",
                    sequence_index=0,
                    event_index=i,
                )
            )
        db.add_all(events)
        db.flush()

        results, alerts = analyse_network_events(
            network_events=events,
            analysis_run_id="run-net",
            db=db,
        )
        types = {d.detection_type for d in results}
        assert "excessive_connection_attempts" in types

    def test_persist_maps_to_orm_with_alerts(self, db: Session) -> None:
        from app.detection.persistence.mapping import persist_detections

        results = [
            DetectionResult(
                detector_id="host.privilege_escalation",
                detector_version="1.0",
                detection_type="privilege_escalation",
                title="Privilege escalation",
                description="setuid detected",
                severity="critical",
                evidence=Evidence(
                    rule="privilege_escalation",
                    observed_values={"privilege_calls": ["setuid"]},
                ),
                scores=DetectionScores(heuristic_score=42),
                source_events=["ev-1", "ev-2"],
            )
        ]
        detections, alerts = persist_detections(results, db=db, analysis_run_id="run-x")
        db.flush()
        assert len(detections) == 1
        assert len(alerts) == 1
        assert detections[0].analysis_run_id == "run-x"
        assert detections[0].severity == "critical"
        assert detections[0].detector_id == "host.privilege_escalation"
        assert detections[0].detector_version == "1.0"
        assert detections[0].source_events == ["ev-1", "ev-2"]
        assert alerts[0].detection_id == detections[0].id
        assert alerts[0].severity == "critical"
