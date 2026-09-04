"""Network detectors — migrated from detection_engine.py analyse_network_events().

Each detector is an independent class implementing the Detector protocol.
Detection semantics (thresholds, severities) are preserved from the legacy
engine, but thresholds are now read from validated detector configuration.
Scoring routes through the single authoritative function in
``app.detection.scoring``.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Sequence

from app.detection.configuration.defaults import DEFAULT_CONFIG
from app.detection.configuration.validation import resolve_detector_config
from app.detection.contracts.core import (
    CanonicalEvent,
    DetectionContext,
    DetectionResult,
    DetectionScores,
    DetectorCategory,
    DetectorScope,
    Evidence,
    EventType,
)
from app.detection.scoring import compute_heuristic_score


def _extract_network_events(events: Sequence[CanonicalEvent]) -> list[CanonicalEvent]:
    return [e for e in events if e.event_type == EventType.NETWORK]


def _config(context: DetectionContext, detector_id: str) -> dict[str, Any]:
    return resolve_detector_config(detector_id, context.configuration, DEFAULT_CONFIG.get(detector_id, {}))


class ExcessiveConnectionDetector:
    """Detects source IPs connecting to 10+ unique destinations (configurable)."""

    @property
    def detector_id(self) -> str:
        return "network.excessive_connection_attempts"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Excessive Connection Attempts"

    @property
    def description(self) -> str:
        return "Detects source IPs with excessive unique destinations."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.NETWORK_FLOW

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.NETWORK,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["unique_destination_threshold"]

        net_events = _extract_network_events(events)
        if not net_events:
            return []

        src_ips: dict[str, list[CanonicalEvent]] = defaultdict(list)
        for ne in net_events:
            if ne.source_ip:
                src_ips[ne.source_ip].append(ne)

        total = len(net_events)
        src_count = len(src_ips)
        port_count = len({ne.source_port for ne in net_events if ne.source_port} | {ne.destination_port for ne in net_events if ne.destination_port})

        results: list[DetectionResult] = []
        matched_rules = 0

        for src_ip, evts in src_ips.items():
            unique_dsts = {e.destination_ip for e in evts if e.destination_ip}
            if len(unique_dsts) >= threshold:
                matched_rules += 1
                score = compute_heuristic_score(
                    event_count=total,
                    diversity=port_count,
                    matched_rules=matched_rules,
                )
                evidence = Evidence(
                    rule="excessive_connection_attempts",
                    observed_values={"source_ip": src_ip, "unique_destinations": len(unique_dsts)},
                    threshold=threshold,
                )
                results.append(DetectionResult(
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detection_type="excessive_connection_attempts",
                    title=f"Excessive connection attempts from {src_ip}",
                    description=(
                        f"Source IP {src_ip} connected to {len(unique_dsts)} unique destinations "
                        f"across {len(evts)} network events. This may indicate scanning or exfiltration."
                    ),
                    severity="high",
                    evidence=evidence,
                    source_ip=src_ip,
                    scores=DetectionScores(heuristic_score=score),
                ))

        return results


class PortScanDetector:
    """Detects ports receiving connections from 5+ unique sources (configurable)."""

    @property
    def detector_id(self) -> str:
        return "network.port_scan_detected"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Port Scan Detection"

    @property
    def description(self) -> str:
        return "Detects port scan activity."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.NETWORK_FLOW

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.NETWORK,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["unique_source_ip_threshold"]

        net_events = _extract_network_events(events)
        if not net_events:
            return []

        port_events: dict[int, list[CanonicalEvent]] = defaultdict(list)
        for ne in net_events:
            if ne.destination_port:
                port_events[ne.destination_port].append(ne)

        total = len(net_events)
        src_ips = {ne.source_ip for ne in net_events if ne.source_ip}
        port_count = len(port_events)

        results: list[DetectionResult] = []
        matched_rules = 0

        for port, evts in port_events.items():
            src_count = len({e.source_ip for e in evts if e.source_ip})
            if src_count >= threshold:
                matched_rules += 1
                score = compute_heuristic_score(
                    event_count=total,
                    diversity=port_count,
                    matched_rules=matched_rules,
                )
                evidence = Evidence(
                    rule="port_scan_detected",
                    observed_values={"destination_port": port, "unique_sources": src_count},
                    threshold=threshold,
                )
                results.append(DetectionResult(
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detection_type="port_scan_detected",
                    title=f"Port scan detected on port {port}",
                    description=(
                        f"Port {port} received connections from {src_count} unique source IPs. "
                        "This pattern is consistent with port scanning activity."
                    ),
                    severity="high",
                    evidence=evidence,
                    scores=DetectionScores(heuristic_score=score),
                ))

        return results


class ConnectionFrequencyDetector:
    """Detects ports with 50+ network events (configurable)."""

    @property
    def detector_id(self) -> str:
        return "network.high_connection_frequency"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "High Connection Frequency"

    @property
    def description(self) -> str:
        return "Detects unusually high connection frequency on ports."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.NETWORK_FLOW

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.NETWORK,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["event_count_threshold"]

        net_events = _extract_network_events(events)
        if not net_events:
            return []

        port_events: dict[int, list[CanonicalEvent]] = defaultdict(list)
        for ne in net_events:
            if ne.destination_port:
                port_events[ne.destination_port].append(ne)

        high_freq_ports = [p for p, evts in port_events.items() if len(evts) >= threshold]
        if not high_freq_ports:
            return []

        total = len(net_events)
        src_ips = len({ne.source_ip for ne in net_events if ne.source_ip})
        port_count = len(port_events)
        score = compute_heuristic_score(
            event_count=total,
            diversity=port_count,
            matched_rules=1,
        )

        evidence = Evidence(
            rule="high_connection_frequency",
            observed_values={"high_frequency_ports": high_freq_ports},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="high_connection_frequency",
            title="Unusually high connection frequency",
            description=(
                f"Ports {high_freq_ports} each received {threshold}+ network events. "
                "High connection frequency may indicate brute-force or DDoS activity."
            ),
            severity="medium",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]


class RepeatedConnectionDetector:
    """Detects source IPs connecting to 20+ unique destinations (configurable)."""

    @property
    def detector_id(self) -> str:
        return "network.repeated_connection_attempts"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Repeated Connection Attempts"

    @property
    def description(self) -> str:
        return "Detects repeated diverse connection attempts."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.NETWORK_FLOW

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.NETWORK,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["unique_destination_threshold"]

        net_events = _extract_network_events(events)
        if not net_events:
            return []

        connections: dict[str, set[str]] = defaultdict(set)
        for ne in net_events:
            if ne.source_ip and ne.destination_ip:
                connections[ne.source_ip].add(ne.destination_ip)

        multi_connection_sources = [ip for ip, dsts in connections.items() if len(dsts) >= threshold]
        if not multi_connection_sources:
            return []

        total = len(net_events)
        port_count = len({ne.source_port for ne in net_events if ne.source_port} | {ne.destination_port for ne in net_events if ne.destination_port})
        score = compute_heuristic_score(
            event_count=total,
            diversity=port_count,
            matched_rules=1,
        )

        evidence = Evidence(
            rule="repeated_connection_attempts",
            observed_values={"source_ips": multi_connection_sources},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="repeated_connection_attempts",
            title="Repeated connection attempts detected",
            description=(
                f"Source IPs {multi_connection_sources} each connected to {threshold}+ unique destinations. "
                "Repeated diverse connections may indicate lateral movement or C2 communication."
            ),
            severity="critical",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]
