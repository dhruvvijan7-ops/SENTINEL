# DEPRECATED (Phase 2): this legacy monolithic engine is retained only for
# backward compatibility and is superseded by app.detection.pipeline /
# app.detection.detectors. New code must use app.detection.pipeline.
from __future__ import annotations

import math
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.detection import Detection
from app.models.network_event import NetworkEvent

NETWORK_CALLS = {"socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg"}
PRIVILEGE_CALLS = {"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "capset", "prctl"}
FILE_SENSITIVE_CALLS = {"openat", "unlink", "unlinkat", "rename", "renameat", "chmod", "fchmod", "chown"}


def _compute_confidence(event_count: int, sequence_count: int, unique_system_calls: int, matched_rules: int) -> int:
    base = min(matched_rules * 15, 60)
    volume_bonus = min(event_count / 100, 20)
    diversity_bonus = min(unique_system_calls / 10, 20)
    raw = base + volume_bonus + diversity_bonus
    return min(max(int(raw), 10), 99)


def analyse_trace(
    *,
    event_count: int,
    sequence_count: int,
    unique_system_calls: int,
    all_calls: list[str],
    db: Session,
    analysis_run_id: str | None = None,
) -> tuple[list[Detection], list[Alert]]:
    detections: list[Detection] = []
    alerts: list[Alert] = []
    call_set = set(all_calls)

    network_used = call_set & NETWORK_CALLS
    privilege_used = call_set & PRIVILEGE_CALLS
    file_sensitive_used = call_set & FILE_SENSITIVE_CALLS

    matched_rules = 0

    if event_count > 500:
        matched_rules += 1
        evidence: dict[str, object] = {
            "rule": "high_event_volume",
            "event_count": event_count,
            "threshold": 500,
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="high_event_volume",
            title="High event volume detected",
            description=(
                f"The trace contains {event_count} events, exceeding the 500-event threshold. "
                "This may indicate automated activity or a compromised process generating excessive system calls."
            ),
            severity="medium",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(event_count, sequence_count, unique_system_calls, matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="medium",
            status="new",
            title="High event volume detected",
            description=detection.description,
            source="detection-engine",
        )
        alerts.append(alert)

    if sequence_count > 50:
        matched_rules += 1
        evidence = {
            "rule": "excessive_sequences",
            "sequence_count": sequence_count,
            "threshold": 50,
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="excessive_sequences",
            title="Excessive execution sequences",
            description=(
                f"The trace contains {sequence_count} execution sequences, exceeding the 50-sequence threshold. "
                "Frequent process restarts or forking patterns may suggest malicious behaviour."
            ),
            severity="medium",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(event_count, sequence_count, unique_system_calls, matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="medium",
            status="new",
            title="Excessive execution sequences",
            description=detection.description,
            source="detection-engine",
        )
        alerts.append(alert)

    if len(network_used) >= 3:
        matched_rules += 1
        evidence = {
            "rule": "suspicious_network_pattern",
            "network_calls": sorted(network_used),
            "count": len(network_used),
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="suspicious_network_pattern",
            title="Suspicious network activity pattern",
            description=(
                f"Detected network-related system calls: {', '.join(sorted(network_used))}. "
                "Multiple distinct network operations suggest potential data exfiltration or command-and-control communication."
            ),
            severity="high",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(event_count, sequence_count, unique_system_calls, matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="high",
            status="new",
            title="Suspicious network activity pattern",
            description=detection.description,
            source="detection-engine",
        )
        alerts.append(alert)

    if privilege_used:
        matched_rules += 1
        evidence = {
            "rule": "privilege_escalation",
            "privilege_calls": sorted(privilege_used),
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="privilege_escalation",
            title="Privilege escalation attempt detected",
            description=(
                f"Detected privilege-related system calls: {', '.join(sorted(privilege_used))}. "
                "These calls are commonly associated with privilege escalation attacks and require immediate investigation."
            ),
            severity="critical",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(event_count, sequence_count, unique_system_calls, matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="critical",
            status="new",
            title="Privilege escalation attempt detected",
            description=detection.description,
            source="detection-engine",
        )
        alerts.append(alert)

    if len(file_sensitive_used) >= 2:
        matched_rules += 1
        evidence = {
            "rule": "suspicious_file_operations",
            "file_calls": sorted(file_sensitive_used),
            "count": len(file_sensitive_used),
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="suspicious_file_operations",
            title="Suspicious file system manipulation",
            description=(
                f"Detected sensitive file operations: {', '.join(sorted(file_sensitive_used))}. "
                "Multiple sensitive file operations may indicate tampering, data staging, or log tampering."
            ),
            severity="high",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(event_count, sequence_count, unique_system_calls, matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="high",
            status="new",
            title="Suspicious file system manipulation",
            description=detection.description,
            source="detection-engine",
        )
        alerts.append(alert)

    if unique_system_calls > 30:
        matched_rules += 1
        evidence = {
            "rule": "high_syscall_diversity",
            "unique_system_calls": unique_system_calls,
            "threshold": 30,
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="high_syscall_diversity",
            title="High syscall diversity observed",
            description=(
                f"The trace uses {unique_system_calls} unique system calls. "
                "Unusually high diversity may indicate a complex attack chain or an advanced toolset."
            ),
            severity="low",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(event_count, sequence_count, unique_system_calls, matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="low",
            status="new",
            title="High syscall diversity observed",
            description=detection.description,
            source="detection-engine",
        )
        alerts.append(alert)

    for detection in detections:
        db.add(detection)
    for alert in alerts:
        db.add(alert)

    if detections or alerts:
        db.flush()

    return detections, alerts


def analyse_network_events(
    *,
    network_events: list[NetworkEvent],
    analysis_run_id: str | None = None,
    db: Session,
) -> tuple[list[Detection], list[Alert]]:
    detections: list[Detection] = []
    alerts: list[Alert] = []
    matched_rules = 0

    src_ips: dict[str, list[NetworkEvent]] = {}
    dst_ips: dict[str, list[NetworkEvent]] = {}
    ports: dict[int, list[NetworkEvent]] = {}
    connections: dict[str, set[str]] = {}

    for ne in network_events:
        if ne.source_ip:
            src_ips.setdefault(ne.source_ip, []).append(ne)
        if ne.destination_ip:
            dst_ips.setdefault(ne.destination_ip, []).append(ne)
        if ne.source_port:
            ports.setdefault(ne.source_port, []).append(ne)
        if ne.destination_port:
            ports.setdefault(ne.destination_port, []).append(ne)
        if ne.source_ip and ne.destination_ip:
            connections.setdefault(ne.source_ip, set()).add(ne.destination_ip)

    total = len(network_events)

    for src_ip, events in src_ips.items():
        unique_dsts = set(e.destination_ip for e in events if e.destination_ip)
        if len(unique_dsts) >= 10:
            matched_rules += 1
            evidence: dict[str, object] = {
                "rule": "excessive_connection_attempts",
                "source_ip": src_ip,
                "unique_destinations": len(unique_dsts),
                "threshold": 10,
            }
            detection = Detection(
                id=str(uuid4()),
                analysis_run_id=analysis_run_id,
                detection_type="excessive_connection_attempts",
                title=f"Excessive connection attempts from {src_ip}",
                description=(
                    f"Source IP {src_ip} connected to {len(unique_dsts)} unique destinations "
                    f"across {len(events)} network events. This may indicate scanning or exfiltration."
                ),
                severity="high",
                confidence=0,
                source_ip=src_ip,
                evidence=evidence,
            )
            confidence = _compute_confidence(total, len(src_ips), len(ports), matched_rules)
            detection.confidence = confidence
            detections.append(detection)

            alert = Alert(
                id=str(uuid4()),
                detection_id=detection.id,
                severity="high",
                status="new",
                title=detection.title,
                description=detection.description,
                source="network-detection-engine",
            )
            alerts.append(alert)

    port_events: dict[int, list[NetworkEvent]] = {}
    for ne in network_events:
        if ne.destination_port:
            port_events.setdefault(ne.destination_port, []).append(ne)

    for port, events in port_events.items():
        src_count = len(set(e.source_ip for e in events if e.source_ip))
        if src_count >= 5:
            matched_rules += 1
            evidence = {
                "rule": "port_scan_detected",
                "destination_port": port,
                "unique_sources": src_count,
                "threshold": 5,
            }
            detection = Detection(
                id=str(uuid4()),
                analysis_run_id=analysis_run_id,
                detection_type="port_scan_detected",
                title=f"Port scan detected on port {port}",
                description=(
                    f"Port {port} received connections from {src_count} unique source IPs. "
                    "This pattern is consistent with port scanning activity."
                ),
                severity="high",
                confidence=0,
                destination_ip=None,
                evidence=evidence,
            )
            confidence = _compute_confidence(total, len(src_ips), len(ports), matched_rules)
            detection.confidence = confidence
            detections.append(detection)

            alert = Alert(
                id=str(uuid4()),
                detection_id=detection.id,
                severity="high",
                status="new",
                title=detection.title,
                description=detection.description,
                source="network-detection-engine",
            )
            alerts.append(alert)

    high_freq_ports = [p for p, evts in port_events.items() if len(evts) >= 50]
    if high_freq_ports:
        matched_rules += 1
        evidence = {
            "rule": "high_connection_frequency",
            "high_frequency_ports": high_freq_ports,
            "threshold": 50,
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="high_connection_frequency",
            title="Unusually high connection frequency",
            description=(
                f"Ports {high_freq_ports} each received 50+ network events. "
                "High connection frequency may indicate brute-force or DDoS activity."
            ),
            severity="medium",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(total, len(src_ips), len(ports), matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="medium",
            status="new",
            title=detection.title,
            description=detection.description,
            source="network-detection-engine",
        )
        alerts.append(alert)

    multi_connection_sources = [ip for ip, dsts in connections.items() if len(dsts) >= 20]
    if multi_connection_sources:
        matched_rules += 1
        evidence = {
            "rule": "repeated_connection_attempts",
            "source_ips": multi_connection_sources,
            "threshold": 20,
        }
        detection = Detection(
            id=str(uuid4()),
            analysis_run_id=analysis_run_id,
            detection_type="repeated_connection_attempts",
            title="Repeated connection attempts detected",
            description=(
                f"Source IPs {multi_connection_sources} each connected to 20+ unique destinations. "
                "Repeated diverse connections may indicate lateral movement or C2 communication."
            ),
            severity="critical",
            confidence=0,
            evidence=evidence,
        )
        confidence = _compute_confidence(total, len(src_ips), len(ports), matched_rules)
        detection.confidence = confidence
        detections.append(detection)

        alert = Alert(
            id=str(uuid4()),
            detection_id=detection.id,
            severity="critical",
            status="new",
            title=detection.title,
            description=detection.description,
            source="network-detection-engine",
        )
        alerts.append(alert)

    for detection in detections:
        db.add(detection)
    for alert in alerts:
        db.add(alert)

    if detections or alerts:
        db.flush()

    return detections, alerts
