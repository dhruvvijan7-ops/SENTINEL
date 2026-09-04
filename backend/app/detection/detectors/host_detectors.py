"""Host trace detectors — migrated from detection_engine.py analyse_trace().

Each detector is an independent class implementing the Detector protocol.
Detection semantics (thresholds, severities) are preserved from the legacy
engine, but thresholds are now read from validated detector configuration
instead of hard-coded literals. Scoring routes through the single
authoritative function in ``app.detection.scoring``.
"""
from __future__ import annotations

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

NETWORK_CALLS = frozenset({"socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg"})
PRIVILEGE_CALLS = frozenset({"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "capset", "prctl"})
FILE_SENSITIVE_CALLS = frozenset({"openat", "unlink", "unlinkat", "rename", "renameat", "chmod", "fchmod", "chown"})


def _get_syscall_calls(events: Sequence[CanonicalEvent]) -> tuple[set[str], list[str]]:
    """Extract syscall names from canonical events."""
    calls: set[str] = set()
    all_calls: list[str] = []
    for e in events:
        if e.event_type == EventType.SYSTEM_CALL and e.syscall:
            calls.add(e.syscall)
            all_calls.append(e.syscall)
    return calls, all_calls


def _config(context: DetectionContext, detector_id: str) -> dict[str, Any]:
    return resolve_detector_config(detector_id, context.configuration, DEFAULT_CONFIG.get(detector_id, {}))


class HighEventVolumeDetector:
    """Detects traces with more than 500 events (configurable)."""

    @property
    def detector_id(self) -> str:
        return "host.high_event_volume"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "High Event Volume"

    @property
    def description(self) -> str:
        return "Detects traces with excessive event counts."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.ANALYSIS_RUN

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.SYSTEM_CALL,)

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

        if context.event_count <= threshold:
            return []

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=1,
        )
        evidence = Evidence(
            rule="high_event_volume",
            observed_values={"event_count": context.event_count},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="high_event_volume",
            title="High event volume detected",
            description=(
                f"The trace contains {context.event_count} events, exceeding the {threshold}-event threshold. "
                "This may indicate automated activity or a compromised process generating excessive system calls."
            ),
            severity="medium",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]


class ExcessiveSequenceDetector:
    """Detects traces with more than 50 execution sequences (configurable)."""

    @property
    def detector_id(self) -> str:
        return "host.excessive_sequences"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Excessive Sequences"

    @property
    def description(self) -> str:
        return "Detects traces with excessive execution sequences."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.ANALYSIS_RUN

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.SYSTEM_CALL,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["sequence_count_threshold"]

        if context.sequence_count <= threshold:
            return []

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=1,
        )
        evidence = Evidence(
            rule="excessive_sequences",
            observed_values={"sequence_count": context.sequence_count},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="excessive_sequences",
            title="Excessive execution sequences",
            description=(
                f"The trace contains {context.sequence_count} execution sequences, exceeding the {threshold}-sequence threshold. "
                "Frequent process restarts or forking patterns may suggest malicious behaviour."
            ),
            severity="medium",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]


class SuspiciousNetworkPatternDetector:
    """Detects 3+ distinct network-related syscalls (configurable)."""

    @property
    def detector_id(self) -> str:
        return "host.suspicious_network_pattern"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Suspicious Network Pattern"

    @property
    def description(self) -> str:
        return "Detects multiple distinct network-related system calls."

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

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["distinct_network_syscall_threshold"]

        call_set, _ = _get_syscall_calls(events)
        network_used = call_set & NETWORK_CALLS

        if len(network_used) < threshold:
            return []

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=1,
        )
        evidence = Evidence(
            rule="suspicious_network_pattern",
            observed_values={"network_calls": sorted(network_used), "count": len(network_used)},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="suspicious_network_pattern",
            title="Suspicious network activity pattern",
            description=(
                f"Detected {len(network_used)} network-related system calls: {', '.join(sorted(network_used))}. "
                "Multiple distinct network operations suggest potential data exfiltration or command-and-control communication."
            ),
            severity="high",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]


class PrivilegeEscalationDetector:
    """Detects privilege-related system calls."""

    @property
    def detector_id(self) -> str:
        return "host.privilege_escalation"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Privilege Escalation"

    @property
    def description(self) -> str:
        return "Detects privilege-related system calls."

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

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        call_set, _ = _get_syscall_calls(events)
        privilege_used = call_set & PRIVILEGE_CALLS

        if not privilege_used:
            return []

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=1,
        )
        evidence = Evidence(
            rule="privilege_escalation",
            observed_values={"privilege_calls": sorted(privilege_used)},
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="privilege_escalation",
            title="Privilege escalation attempt detected",
            description=(
                f"Detected privilege-related system calls: {', '.join(sorted(privilege_used))}. "
                "These calls are commonly associated with privilege escalation attacks and require immediate investigation."
            ),
            severity="critical",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]


class SensitiveFileOperationDetector:
    """Detects 2+ sensitive file operations (configurable)."""

    @property
    def detector_id(self) -> str:
        return "host.suspicious_file_operations"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Sensitive File Operations"

    @property
    def description(self) -> str:
        return "Detects multiple sensitive file operations."

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

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["sensitive_operation_threshold"]

        call_set, _ = _get_syscall_calls(events)
        file_sensitive_used = call_set & FILE_SENSITIVE_CALLS

        if len(file_sensitive_used) < threshold:
            return []

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=1,
        )
        evidence = Evidence(
            rule="suspicious_file_operations",
            observed_values={"file_calls": sorted(file_sensitive_used), "count": len(file_sensitive_used)},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="suspicious_file_operations",
            title="Suspicious file system manipulation",
            description=(
                f"Detected {len(file_sensitive_used)} sensitive file operations: {', '.join(sorted(file_sensitive_used))}. "
                "Multiple sensitive file operations may indicate tampering, data staging, or log tampering."
            ),
            severity="high",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]


class HighSyscallDiversityDetector:
    """Detects traces with more than 30 unique syscalls (configurable)."""

    @property
    def detector_id(self) -> str:
        return "host.high_syscall_diversity"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "High Syscall Diversity"

    @property
    def description(self) -> str:
        return "Detects unusually high syscall diversity."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.THRESHOLD

    @property
    def scope(self) -> DetectorScope:
        return DetectorScope.ANALYSIS_RUN

    @property
    def supported_event_types(self) -> tuple[EventType, ...]:
        return (EventType.SYSTEM_CALL,)

    @property
    def enabled(self) -> bool:
        return True

    def detect(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
    ) -> Sequence[DetectionResult]:
        cfg = _config(context, self.detector_id)
        threshold = cfg["unique_syscall_threshold"]

        if context.unique_system_calls <= threshold:
            return []

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=1,
        )
        evidence = Evidence(
            rule="high_syscall_diversity",
            observed_values={"unique_system_calls": context.unique_system_calls},
            threshold=threshold,
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="high_syscall_diversity",
            title="High syscall diversity observed",
            description=(
                f"The trace uses {context.unique_system_calls} unique system calls. "
                "Unusually high diversity may indicate a complex attack chain or an advanced toolset."
            ),
            severity="low",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
        )]
