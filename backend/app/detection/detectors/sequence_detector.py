"""Ordered system-call sequence detector (Phase 2).

Identifies real ordered patterns — e.g. ``open -> write -> close`` — over
system-call events, preserving order. Because current system-call telemetry
carries no timestamps, the matcher operates on event order only
(``ordering_basis="event_index"``) and does NOT claim a time window was
enforced, even if ``window_seconds`` is configured.
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
from app.detection.sequence.matching import find_matches
from app.detection.sequence.models import Predicate, SequenceDefinition


class SyscallSequenceDetector:
    """Detects an ordered system-call sequence (A, then B, then C)."""

    @property
    def detector_id(self) -> str:
        return "host.syscall_sequence"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Syscall Sequence"

    @property
    def description(self) -> str:
        return "Detects an ordered sequence of system calls (ordering only; syscalls lack timestamps)."

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
        cfg = resolve_detector_config(
            self.detector_id, context.configuration, DEFAULT_CONFIG.get(self.detector_id, {})
        )
        raw_sequence = cfg["sequence"]
        window_seconds = cfg.get("window_seconds")

        if not raw_sequence:
            return []

        syscall_events = [e for e in events if e.event_type == EventType.SYSTEM_CALL]
        if len(syscall_events) < 2:
            return []

        predicates = tuple(
            Predicate(field="syscall", value=str(name)) for name in raw_sequence
        )
        definition = SequenceDefinition(
            id="syscall.sequence." + ".".join(str(n) for n in raw_sequence),
            name="Syscall sequence: " + ", ".join(str(n) for n in raw_sequence),
            predicates=predicates,
            time_window_seconds=window_seconds,
        )

        matches = find_matches(syscall_events, definition)

        if not matches:
            return []

        match = matches[0]
        matched_syscalls = [
            syscall_events[idx].syscall for idx in match.matched_indexes
        ]

        evidence_fields: dict[str, Any] = {
            "sequence": list(raw_sequence),
            "matched_events": list(match.matched_indexes),
            "ordering_basis": match.ordering_basis,
            "temporal_constraint_applied": match.temporal_constraint_applied,
            "matched_syscalls": matched_syscalls,
        }
        if match.start_timestamp is not None:
            evidence_fields["start_timestamp"] = match.start_timestamp.isoformat()
        if match.end_timestamp is not None:
            evidence_fields["end_timestamp"] = match.end_timestamp.isoformat()
        if match.span_seconds is not None:
            evidence_fields["span_seconds"] = match.span_seconds

        score = compute_heuristic_score(
            event_count=context.event_count,
            diversity=context.unique_system_calls,
            matched_rules=len(matches),
        )
        evidence = Evidence(
            rule="syscall_sequence",
            observed_values=evidence_fields,
            description="Ordered system-call sequence matched using event order (syscalls lack timestamps).",
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="syscall_sequence",
            title="Ordered syscall sequence detected",
            description=(
                f"Detected the ordered syscall sequence ({', '.join(str(n) for n in raw_sequence)}) "
                f"({len(matches)} match(es)). Matching used event order only; no time window was enforced "
                "because system-call events carry no timestamps."
            ),
            severity="low",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
            source_events=[
                syscall_events[idx].event_id for idx in match.matched_indexes
            ],
        )]
