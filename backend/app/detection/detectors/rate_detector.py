"""Network event-rate / window detector (Phase 2).

Demonstrates genuine temporal detection over network telemetry, which carries
real timestamps. Counts network events grouped by destination port within a
configurable sliding window (``window_seconds``) and fires once the observed
count within any window reaches ``event_threshold``.

System-call events are intentionally NOT consumed here — they carry no
timestamps, so temporal processing would have to fabricate time.
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
from app.detection.temporal.windows import grouped_max_in_window


def _port_group_key(event: CanonicalEvent) -> Any:
    return event.destination_port


class EventRateWindowDetector:
    """Detects high connection rates per destination port within a window."""

    @property
    def detector_id(self) -> str:
        return "network.event_rate_window"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "Event Rate Window"

    @property
    def description(self) -> str:
        return "Detects bursts of network events per destination port within a time window."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.RULE

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
        cfg = resolve_detector_config(
            self.detector_id, context.configuration, DEFAULT_CONFIG.get(self.detector_id, {})
        )
        window_seconds = cfg["window_seconds"]
        event_threshold = cfg["event_threshold"]

        # Only network events carry timestamps; temporal analysis is restricted to them.
        net_events = [e for e in events if e.event_type == EventType.NETWORK]
        if not net_events:
            return []

        observations = grouped_max_in_window(
            net_events,
            window_seconds=window_seconds,
            group_key=_port_group_key,
        )

        results: list[DetectionResult] = []
        matched_groups: list[int] = []
        for port, obs in observations.items():
            if obs.observed_count >= event_threshold:
                matched_groups.append(port)
                # Diversity metric for network scoring mirrors port diversity.
                score = compute_heuristic_score(
                    event_count=obs.observed_count,
                    diversity=len({e.source_ip for e in net_events if e.source_ip}),
                    matched_rules=1,
                )
                evidence_fields: dict[str, Any] = {
                    "destination_port": port,
                    "window_duration": window_seconds,
                    "observed_count": obs.observed_count,
                    "event_threshold": event_threshold,
                    "grouping_key": "destination_port",
                }
                if obs.window_start is not None:
                    evidence_fields["window_start"] = _iso(obs.window_start)
                if obs.window_end is not None:
                    evidence_fields["window_end"] = _iso(obs.window_end)
                if obs.matched_event_ids:
                    evidence_fields["matched_events"] = list(obs.matched_event_ids)
                    evidence_fields["matched_events_truncated"] = len(obs.matched_event_ids) < obs.observed_count

                evidence = Evidence(
                    rule="network_event_rate_window",
                    observed_values=evidence_fields,
                    threshold=event_threshold,
                )
                results.append(DetectionResult(
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detection_type="network_event_rate_window",
                    title=f"High event rate on port {port}",
                    description=(
                        f"{obs.observed_count} network events occurred on destination port {port} "
                        f"within a {window_seconds}-second window (threshold {event_threshold}), "
                        "suggesting burst/scan activity."
                    ),
                    severity="medium",
                    evidence=evidence,
                    scores=DetectionScores(heuristic_score=score),
                    source_events=list(obs.matched_event_ids),
                ))
        return results


def _iso(dt) -> str:
    return dt.isoformat()
