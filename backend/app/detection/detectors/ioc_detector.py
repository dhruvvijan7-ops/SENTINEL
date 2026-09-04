"""IOC matching detector (Phase 2).

Matches real telemetry values against an injected :class:`IOCProvider`. Current
telemetry reliably populates IP addresses on NETWORK events, so the detector
matches ``source_ip`` and ``destination_ip`` against IP IOCs.

The provider is injected (dependency inversion) so the detector is decoupled
from any storage/feed. No IOC is fabricated — with an empty provider the
detector simply reports nothing.
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
from app.detection.ioc.models import IOCType
from app.detection.ioc.provider import IOCProvider
from app.detection.scoring import compute_heuristic_score

_MAX_MATCH_RESULTS = 20
_MAX_EVIDENCE_EVENTS = 10


class IOCDetector:
    """Matches network IPs against configured IOCs."""

    def __init__(self, ioc_provider: IOCProvider | None = None) -> None:
        self._provider = ioc_provider or IOCProvider()

    @property
    def detector_id(self) -> str:
        return "network.ioc_match"

    @property
    def detector_version(self) -> str:
        return "1.0"

    @property
    def name(self) -> str:
        return "IOC Match"

    @property
    def description(self) -> str:
        return "Matches network IP telemetry against configured indicators of compromise."

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.IOC

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
        resolve_detector_config(self.detector_id, context.configuration, DEFAULT_CONFIG.get(self.detector_id, {}))  # validate hook
        matcher = self._provider.matcher()
        if len(matcher) == 0:
            return []

        net_events = [e for e in events if e.event_type == EventType.NETWORK]
        if not net_events:
            return []

        matches_by_field: dict[str, list] = {}
        matched_event_ids: list[str] = []

        for idx, ne in enumerate(net_events):
            field_values = (
                ("source_ip", ne.source_ip),
                ("destination_ip", ne.destination_ip),
            )
            for field_name, candidate in field_values:
                for m in matcher.match_field(IOCType.IP, candidate, field_name):
                    key = (m.ioc.normalized_value, field_name)
                    if key in matches_by_field:
                        continue
                    matches_by_field[key] = m.to_dict()
                    matched_event_ids.append(ne.event_id)
                    if len(matches_by_field) >= _MAX_MATCH_RESULTS:
                        break
            if len(matches_by_field) >= _MAX_MATCH_RESULTS:
                break

        if not matches_by_field:
            return []

        matched_iocs = list(matches_by_field.values())
        matched_fields = list(matches_by_field.keys())
        field_names = [fn for _, fn in matched_fields]

        evidence_fields: dict[str, Any] = {
            "ioc_matches": matched_iocs[: _MAX_MATCH_RESULTS],
            "matched_fields": _unique(field_names),
        }
        if matched_event_ids:
            evidence_fields["matched_events"] = matched_event_ids[:_MAX_EVIDENCE_EVENTS]
            if len(matched_event_ids) > _MAX_EVIDENCE_EVENTS:
                evidence_fields["matched_events_truncated"] = True

        score = compute_heuristic_score(
            event_count=len(net_events),
            diversity=len({e.destination_port for e in net_events if e.destination_port}),
            matched_rules=len(matched_iocs),
        )
        evidence = Evidence(
            rule="ioc_match",
            observed_values=evidence_fields,
            description="Network IP telemetry matched configured IOC(s).",
        )
        return [DetectionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detection_type="ioc_match",
            title="IOC match detected",
            description=(
                f"{len(matched_iocs)} configured IOC(s) matched network IP telemetry "
                f"on field(s): {', '.join(field_names)}."
            ),
            severity="high",
            evidence=evidence,
            scores=DetectionScores(heuristic_score=score),
            source_events=matched_event_ids[:_MAX_EVIDENCE_EVENTS],
        )]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
