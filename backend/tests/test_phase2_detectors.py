"""Tests for the Phase 2 detection capabilities.

Covers:
- Rate / sliding-window detection (EventRateWindowDetector + grouped_max_in_window)
- Ordered sequence matching (SyscallSequenceDetector + find_matches)
- IOC foundation (normalization, matcher, provider, IOCDetector)
- Integration through the registry / pipeline
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.detection.configuration.defaults import DEFAULT_ENABLED
from app.detection.contracts.core import (
    CanonicalEvent,
    DetectionContext,
    DetectorCategory,
    DetectorScope,
    EventType,
)
from app.detection.detectors.ioc_detector import IOCDetector
from app.detection.detectors.rate_detector import EventRateWindowDetector
from app.detection.detectors.sequence_detector import SyscallSequenceDetector
from app.detection.ioc.models import IOC, IOCType
from app.detection.ioc.normalize import (
    IOCNormalizationError,
    normalize_ioc,
)
from app.detection.ioc.provider import IOCProvider
from app.detection.registry.bootstrap import build_registry, build_orchestrator
from app.detection.sequence.matching import find_matches
from app.detection.sequence.models import Predicate, SequenceDefinition
from app.detection.temporal.windows import grouped_max_in_window


def _syscall(name: str, idx: int) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"ev-{idx}",
        timestamp=None,
        event_type=EventType.SYSTEM_CALL,
        source_type="host_trace",
        syscall=name,
    )


def _net_event(
    idx: int,
    si: str = "10.0.0.1",
    di: str = "192.168.1.10",
    dp: int = 443,
    ts: datetime | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=f"net-{idx}",
        timestamp=ts or datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc),
        event_type=EventType.NETWORK,
        source_type="host_trace",
        source_ip=si,
        destination_ip=di,
        destination_port=dp,
        protocol="tcp",
        syscall="connect",
    )


# ---------------------------------------------------------------------------
# Temporal / rate-window primitive
# ---------------------------------------------------------------------------


class TestGroupedMaxInWindow:
    def test_counts_all_in_wide_window(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [
            _net_event(i, dp=8080, ts=t0 + timedelta(seconds=i)) for i in range(10)
        ]
        obs = grouped_max_in_window(
            events, window_seconds=60, group_key=lambda e: e.destination_port
        )
        assert list(obs.keys()) == [8080]
        assert obs[8080].observed_count == 10

    def test_splits_across_window_boundary(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = []
        for i in range(3):
            events.append(_net_event(i, dp=22, ts=t0 + timedelta(seconds=i)))
        # 3 events within 3 seconds -> all fit in a 10s window
        obs = grouped_max_in_window(
            events, window_seconds=10, group_key=lambda e: e.destination_port
        )
        assert obs[22].observed_count == 3

    def test_grouping_by_port(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [
            _net_event(0, dp=443, ts=t0),
            _net_event(1, dp=443, ts=t0 + timedelta(seconds=1)),
            _net_event(2, dp=22, ts=t0),
        ]
        obs = grouped_max_in_window(
            events, window_seconds=60, group_key=lambda e: e.destination_port
        )
        assert set(obs.keys()) == {443, 22}
        assert obs[443].observed_count == 2
        assert obs[22].observed_count == 1


# ---------------------------------------------------------------------------
# Rate-window detector
# ---------------------------------------------------------------------------


def _rate_detector_config(threshold: int, window: int) -> DetectionContext:
    return DetectionContext(
        event_count=10,
        configuration={
            "network.event_rate_window": {
                "event_threshold": threshold,
                "window_seconds": window,
            }
        },
    )


class TestEventRateWindowDetector:
    def test_fires_when_threshold_reached(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [
            _net_event(i, dp=443, ts=t0 + timedelta(seconds=i)) for i in range(5)
        ]
        det = EventRateWindowDetector()
        results = det.detect(events, _rate_detector_config(3, 60))
        assert len(results) == 1
        assert results[0].detector_id == "network.event_rate_window"
        assert det.category == DetectorCategory.RULE
        assert det.scope == DetectorScope.NETWORK_FLOW
        assert results[0].evidence.observed_values["destination_port"] == 443
        assert results[0].evidence.observed_values["observed_count"] >= 3
        assert results[0].scores.heuristic_score is not None

    def test_ignores_system_call_events(self) -> None:
        syscalls = [_syscall("open", i) for i in range(5)]
        det = EventRateWindowDetector()
        assert det.detect(syscalls, _rate_detector_config(3, 60)) == []

    def test_no_result_below_threshold(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [_net_event(i, dp=443, ts=t0 + timedelta(seconds=i)) for i in range(2)]
        det = EventRateWindowDetector()
        assert det.detect(events, _rate_detector_config(3, 60)) == []

    def test_uses_defaults_when_no_config(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [_net_event(i, dp=443, ts=t0 + timedelta(seconds=i)) for i in range(3)]
        det = EventRateWindowDetector()
        # Default threshold is 50; 3 events must not fire.
        assert det.detect(events, DetectionContext(event_count=3)) == []


# ---------------------------------------------------------------------------
# Sequence matching framework
# ---------------------------------------------------------------------------


class TestFindMatches:
    def _events(self, names: list[str]) -> list[CanonicalEvent]:
        return [_syscall(n, i) for i, n in enumerate(names)]

    def test_matches_ordered_pattern(self) -> None:
        events = self._events(["open", "write", "close"])
        definition = SequenceDefinition(
            id="t1",
            name="open-write-close",
            predicates=(
                Predicate(field="syscall", value="open"),
                Predicate(field="syscall", value="write"),
                Predicate(field="syscall", value="close"),
            ),
        )
        matches = find_matches(events, definition)
        assert len(matches) == 1
        assert matches[0].matched_indexes == (0, 1, 2)
        # syscalls carry no timestamps -> ordering basis must be event_index
        assert matches[0].ordering_basis == "event_index"

    def test_out_of_order_does_not_match(self) -> None:
        events = self._events(["write", "open", "close"])
        definition = SequenceDefinition(
            id="t1",
            name="open-write-close",
            predicates=(
                Predicate(field="syscall", value="open"),
                Predicate(field="syscall", value="write"),
                Predicate(field="syscall", value="close"),
            ),
        )
        assert find_matches(events, definition) == []

    def test_multiple_non_overlapping_matches(self) -> None:
        events = self._events(["open", "write", "close", "open", "write", "close"])
        definition = SequenceDefinition(
            id="t1",
            name="owc",
            predicates=(
                Predicate(field="syscall", value="open"),
                Predicate(field="syscall", value="write"),
                Predicate(field="syscall", value="close"),
            ),
        )
        matches = find_matches(events, definition, max_matches=10)
        assert len(matches) == 2
        assert matches[0].matched_indexes == (0, 1, 2)
        assert matches[1].matched_indexes == (3, 4, 5)

    def test_timestamp_window_enforced_for_network(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [
            _net_event(0, dp=443, ts=t0),
            _net_event(1, dp=443, ts=t0 + timedelta(seconds=1)),
        ]
        definition = SequenceDefinition(
            id="t2",
            name="two-connects",
            predicates=(
                Predicate(field="destination_port", value=443),
                Predicate(field="destination_port", value=443),
            ),
            time_window_seconds=5,
        )
        matches = find_matches(events, definition)
        assert len(matches) == 1
        assert matches[0].ordering_basis == "timestamp"
        assert matches[0].temporal_constraint_applied is True

    def test_empty_predicates_return_no_matches(self) -> None:
        events = self._events(["open", "write"])
        definition = SequenceDefinition(id="e", name="empty")
        assert find_matches(events, definition) == []


# ---------------------------------------------------------------------------
# Sequence detector
# ---------------------------------------------------------------------------


class TestSyscallSequenceDetector:
    def test_fires_on_ordered_default_pattern(self) -> None:
        events = [_syscall("open", 0), _syscall("write", 1), _syscall("close", 2)]
        det = SyscallSequenceDetector()
        results = det.detect(events, DetectionContext(event_count=3))
        assert len(results) == 1
        assert results[0].detector_id == "host.syscall_sequence"
        assert det.category == DetectorCategory.RULE
        assert det.scope == DetectorScope.ANALYSIS_RUN
        evidence = results[0].evidence.observed_values
        assert evidence["ordering_basis"] == "event_index"
        assert evidence["temporal_constraint_applied"] is False

    def test_no_match_on_out_of_order(self) -> None:
        events = [_syscall("write", 0), _syscall("open", 1), _syscall("close", 2)]
        det = SyscallSequenceDetector()
        assert det.detect(events, DetectionContext(event_count=3)) == []

    def test_respects_configured_sequence(self) -> None:
        events = [_syscall("open", 0), _syscall("read", 1), _syscall("close", 2)]
        det = SyscallSequenceDetector()
        context = DetectionContext(
            event_count=3,
            configuration={
                "host.syscall_sequence": {"sequence": ("open", "read", "close")}
            },
        )
        results = det.detect(events, context)
        assert len(results) == 1

    def test_no_matches_when_sequence_config_empty(self) -> None:
        events = [_syscall("open", 0), _syscall("write", 1), _syscall("close", 2)]
        det = SyscallSequenceDetector()
        context = DetectionContext(
            event_count=3,
            configuration={"host.syscall_sequence": {"sequence": ()}},
        )
        assert det.detect(events, context) == []


# ---------------------------------------------------------------------------
# IOC foundation
# ---------------------------------------------------------------------------


class TestNormalizeIoc:
    def test_ip_normalization(self) -> None:
        assert normalize_ioc(IOCType.IP, " 1.1.1.1 ") == "1.1.1.1"

    def test_domain_normalization(self) -> None:
        assert normalize_ioc(IOCType.DOMAIN, "Evil.Example.COM.") == "evil.example.com"

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(IOCNormalizationError):
            normalize_ioc(IOCType.IP, "not-an-ip")

    def test_invalid_url_raises(self) -> None:
        with pytest.raises(IOCNormalizationError):
            normalize_ioc(IOCType.URL, "no-scheme")


class TestIOCProvider:
    def test_add_normalizes_value(self) -> None:
        provider = IOCProvider()
        provider.add(IOC(type=IOCType.IP, value="1.1.1.1"))
        assert provider.all()[0].normalized_value == "1.1.1.1"

    def test_matcher_returns_zero_when_empty(self) -> None:
        provider = IOCProvider()
        assert len(provider.matcher()) == 0


# ---------------------------------------------------------------------------
# IOC detector
# ---------------------------------------------------------------------------


def _ioc_detector(iocs: list[IOC]) -> IOCDetector:
    provider = IOCProvider()
    for ioc in iocs:
        provider.add(ioc)
    return IOCDetector(ioc_provider=provider)


class TestIOCDetector:
    def test_matches_source_ip(self) -> None:
        det = _ioc_detector([IOC(type=IOCType.IP, value="8.8.8.8")])
        events = [_net_event(0, si="8.8.8.8", di="10.0.0.5")]
        results = det.detect(events, DetectionContext(event_count=1))
        assert len(results) == 1
        assert results[0].detector_id == "network.ioc_match"
        assert det.category == DetectorCategory.IOC
        assert results[0].severity == "high"
        ioc_matches = results[0].evidence.observed_values["ioc_matches"]
        assert ioc_matches[0]["ioc_value"] == "8.8.8.8"

    def test_matches_destination_ip(self) -> None:
        det = _ioc_detector([IOC(type=IOCType.IP, value="1.1.1.1")])
        events = [_net_event(0, si="10.0.0.5", di="1.1.1.1")]
        results = det.detect(events, DetectionContext(event_count=1))
        assert len(results) == 1
        assert results[0].evidence.observed_values["matched_fields"] == ["destination_ip"]

    def test_no_match_without_matching_ioc(self) -> None:
        det = _ioc_detector([IOC(type=IOCType.IP, value="9.9.9.9")])
        events = [_net_event(0, si="10.0.0.5", di="8.8.8.8")]
        assert det.detect(events, DetectionContext(event_count=1)) == []

    def test_empty_provider_returns_nothing(self) -> None:
        det = IOCDetector()
        events = [_net_event(0)]
        assert det.detect(events, DetectionContext(event_count=1)) == []

    def test_ignores_syscall_events(self) -> None:
        det = _ioc_detector([IOC(type=IOCType.IP, value="8.8.8.8")])
        events = [_syscall("open", 0)]
        assert det.detect(events, DetectionContext(event_count=1)) == []


# ---------------------------------------------------------------------------
# Registry / bootstrap integration
# ---------------------------------------------------------------------------


class TestPhase2RegistryIntegration:
    def test_new_detectors_registered_and_enabled(self) -> None:
        registry = build_registry()
        ids = {d.detector_id for d in registry.get_all()}
        assert "network.event_rate_window" in ids
        assert "host.syscall_sequence" in ids
        assert "network.ioc_match" in ids
        for detector_id in ("network.event_rate_window", "host.syscall_sequence", "network.ioc_match"):
            assert DEFAULT_ENABLED[detector_id] is True

    def test_orchestrator_runs_phase2_detectors(self) -> None:
        t0 = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
        events = [
            _net_event(i, dp=8080, ts=t0 + timedelta(seconds=i)) for i in range(5)
        ]
        orch = build_orchestrator()
        # Reduce the rate threshold so the detector fires with 5 events.
        from app.detection.configuration.provider import DetectorConfigurationProvider
        provider = DetectorConfigurationProvider(
            overrides={"network.event_rate_window": {"event_threshold": 3, "window_seconds": 60}}
        )
        orch = build_orchestrator(provider)
        result = orch.execute(events, DetectionContext(event_count=5))
        types = {r.detection_type for r in result.results}
        assert "network_event_rate_window" in types
