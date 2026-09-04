"""Detector registry bootstrap.

Registers detectors into a :class:`DetectorRegistry` and builds a configured
:class:`DetectionOrchestrator`.

This is the single place where detector instances are wired together. Future
phases register additional detectors here (statistical, ML, correlation, etc.)
without modifying the orchestrator or routes.

The registry is built fresh (per invocation) and reflects the current
:class:`DetectorConfigurationProvider` enabled state, so runtime enable/disable
configuration is always honoured — there is no stale cached orchestrator.
"""
from __future__ import annotations

from app.detection.configuration.provider import DetectorConfigurationProvider
from app.detection.detectors.host_detectors import (
    ExcessiveSequenceDetector,
    HighEventVolumeDetector,
    HighSyscallDiversityDetector,
    PrivilegeEscalationDetector,
    SensitiveFileOperationDetector,
    SuspiciousNetworkPatternDetector,
)
from app.detection.detectors.ioc_detector import IOCDetector
from app.detection.detectors.network_detectors import (
    ConnectionFrequencyDetector,
    ExcessiveConnectionDetector,
    PortScanDetector,
    RepeatedConnectionDetector,
)
from app.detection.detectors.rate_detector import EventRateWindowDetector
from app.detection.detectors.sequence_detector import SyscallSequenceDetector
from app.detection.ioc.provider import IOCProvider
from app.detection.orchestration.orchestrator import DetectionOrchestrator
from app.detection.registry.registry import DetectorRegistry


def _all_detectors(ioc_provider: IOCProvider | None = None) -> list:
    """Instantiate the full set of registered detectors."""
    return [
        # Host detectors (migrated from legacy analyse_trace)
        HighEventVolumeDetector(),
        ExcessiveSequenceDetector(),
        SuspiciousNetworkPatternDetector(),
        PrivilegeEscalationDetector(),
        SensitiveFileOperationDetector(),
        HighSyscallDiversityDetector(),
        # Network detectors (migrated from legacy analyse_network_events)
        ExcessiveConnectionDetector(),
        PortScanDetector(),
        ConnectionFrequencyDetector(),
        RepeatedConnectionDetector(),
        # Phase 2 detectors
        EventRateWindowDetector(),
        SyscallSequenceDetector(),
        IOCDetector(ioc_provider=ioc_provider or IOCProvider()),
    ]


def build_registry(
    config_provider: DetectorConfigurationProvider | None = None,
    ioc_provider: IOCProvider | None = None,
) -> DetectorRegistry:
    """Construct a registry pre-populated with all detectors.

    Enable/disable state is applied from ``config_provider`` so the returned
    registry reflects current configuration. Defaults to an all-enabled
    provider when none is supplied.
    """
    provider = config_provider or DetectorConfigurationProvider()
    registry = DetectorRegistry()
    for detector in _all_detectors(ioc_provider):
        registry.register(detector)
    for detector in registry.get_all():
        if not provider.is_enabled(detector.detector_id):
            registry.set_enabled(detector.detector_id, False)
    return registry


def build_orchestrator(
    config_provider: DetectorConfigurationProvider | None = None,
    ioc_provider: IOCProvider | None = None,
) -> DetectionOrchestrator:
    """Build a DetectionOrchestrator backed by the current registry."""
    provider = config_provider or DetectorConfigurationProvider()
    return DetectionOrchestrator(
        build_registry(provider, ioc_provider),
        config_provider=provider,
    )
