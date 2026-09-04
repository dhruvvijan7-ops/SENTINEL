"""Detection orchestrator.

Receives canonical events, queries the detector registry, executes
applicable detectors, collects results, and handles failures safely.
Does NOT contain detection logic itself.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Sequence

from app.detection.configuration.provider import DetectorConfigurationProvider
from app.detection.configuration.validation import ConfigValidationError
from app.detection.contracts.core import (
    CanonicalEvent,
    DetectionContext,
    DetectionResult,
    Detector,
    EventType,
)
from app.detection.registry.registry import DetectorRegistry

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorResult:
    """Aggregated output from the orchestrator."""
    results: list[DetectionResult] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


class DetectionOrchestrator:
    """Executes detectors against canonical events.

    Responsibilities:
    1. Receive normalized events
    2. Obtain applicable detectors from registry
    3. Execute each detector safely
    4. Collect DetectionResults
    5. Handle detector failures without crashing the entire analysis
    """

    def __init__(
        self,
        registry: DetectorRegistry,
        config_provider: DetectorConfigurationProvider | None = None,
    ) -> None:
        self._registry = registry
        self._config_provider = config_provider or DetectorConfigurationProvider()

    def execute(
        self,
        events: Sequence[CanonicalEvent],
        context: DetectionContext,
        event_types: set[EventType] | None = None,
    ) -> OrchestratorResult:
        """Run enabled detectors against the provided events.

        If ``event_types`` is provided, only detectors that support at
        least one of the given event types are executed. This lets the
        application layer scope a run to host detectors, network
        detectors, or all detectors without the orchestrator knowing
        any individual detector.
        """
        result = OrchestratorResult()
        detectors = self._registry.get_enabled()

        def _applicable(detector: Detector) -> bool:
            if not event_types:
                return True
            supported = set(detector.supported_event_types)
            return bool(supported & event_types)

        for detector in detectors:
            if not _applicable(detector):
                continue
            try:
                # Inject the detector's validated, read-only configuration into a
                # per-detector context copy. This keeps configuration isolated to a
                # single detector and avoids cross-analysis / cross-detector leakage.
                # Detectors not registered in the configuration schema (e.g. custom
                # or test detectors) fall back to empty config and their own defaults.
                try:
                    detector_config = self._config_provider.get_config(detector.detector_id)
                except ConfigValidationError:
                    detector_config = {}
                detector_context = replace(
                    context,
                    configuration={
                        detector.detector_id: detector_config,
                        **context.configuration,
                    },
                )
                detector_results = detector.detect(events, detector_context)
                result.results.extend(detector_results)
            except Exception as exc:
                error_info = {
                    "detector_id": detector.detector_id,
                    "detector_version": detector.detector_version,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
                result.errors.append(error_info)
                logger.error(
                    "Detector %s v%s failed: %s: %s",
                    detector.detector_id,
                    detector.detector_version,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )

        return result
