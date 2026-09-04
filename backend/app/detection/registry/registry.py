"""Detector registry.

Manages registration, lookup, enable/disable, and metadata for detectors.
"""
from __future__ import annotations

import logging
from typing import Sequence

from app.detection.contracts.core import Detector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Central registry for detector instances.

    Detectors are registered at startup. The orchestrator queries
    this registry to find applicable detectors.
    """

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}
        self._enabled: dict[str, bool] = {}

    def register(self, detector: Detector) -> None:
        """Register a detector. Overwrites if same detector_id exists."""
        self._detectors[detector.detector_id] = detector
        self._enabled[detector.detector_id] = detector.enabled
        logger.info(
            "Registered detector: %s v%s (enabled=%s)",
            detector.detector_id,
            detector.detector_version,
            detector.enabled,
        )

    def get(self, detector_id: str) -> Detector | None:
        return self._detectors.get(detector_id)

    def get_enabled(self) -> Sequence[Detector]:
        """Return all enabled detectors in registration order."""
        return [
            d
            for d in self._detectors.values()
            if self._enabled.get(d.detector_id, d.enabled)
        ]

    def get_all(self) -> Sequence[Detector]:
        return list(self._detectors.values())

    def set_enabled(self, detector_id: str, enabled: bool) -> bool:
        """Enable or disable a detector. Returns True if found."""
        if detector_id in self._detectors:
            self._enabled[detector_id] = enabled
            logger.info("Detector %s enabled=%s", detector_id, enabled)
            return True
        return False

    def is_enabled(self, detector_id: str) -> bool:
        return self._enabled.get(detector_id, False)

    def metadata_list(self) -> list[dict]:
        """Return metadata for all registered detectors."""
        result = []
        for d in self._detectors.values():
            result.append({
                "detector_id": d.detector_id,
                "name": d.name,
                "version": d.detector_version,
                "category": d.category.value,
                "scope": d.scope.value,
                "description": d.description,
                "enabled": self._enabled.get(d.detector_id, d.enabled),
            })
        return result
