"""In-memory detector configuration provider.

Provides current, validated detector configuration and enabled state.
Initial Phase 2 configuration is intentionally in-memory (per Master builder
specification 104) — no database table is required. The provider is injectable
into the orchestrator and pipeline, keeping configuration out of detectors'
control and testable in isolation.
"""
from __future__ import annotations

from typing import Any

from app.detection.configuration.defaults import DEFAULT_CONFIG, DEFAULT_ENABLED
from app.detection.configuration.validation import ConfigValidationError, validate_config


class DetectorConfigurationProvider:
    """Read-only provider of validated detector configuration.

    ``overrides`` and ``enabled_overrides`` are validated on update; the provider
    never permits negative thresholds, unknown detectors, or unknown fields.

    The object is safe to share across requests (it does not mutate during
    normal execution). Updating configuration is an explicit, audited action.
    """

    def __init__(
        self,
        overrides: dict[str, dict[str, Any]] | None = None,
        enabled_overrides: dict[str, bool] | None = None,
    ) -> None:
        self._overrides: dict[str, dict[str, Any]] = {}
        self._enabled_overrides: dict[str, bool] = {}
        if overrides:
            for detector_id, params in overrides.items():
                self.update_config(detector_id, params)
        if enabled_overrides:
            for detector_id, enabled in enabled_overrides.items():
                self.set_enabled(detector_id, enabled)

    # -- identity -----------------------------------------------------------

    def known_detectors(self) -> list[str]:
        return list(DEFAULT_CONFIG.keys())

    # -- configuration ------------------------------------------------------

    def get_config(self, detector_id: str) -> dict[str, Any]:
        if detector_id not in DEFAULT_CONFIG:
            raise ConfigValidationError(
                f"Unknown detector_id '{detector_id}' has no configuration schema."
            )
        raw = self._overrides.get(detector_id, {})
        return validate_config(detector_id, raw)

    def get_all_config(self) -> dict[str, dict[str, Any]]:
        return {detector_id: self.get_config(detector_id) for detector_id in DEFAULT_CONFIG}

    def update_config(self, detector_id: str, params: dict[str, Any]) -> None:
        """Validate and store new configuration for a detector."""
        validated = validate_config(detector_id, params)
        self._overrides[detector_id] = validated

    # -- enabled state ------------------------------------------------------

    def is_enabled(self, detector_id: str) -> bool:
        if detector_id not in DEFAULT_ENABLED:
            raise ConfigValidationError(
                f"Unknown detector_id '{detector_id}' has no enabled state."
            )
        return self._enabled_overrides.get(detector_id, DEFAULT_ENABLED.get(detector_id, True))

    def set_enabled(self, detector_id: str, enabled: bool) -> None:
        if detector_id not in DEFAULT_ENABLED:
            raise ConfigValidationError(
                f"Unknown detector_id '{detector_id}' has no enabled state."
            )
        if not isinstance(enabled, bool):
            raise ConfigValidationError("'enabled' must be a boolean.")
        self._enabled_overrides[detector_id] = enabled
