"""Detector configuration validation.

Enforces that configuration values are typed, within range, and free of
unknown parameters. Configuration is data — never executable code. Malformed
configuration fails fast with a :class:`ConfigValidationError` rather than
silently being ignored or crashing unrelated detectors later.
"""
from __future__ import annotations

from typing import Any

from app.detection.configuration.defaults import DEFAULT_CONFIG, DETECTOR_CONFIG_SCHEMAS
from app.detection.configuration.models import ConfigParameter


class ConfigValidationError(ValueError):
    """Raised when a detector configuration is invalid."""


def _check_value(parameter: ConfigParameter, value: Any) -> None:
    expected = parameter.value_type
    valid = isinstance(value, expected)
    # bool is a subclass of int; reject bool where int is expected to avoid
    # subtle semantic confusion between flags and numeric thresholds.
    if valid and expected is int and isinstance(value, bool):
        valid = False
    if not valid:
        raise ConfigValidationError(
            f"Parameter '{parameter.name}' must be of type "
            f"{expected.__name__}, got {type(value).__name__}."
        )
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if parameter.min_value is not None and value < parameter.min_value:
            raise ConfigValidationError(
                f"Parameter '{parameter.name}' must be >= {parameter.min_value}, got {value}."
            )
        if parameter.max_value is not None and value > parameter.max_value:
            raise ConfigValidationError(
                f"Parameter '{parameter.name}' must be <= {parameter.max_value}, got {value}."
            )


def validate_config(detector_id: str, params: dict[str, Any] | None) -> dict[str, Any]:
    """Validate raw configuration for a detector.

    Returns a validated dict that always contains every parameter, filled
    with defaults where values are absent. Raises :class:`ConfigValidationError`
    for unknown detector IDs, unknown parameters, or invalid values.
    """
    if detector_id not in DETECTOR_CONFIG_SCHEMAS:
        raise ConfigValidationError(
            f"Unknown detector_id '{detector_id}' has no configuration schema."
        )

    schema = DETECTOR_CONFIG_SCHEMAS[detector_id]
    raw = params or {}

    unknown = set(raw) - schema.parameter_names()
    if unknown:
        raise ConfigValidationError(
            f"Unknown configuration parameter(s) for '{detector_id}': "
            f"{', '.join(sorted(unknown))}."
        )

    validated: dict[str, Any] = schema.defaults()
    for name, value in raw.items():
        parameter = schema.get_parameter(name)
        if parameter is None:
            continue  # already rejected above
        _check_value(parameter, value)
        validated[name] = value
    return validated


def resolve_detector_config(
    detector_id: str,
    context_configuration: dict[str, Any] | None,
    defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve the effective config for a detector.

    Precedence (highest wins):
        1. validated config already injected in the context
           (``context_configuration[detector_id]``)
        2. explicit ``defaults`` (schema defaults when the detector is invoked
           directly in tests without the provider)

    This keeps detectors working when called standalone while still honouring
    provider-injected configuration through the pipeline.
    """
    injected = (context_configuration or {}).get(detector_id)
    if isinstance(injected, dict) and injected:
        return injected
    if defaults is not None:
        return defaults
    return DEFAULT_CONFIG.get(detector_id, {})
