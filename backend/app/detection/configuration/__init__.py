"""Detector configuration subsystem.

Provides a typed, validated, deterministic configuration layer for
detectors. The subsystem exposes:

- ``DetectorConfigSchema`` and ``ConfigParameter`` (typed schemas)
- authoritative default configuration (``configuration.defaults``)
- strict validation (``configuration.validation``)
- an injectable in-memory provider (``configuration.provider``)

Configuration is *data*, never executable code: no ``eval`` / ``exec``.
"""
from app.detection.configuration.defaults import (  # noqa: F401
    DEFAULT_CONFIG,
    DEFAULT_ENABLED,
    DETECTOR_CONFIG_SCHEMAS,
)
from app.detection.configuration.models import (  # noqa: F401
    ConfigParameter,
    DetectorConfigSchema,
)
from app.detection.configuration.provider import (  # noqa: F401
    DetectorConfigurationProvider,
)
from app.detection.configuration.validation import (  # noqa: F401
    ConfigValidationError,
    validate_config,
)

__all__ = [
    "ConfigParameter",
    "DetectorConfigSchema",
    "DetectorConfigurationProvider",
    "ConfigValidationError",
    "validate_config",
    "DETECTOR_CONFIG_SCHEMAS",
    "DEFAULT_CONFIG",
    "DEFAULT_ENABLED",
]
