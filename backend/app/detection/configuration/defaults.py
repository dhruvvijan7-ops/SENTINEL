"""Authoritative detector configuration schemas and defaults.

This module is the SINGLE source of truth for:
- every configurable detector's parameter schema (types, ranges, defaults)
- the default enabled/disabled state of every detector

The Phase 1 threshold defaults are preserved exactly:
500 events, 50 sequences, 3 network syscall types, 2 sensitive file ops,
30 unique syscalls, 10 unique destinations, 5 source IPs per port,
50 events per port, 20 destinations per source.
"""
from __future__ import annotations

from typing import Any

from app.detection.configuration.models import ConfigParameter, DetectorConfigSchema

# ---------------------------------------------------------------------------
# Host detector schemas
# ---------------------------------------------------------------------------

HOST_HIGH_EVENT_VOLUME = DetectorConfigSchema(
    detector_id="host.high_event_volume",
    parameters=(
        ConfigParameter(
            name="event_count_threshold",
            default=500,
            value_type=int,
            min_value=1,
            description="Number of events above which the detector fires.",
        ),
    ),
)

HOST_EXCESSIVE_SEQUENCES = DetectorConfigSchema(
    detector_id="host.excessive_sequences",
    parameters=(
        ConfigParameter(
            name="sequence_count_threshold",
            default=50,
            value_type=int,
            min_value=1,
            description="Number of execution sequences above which the detector fires.",
        ),
    ),
)

HOST_SUSPICIOUS_NETWORK_PATTERN = DetectorConfigSchema(
    detector_id="host.suspicious_network_pattern",
    parameters=(
        ConfigParameter(
            name="distinct_network_syscall_threshold",
            default=3,
            value_type=int,
            min_value=1,
            description="Distinct network-related syscalls required to fire.",
        ),
    ),
)

HOST_SUSPICIOUS_FILE_OPERATIONS = DetectorConfigSchema(
    detector_id="host.suspicious_file_operations",
    parameters=(
        ConfigParameter(
            name="sensitive_operation_threshold",
            default=2,
            value_type=int,
            min_value=1,
            description="Distinct sensitive file operations required to fire.",
        ),
    ),
)

HOST_HIGH_SYSCALL_DIVERSITY = DetectorConfigSchema(
    detector_id="host.high_syscall_diversity",
    parameters=(
        ConfigParameter(
            name="unique_syscall_threshold",
            default=30,
            value_type=int,
            min_value=1,
            description="Unique syscalls above which the detector fires.",
        ),
    ),
)

HOST_PRIVILEGE_ESCALATION = DetectorConfigSchema(
    detector_id="host.privilege_escalation",
    parameters=(),
)

# ---------------------------------------------------------------------------
# Network detector schemas
# ---------------------------------------------------------------------------

NETWORK_EXCESSIVE_CONNECTION = DetectorConfigSchema(
    detector_id="network.excessive_connection_attempts",
    parameters=(
        ConfigParameter(
            name="unique_destination_threshold",
            default=10,
            value_type=int,
            min_value=1,
            description="Unique destinations per source IP required to fire.",
        ),
    ),
)

NETWORK_PORT_SCAN = DetectorConfigSchema(
    detector_id="network.port_scan_detected",
    parameters=(
        ConfigParameter(
            name="unique_source_ip_threshold",
            default=5,
            value_type=int,
            min_value=1,
            description="Unique source IPs per destination port required to fire.",
        ),
    ),
)

NETWORK_HIGH_CONNECTION_FREQUENCY = DetectorConfigSchema(
    detector_id="network.high_connection_frequency",
    parameters=(
        ConfigParameter(
            name="event_count_threshold",
            default=50,
            value_type=int,
            min_value=1,
            description="Events per destination port above which the detector fires.",
        ),
    ),
)

NETWORK_REPEATED_CONNECTION = DetectorConfigSchema(
    detector_id="network.repeated_connection_attempts",
    parameters=(
        ConfigParameter(
            name="unique_destination_threshold",
            default=20,
            value_type=int,
            min_value=1,
            description="Unique destinations per source IP required to fire.",
        ),
    ),
)

# ---------------------------------------------------------------------------
# New Phase 2 detector schemas
# ---------------------------------------------------------------------------

NETWORK_RATE_WINDOW = DetectorConfigSchema(
    detector_id="network.event_rate_window",
    parameters=(
        ConfigParameter(
            name="window_seconds",
            default=60,
            value_type=int,
            min_value=1,
            description="Length (seconds) of the sliding window.",
        ),
        ConfigParameter(
            name="event_threshold",
            default=50,
            value_type=int,
            min_value=1,
            description="Event count within the window required to fire.",
        ),
    ),
)

HOST_SYSCALL_SEQUENCE = DetectorConfigSchema(
    detector_id="host.syscall_sequence",
    parameters=(
        ConfigParameter(
            name="sequence",
            default=("open", "write", "close"),
            value_type=tuple,
            description="Ordered syscall-predicate pattern (A, B, C).",
        ),
        ConfigParameter(
            name="window_seconds",
            default=None,
            value_type=int,
            min_value=1,
            required=False,
            description="Optional time window. Currently unenforced for syscalls (no timestamps).",
        ),
    ),
)

NETWORK_IOC_MATCH = DetectorConfigSchema(
    detector_id="network.ioc_match",
    parameters=(),
)

# ---------------------------------------------------------------------------
# Registered schemas and defaults
# ---------------------------------------------------------------------------

DETECTOR_CONFIG_SCHEMAS: dict[str, DetectorConfigSchema] = {
    schema.detector_id: schema
    for schema in (
        HOST_HIGH_EVENT_VOLUME,
        HOST_EXCESSIVE_SEQUENCES,
        HOST_SUSPICIOUS_NETWORK_PATTERN,
        HOST_SUSPICIOUS_FILE_OPERATIONS,
        HOST_HIGH_SYSCALL_DIVERSITY,
        HOST_PRIVILEGE_ESCALATION,
        NETWORK_EXCESSIVE_CONNECTION,
        NETWORK_PORT_SCAN,
        NETWORK_HIGH_CONNECTION_FREQUENCY,
        NETWORK_REPEATED_CONNECTION,
        NETWORK_RATE_WINDOW,
        HOST_SYSCALL_SEQUENCE,
        NETWORK_IOC_MATCH,
    )
}

DEFAULT_CONFIG: dict[str, dict[str, Any]] = {
    detector_id: schema.defaults()
    for detector_id, schema in DETECTOR_CONFIG_SCHEMAS.items()
}

# Every detector is enabled by default.
DEFAULT_ENABLED: dict[str, bool] = {
    detector_id: True for detector_id in DETECTOR_CONFIG_SCHEMAS
}
