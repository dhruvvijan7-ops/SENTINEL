"""Safe IOC normalization.

Normalizes values deterministically without destroying meaningful distinctions:
- IP addresses → canonical textual form (``ipaddress`` library)
- domains/URLs/hashes → stripped + case-normalized

Invalid values raise :class:`IOCCNormalizationError` rather than silently
producing a garbage normalized value.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from app.detection.ioc.models import IOCType


class IOCNormalizationError(ValueError):
    """Raised when a value cannot be normalized for its IOC type."""


def normalize_ioc(type_: IOCType, value: str) -> str:
    """Normalize ``value`` for the given IOC type."""
    if value is None:
        raise IOCNormalizationError("IOC value cannot be None.")
    if not isinstance(value, str) or not value.strip():
        raise IOCNormalizationError("IOC value must be a non-empty string.")
    value = value.strip()

    if type_ == IOCType.IP:
        return _normalize_ip(value)
    if type_ == IOCType.DOMAIN:
        return _normalize_domain(value)
    if type_ == IOCType.URL:
        return _normalize_url(value)
    if type_ in (IOCType.FILE_HASH, IOCType.FILE_PATH, IOCType.PROCESS):
        return value
    raise IOCNormalizationError(f"Unsupported IOC type: {type_!r}")


def _normalize_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IOCNormalizationError(f"Invalid IP address: {value!r}") from exc
    return addr.compressed


def _normalize_domain(value: str) -> str:
    # Remove an optional trailing dot but otherwise normalise by lowercasing.
    v = value.lower()
    while v.endswith("."):
        v = v[:-1]
    if not v:
        raise IOCNormalizationError("Empty domain.")
    return v


def _normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise IOCNormalizationError(f"Invalid URL: {value!r}")
    # Lowercase scheme + host, preserve path/query exactly.
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    return urlparse._replace(parsed, scheme=scheme, netloc=netloc).geturl()
