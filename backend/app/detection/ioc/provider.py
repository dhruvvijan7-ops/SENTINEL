"""In-memory IOC provider.

Supplies normalized, enabled IOCs to the matcher. Phase 2 uses an in-memory /
configuration-backed provider only (specification 53/104); the
:class:`IOCProvider` abstraction permits a future STIX/TAXII or external
threat-intelligence provider without touching the detector.
"""
from __future__ import annotations

from app.detection.ioc.matcher import IOCMatcher
from app.detection.ioc.models import IOC, IOCType
from app.detection.ioc.normalize import IOCNormalizationError, normalize_ioc


class IOCProvider:
    """Provides an indexed matcher over configured IOCs."""

    def __init__(self, iocs: list[IOC] | None = None) -> None:
        self._iocs: list[IOC] = []
        self._matcher = IOCMatcher()
        if iocs:
            for ioc in iocs:
                self.add(ioc)

    def add(self, ioc: IOC) -> None:
        """Add an IOC, computing its normalized value on insert."""
        if ioc.normalized_value is None:
            try:
                normalized = normalize_ioc(ioc.type, ioc.value)
            except IOCNormalizationError:
                # Malformed IOC: skip rather than crash unrelated detection.
                return
            ioc = IOC(
                id=ioc.id,
                type=ioc.type,
                value=ioc.value,
                normalized_value=normalized,
                source=ioc.source,
                confidence=ioc.confidence,
                description=ioc.description,
                metadata=dict(ioc.metadata),
                enabled=ioc.enabled,
            )
        self._iocs.append(ioc)
        self._matcher.add(ioc)

    def all(self) -> list[IOC]:
        return list(self._iocs)

    def matcher(self) -> IOCMatcher:
        return self._matcher
