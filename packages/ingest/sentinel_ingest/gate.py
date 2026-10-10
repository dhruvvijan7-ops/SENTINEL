"""Stage-3 §1 hostile-file gate: per-principal concurrency/rate tracking and
pure quota checks.  Bounds come from Settings (Sentinel-owned ASGI middleware
+ gate); no third-party WAF."""
from __future__ import annotations

import threading
import time
from collections import deque

from sentinel_core.errors import GateQuotaExceeded, GateRateLimited


class PrincipalLimiter:
    """In-process limiter (M1): concurrency semaphore + hourly sliding window.

    Multi-instance deployments need a shared limiter (Stage-6 auth service);
    documented as an M1 limitation, not silently widened.
    """

    def __init__(self, max_concurrent: int, hourly_quota: int):
        self._max_concurrent = max_concurrent
        self._hourly = hourly_quota
        self._lock = threading.Lock()
        self._active: dict[str, int] = {}
        self._windows: dict[str, deque[float]] = {}

    def acquire(self, principal_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            active = self._active.get(principal_id, 0)
            if active >= self._max_concurrent:
                raise GateRateLimited(
                    "too many concurrent uploads for principal",
                    details={"limit": self._max_concurrent},
                )
            window = self._windows.setdefault(principal_id, deque())
            cutoff = now - 3600.0
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= self._hourly:
                raise GateRateLimited(
                    "hourly upload quota exhausted for principal",
                    details={"limit": self._hourly},
                )
            window.append(now)
            self._active[principal_id] = active + 1

    def release(self, principal_id: str) -> None:
        with self._lock:
            active = self._active.get(principal_id, 0)
            if active <= 1:
                self._active.pop(principal_id, None)
            else:
                self._active[principal_id] = active - 1


def check_storage_quota(stored_bytes: int, quota_bytes: int) -> None:
    if stored_bytes >= quota_bytes:
        raise GateQuotaExceeded(
            "workspace storage quota exhausted",
            details={"stored_bytes": stored_bytes, "quota_bytes": quota_bytes},
        )
