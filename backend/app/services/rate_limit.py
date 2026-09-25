from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


class RateLimitExceeded(Exception):
    """Raised when a request exceeds a configured rate limit."""


@dataclass(frozen=True)
class LimitSpec:
    max_events: int
    window_seconds: float


class InMemoryRateLimiter:
    """Per-key sliding-window rate limiter for a single process.

    Keys are strings such as "login:ip:127.0.0.1" or "login:user:user@x.com".
    Suitable for the single-worker development/deployment layout; a shared
    store (e.g. Redis) is required for horizontally scaled deployments.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, spec: LimitSpec) -> bool:
        now = time.monotonic()
        cutoff = now - spec.window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= spec.max_events:
                return False
            bucket.append(now)
            if len(self._events) > 10_000:
                for k in [k for k, v in self._events.items() if not v]:
                    del self._events[k]
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


limiter = InMemoryRateLimiter()

# Login: per-IP brute-force throttle and per-account throttle.
LOGIN_IP: LimitSpec = LimitSpec(max_events=5, window_seconds=60)
LOGIN_ACCOUNT: LimitSpec = LimitSpec(max_events=10, window_seconds=900)

# Registration: per-IP.
REGISTER_IP: LimitSpec = LimitSpec(max_events=5, window_seconds=3600)

# Password reset: per-IP and per-account.
FORGOT_IP: LimitSpec = LimitSpec(max_events=5, window_seconds=600)
FORGOT_ACCOUNT: LimitSpec = LimitSpec(max_events=3, window_seconds=3600)
RESET_IP: LimitSpec = LimitSpec(max_events=5, window_seconds=900)

# Refresh: per-IP.
REFRESH_IP: LimitSpec = LimitSpec(max_events=20, window_seconds=300)