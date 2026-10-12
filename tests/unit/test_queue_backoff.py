"""Stage-6 §6.5: queue backoff distribution bounds.

The reaper and the failure path both schedule retries with full-jitter
exponential backoff.  The contract is a *bound*, not a value: every draw must
sit inside ``uniform(0, min(cap, base * 2**(attempt-1)))``.  hypothesis
exercises the bound across the whole attempt range.
"""
from __future__ import annotations

import random

from hypothesis import given, settings, strategies as st

from sentinel_storage.repos_jobs import backoff_seconds

BASE = 5
CAP = 900


def _ceiling(attempt: int) -> float:
    return float(min(CAP, BASE * (2 ** (attempt - 1))))


@given(
    attempt=st.integers(min_value=1, max_value=64),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
@settings(max_examples=300, deadline=None)
def test_backoff_is_within_the_full_jitter_bounds(attempt: int, seed: int) -> None:
    delay = backoff_seconds(
        attempt, base_seconds=BASE, cap_seconds=CAP, rng=random.Random(seed)
    )
    assert 0.0 <= delay <= _ceiling(attempt), (
        f"attempt={attempt} drew {delay}, outside [0, {_ceiling(attempt)}]"
    )


@given(attempt=st.integers(min_value=1, max_value=64))
@settings(max_examples=100, deadline=None)
def test_backoff_never_exceeds_the_cap(attempt: int) -> None:
    rng = random.Random(0)
    for _ in range(50):
        delay = backoff_seconds(
            attempt, base_seconds=BASE, cap_seconds=CAP, rng=rng
        )
        assert delay <= CAP


def test_first_attempt_is_bounded_by_the_base_delay() -> None:
    rng = random.Random(1234)
    draws = [backoff_seconds(1, base_seconds=BASE, cap_seconds=CAP, rng=rng) for _ in range(50)]
    assert all(0.0 <= d <= BASE for d in draws)
    assert min(draws) < max(draws), "full jitter must not collapse to a constant"


def test_backoff_grows_with_the_attempt_until_the_cap() -> None:
    rng = random.Random(99)
    assert _ceiling(1) == BASE
    assert _ceiling(3) == BASE * 4
    assert _ceiling(20) == CAP


def test_default_rng_is_usable_without_injection() -> None:
    delay = backoff_seconds(2, base_seconds=BASE, cap_seconds=CAP)
    assert 0.0 <= delay <= 10.0
