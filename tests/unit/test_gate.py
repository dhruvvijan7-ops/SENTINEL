from __future__ import annotations

import pytest

from sentinel_core.errors import (
    GateEmptyFile,
    GateFileTooLarge,
    GateIdempotencyMismatch,
    GateQuotaExceeded,
    GateRateLimited,
    GateTenantMismatch,
    GateTimeout,
    GateUnauthenticated,
)
from sentinel_ingest.gate import PrincipalLimiter, check_storage_quota


def test_error_codes_and_statuses():
    for exc_cls, code, status in (
        (GateEmptyFile, "GATE_EMPTY_FILE", 400),
        (GateFileTooLarge, "GATE_FILE_TOO_LARGE", 413),
        (GateRateLimited, "GATE_RATE_LIMITED", 429),
        (GateQuotaExceeded, "GATE_QUOTA_EXCEEDED", 402),
        (GateTenantMismatch, "GATE_TENANT_MISMATCH", 403),
        (GateTimeout, "GATE_TIMEOUT", 408),
        (GateUnauthenticated, "GATE_UNAUTHENTICATED", 401),
        (GateIdempotencyMismatch, "GATE_IDEMPOTENCY_MISMATCH", 409),
    ):
        exc = exc_cls("msg")
        assert exc.code == code
        assert exc.status == status
        body = exc.body()
        assert body["code"] == code
        assert body["message"] == "msg"


def test_limiter_concurrency_and_hourly():
    limiter = PrincipalLimiter(max_concurrent=2, hourly_quota=3)
    limiter.acquire("p")
    limiter.acquire("p")
    with pytest.raises(GateRateLimited):  # concurrency 2/2
        limiter.acquire("p")
    limiter.release("p")
    limiter.acquire("p")  # 3rd successful acquire this hour (window full)
    limiter.release("p")
    limiter.release("p")
    with pytest.raises(GateRateLimited):  # hourly quota 3/3
        limiter.acquire("p")


def test_limiter_independent_principals():
    limiter = PrincipalLimiter(max_concurrent=1, hourly_quota=1)
    limiter.acquire("a")
    limiter.acquire("b")  # other principal unaffected
    limiter.release("a")
    limiter.release("b")


def test_storage_quota():
    check_storage_quota(100, 200)
    with pytest.raises(GateQuotaExceeded):
        check_storage_quota(200, 200)
    with pytest.raises(GateQuotaExceeded):
        check_storage_quota(201, 200)
