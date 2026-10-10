"""Stage-3 gate / API error vocabulary (openapi.yaml components.schemas.Error).

Codes mirror Stage-3 §1.5 exactly; HTTP statuses mirror openapi createUpload
responses.  Never invent codes.
"""
from __future__ import annotations

from typing import Any


class GateError(Exception):
    code: str = "GATE_INTERNAL"
    status: int = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            out["details"] = self.details
        return out


class GateUnauthenticated(GateError):
    code = "GATE_UNAUTHENTICATED"
    status = 401


class GateForbidden(GateError):
    code = "GATE_FORBIDDEN"
    status = 403


class GateTenantMismatch(GateError):
    code = "GATE_TENANT_MISMATCH"
    status = 403


class GateBodyLengthMismatch(GateError):
    code = "GATE_BODY_LENGTH_MISMATCH"
    status = 400


class GateRequestTooLarge(GateError):
    code = "GATE_REQUEST_TOO_LARGE"
    status = 413


class GateFileTooLarge(GateError):
    code = "GATE_FILE_TOO_LARGE"
    status = 413


class GateEmptyFile(GateError):
    code = "GATE_EMPTY_FILE"
    status = 400


class GateTooManyFiles(GateError):
    code = "GATE_TOO_MANY_FILES"
    status = 400


class GateFieldTooLarge(GateError):
    code = "GATE_FIELD_TOO_LARGE"
    status = 400


class GateQuotaExceeded(GateError):
    code = "GATE_QUOTA_EXCEEDED"
    status = 402


class GateRateLimited(GateError):
    code = "GATE_RATE_LIMITED"
    status = 429


class GateTimeout(GateError):
    code = "GATE_TIMEOUT"
    status = 408


class GateIdempotencyMismatch(GateError):
    code = "GATE_IDEMPOTENCY_MISMATCH"
    status = 409


class GateStoreWriteFailed(GateError):
    code = "GATE_STORE_WRITE_FAILED"
    status = 503


class NotFoundError(GateError):
    code = "NOT_FOUND"
    status = 404


class BadRequestError(GateError):
    code = "BAD_REQUEST"
    status = 400
