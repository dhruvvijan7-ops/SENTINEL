from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from sentinel_core.config import Settings
from sentinel_core.db import tx
from sentinel_core.errors import GateError
from sentinel_core.logging import configure_logging, get_logger
from sentinel_ingest.gate import PrincipalLimiter

from .metrics import HTTP_DURATION, HTTP_REQUESTS, route_label
from .routes_audit import router as audit_router
from .routes_findings import router as findings_router
from .routes_health import router as health_router
from .routes_jobs import router as jobs_router
from .routes_runs import router as runs_router
from .routes_uploads import router as uploads_router

log = get_logger("api")


def _record_http(request: Request, response, started: float) -> None:
    route = route_label(request)
    status = str(response.status_code)
    HTTP_REQUESTS.labels(route, request.method, status).inc()
    HTTP_DURATION.labels(route, request.method).observe(time.perf_counter() - started)


def _bootstrap_principals(settings: Settings) -> None:
    """Ensure principals rows exist for dev keys (FK target for
    idempotency_keys).  Production bootstrap lives in the Stage-6 auth
    service; this is the documented M1 stub.  key_hash = sha256(key) here;
    production uses argon2id (schema comment)."""
    import hashlib
    import uuid

    # Bootstrap via the worker role (BYPASSRLS): the principals RLS policy
    # has an implicit WITH CHECK on the session tenant, which is unset at
    # startup; the platform processor is the only role allowed to seed.
    with tx(settings.database_worker_url or settings.database_url) as conn:
        for dk in settings.auth_dev_keys:
            conn.execute(
                """
                INSERT INTO principals (id, tenant_id, workspace_id, kind, display_name, key_hash, scopes)
                VALUES (%s, %s, %s, 'api_key', %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    uuid.UUID(dk.principal_id),
                    dk.tenant_id,
                    dk.workspace_id,
                    dk.display_name,
                    hashlib.sha256(dk.key.encode()).digest(),
                    list(dk.scopes),
                ),
            )
        conn.commit()


def create_app(settings: Settings) -> FastAPI:
    configure_logging(
        settings.observability_log_format, settings.observability_log_level
    )

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            _bootstrap_principals(settings)
        except Exception as exc:  # pragma: no cover - startup diagnostics
            log.error("principal_bootstrap_failed", error=str(exc))
            raise
        yield

    app = FastAPI(
        title="Sentinel Light HIDS API",
        version="0.1.0",
        description="Milestone 1 surface (openapi.yaml is normative).",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.limiter = PrincipalLimiter(
        settings.ingest_max_concurrent_uploads_per_principal,
        settings.ingest_upload_hourly_quota_per_principal,
    )

    @app.middleware("http")
    async def body_limit_and_metrics(request: Request, call_next):
        # Sentinel-owned request cap (Stage-3 §1): Content-Length pre-check +
        # streamed byte count.  No third-party WAF (spec constraint).
        started = time.perf_counter()
        max_bytes = settings.ingest_max_request_bytes
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                too_large = int(declared) > max_bytes
            except ValueError:
                too_large = False
            if too_large:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "code": "GATE_REQUEST_TOO_LARGE",
                        "message": f"request body exceeds {max_bytes} bytes",
                    },
                )
                _record_http(request, response, started)
                return response
        response = await call_next(request)
        _record_http(request, response, started)
        return response

    @app.exception_handler(GateError)
    async def gate_error_handler(request: Request, exc: GateError):
        return JSONResponse(status_code=exc.status, content=exc.body())

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=400, content={"code": "BAD_REQUEST", "message": str(exc.errors())}
        )

    app.include_router(health_router)
    app.include_router(uploads_router)
    app.include_router(runs_router)
    app.include_router(jobs_router)
    app.include_router(audit_router)
    app.include_router(findings_router)

    return app
