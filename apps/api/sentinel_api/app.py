from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from sentinel_core.config import Settings
from sentinel_core.db import tx
from sentinel_core.errors import GateError
from sentinel_core.logging import configure_logging, get_logger
from sentinel_ingest.gate import PrincipalLimiter

from .routes_health import router as health_router
from .routes_runs import router as runs_router
from .routes_uploads import router as uploads_router

log = get_logger("api")


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
    with tx(settings.worker_url or settings.database_url) as conn:
        for dk in settings.dev_keys:
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
    configure_logging(settings.log_format)

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
        settings.max_concurrent_uploads_per_principal,
        settings.upload_hourly_quota_per_principal,
    )

    @app.middleware("http")
    async def body_limit_and_metrics(request: Request, call_next):
        # Sentinel-owned request cap (Stage-3 §1): Content-Length pre-check +
        # streamed byte count.  No third-party WAF (spec constraint).
        max_bytes = settings.max_request_bytes
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "code": "GATE_REQUEST_TOO_LARGE",
                            "message": f"request body exceeds {max_bytes} bytes",
                        },
                    )
            except ValueError:
                pass
        response = await call_next(request)
        from .metrics import HTTP_REQUESTS

        HTTP_REQUESTS.labels(request.method, request.url.path, str(response.status_code)).inc()
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

    return app
