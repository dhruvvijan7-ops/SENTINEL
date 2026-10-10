from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from sentinel_core.db import ping

from .metrics import metrics_payload

router = APIRouter()

_START = time.monotonic()


@router.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": time.monotonic() - _START}


@router.get("/ready")
def ready(request: Request):
    settings = request.app.state.settings
    db_ok = ping(settings.database_url)
    store_ok = True
    try:
        root = Path(settings.storage_local_dir)
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".ready-probe"
        probe.write_bytes(b"ok")
        probe.unlink()
    except OSError:
        store_ok = False
    status = "ok" if (db_ok and store_ok) else "degraded"
    body = {
        "status": status,
        "checks": {
            "database": "ok" if db_ok else "degraded",
            "object_store": "ok" if store_ok else "degraded",
            "queue": "ok" if db_ok else "degraded",
        },
    }
    return JSONResponse(status_code=200 if status == "ok" else 503, content=body)


@router.get("/metrics")
def metrics():
    return Response(content=metrics_payload(), media_type="text/plain; version=0.0.4")
