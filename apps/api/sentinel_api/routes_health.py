from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from sentinel_core.config import Settings
from sentinel_core.db import ping, tx
from sentinel_storage import repos_jobs

from .metrics import metrics_payload, refresh_queue_gauges

router = APIRouter()

_START = time.monotonic()

# Stage-6 §5.4: /ready degrades when the oldest queued job has waited longer
# than this.  PROPOSED — re-measure under §6.6 before it becomes MEASURED.
QUEUE_STALE_SECONDS = 15 * 60


def _store_probe(settings: Settings) -> bool:
    try:
        root = Path(settings.storage_root)
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".ready-probe"
        probe.write_bytes(b"ok")
        probe.unlink()
        return True
    except OSError:
        return False


def _queue_ok(settings: Settings) -> bool:
    """Oldest-queued-job age (Stage-6 §5.4).  Read through the BYPASSRLS
    platform role: the app role sees only its own tenant's rows under RLS,
    which would under-report the depth the operator needs to see."""
    dsn = settings.database_worker_url or settings.database_url
    try:
        with tx(dsn) as conn:
            age = repos_jobs.oldest_queued_age_seconds(conn)
    except Exception:
        return False
    if age is None:
        return True
    return age <= QUEUE_STALE_SECONDS


@router.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": time.monotonic() - _START}


@router.get("/ready")
def ready(request: Request):
    settings = request.app.state.settings
    db_ok = ping(settings.database_url)
    store_ok = _store_probe(settings)
    queue_ok = _queue_ok(settings) if db_ok else False
    status = "ok" if (db_ok and store_ok and queue_ok) else "degraded"
    body = {
        "status": status,
        "checks": {
            "database": "ok" if db_ok else "degraded",
            "object_store": "ok" if store_ok else "degraded",
            "queue": "ok" if queue_ok else "degraded",
        },
    }
    return JSONResponse(status_code=200 if status == "ok" else 503, content=body)


@router.get("/metrics")
def metrics(request: Request):
    refresh_queue_gauges(request.app.state.settings)
    return Response(content=metrics_payload(), media_type="text/plain; version=0.0.4")
