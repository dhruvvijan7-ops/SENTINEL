from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest

from sentinel_core.config import Settings
from sentinel_core.db import tx
from sentinel_storage import repos_jobs

# Stage-6 §5.2.  Latency buckets are PROPOSED until §6.6 re-labels them
# MEASURED (§5.2: "Buckets: PROPOSED latency buckets").
_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)

UPLOADS_ACCEPTED = Counter("sentinel_uploads_accepted_total", "Uploads accepted")
UPLOADS_REJECTED = Counter(
    "sentinel_uploads_rejected_total", "Uploads rejected by gate", ["code"]
)
HTTP_REQUESTS = Counter(
    "sentinel_http_requests_total", "HTTP requests", ["route", "method", "status"]
)
HTTP_DURATION = Histogram(
    "sentinel_http_request_duration_seconds",
    "HTTP request latency",
    ["route", "method"],
    buckets=_LATENCY_BUCKETS,
)
JOBS_QUEUED = Gauge("sentinel_jobs_queued", "Jobs waiting to be claimed", ["type"])
JOBS_RUNNING = Gauge("sentinel_jobs_running", "Jobs holding a worker lease", ["type"])


def route_label(request) -> str:
    """The matched route template, not the raw path: raw paths carry tenant and
    artifact identifiers into the label set (unbounded cardinality)."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path or request.url.path


def refresh_queue_gauges(settings: Settings) -> None:
    """Re-read queue depth for /metrics.  A failed read leaves the last known
    values in place rather than failing the scrape (§5.2 is a health surface)."""
    dsn = settings.database_worker_url or settings.database_url
    if not dsn:
        return
    try:
        with tx(dsn) as conn:
            depth = repos_jobs.queue_depth(conn)
    except Exception:
        return
    JOBS_QUEUED.clear()
    JOBS_RUNNING.clear()
    for job_type, counts in depth.items():
        JOBS_QUEUED.labels(type=job_type).set(counts["queued"])
        JOBS_RUNNING.labels(type=job_type).set(counts["running"])


def metrics_payload() -> bytes:
    return generate_latest()
