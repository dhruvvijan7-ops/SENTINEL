from __future__ import annotations

from prometheus_client import Counter, generate_latest

UPLOADS_ACCEPTED = Counter("sentinel_uploads_accepted_total", "Uploads accepted")
UPLOADS_REJECTED = Counter(
    "sentinel_uploads_rejected_total", "Uploads rejected by gate", ["code"]
)
HTTP_REQUESTS = Counter(
    "sentinel_http_requests_total", "HTTP requests", ["method", "path", "status"]
)


def metrics_payload() -> bytes:
    return generate_latest()
