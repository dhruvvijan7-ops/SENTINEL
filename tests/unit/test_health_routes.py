"""Runtime behaviour of /health and /ready (Stage-6 §5.4).

No database is required: the app is built with an unreachable DSN so the
degraded branch is exercised deterministically rather than skipped.
"""
from __future__ import annotations

from sentinel_api.routes_health import QUEUE_STALE_SECONDS

UNREACHABLE = "postgresql+psycopg://sentinel:not-a-real-password@127.0.0.1:9/sentinel"


def _client(tmp_path, database_url: str):
    from fastapi.testclient import TestClient

    from sentinel_api.app import create_app
    from sentinel_core.config import Settings

    settings = Settings(
        database_url=database_url,
        storage_root=str(tmp_path / "objects"),
        observability_log_format="console",
    )
    return TestClient(create_app(settings))


def test_health_is_liveness_only_and_never_degrades(tmp_path) -> None:
    client = _client(tmp_path, UNREACHABLE)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["uptime_seconds"] >= 0


def test_ready_degrades_when_the_database_is_unreachable(tmp_path) -> None:
    client = _client(tmp_path, UNREACHABLE)
    r = client.get("/ready")
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"] == "degraded"
    assert body["checks"]["queue"] == "degraded"


def test_ready_reports_the_three_spec_5_4_checks(tmp_path) -> None:
    client = _client(tmp_path, UNREACHABLE)
    checks = client.get("/ready").json()["checks"]
    assert set(checks) == {"database", "object_store", "queue"}
    assert set(checks.values()) <= {"ok", "degraded"}


def test_queue_staleness_threshold_matches_spec_5_4() -> None:
    assert QUEUE_STALE_SECONDS == 15 * 60
