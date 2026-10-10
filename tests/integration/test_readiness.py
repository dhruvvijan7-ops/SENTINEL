"""M1 exit ④: readiness flips when the database goes away and comes back."""
from __future__ import annotations

import subprocess
import time

import pytest


def _db_container_up() -> bool:
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "sentinel-db"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.slow
def test_readiness_flips_on_db_stop_start(client, migrated):
    if not _db_container_up():
        pytest.skip("sentinel-db container not running; readiness flip untestable here")

    # baseline: ok
    r = client.get("/ready")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"
    assert r.json()["checks"]["database"] == "ok"

    subprocess.run(["docker", "stop", "sentinel-db"], check=True, timeout=60)
    try:
        # ping has connect_timeout=3; allow the middleware a beat
        deadline = time.monotonic() + 20
        degraded = None
        while time.monotonic() < deadline:
            r = client.get("/ready")
            if r.status_code == 503:
                degraded = r
                break
            time.sleep(1)
        assert degraded is not None, "readiness never degraded after DB stop"
        body = degraded.json()
        assert body["status"] == "degraded"
        assert body["checks"]["database"] == "degraded"
    finally:
        subprocess.run(["docker", "start", "sentinel-db"], check=True, timeout=60)

    deadline = time.monotonic() + 60
    ok = None
    while time.monotonic() < deadline:
        r = client.get("/ready")
        if r.status_code == 200:
            ok = r
            break
        time.sleep(1)
    assert ok is not None, "readiness never recovered after DB start"
    assert ok.json()["status"] == "ok"
